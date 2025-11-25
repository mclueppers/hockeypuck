/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pghkp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"
	"iter"
	"maps"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//
// Private bulk-update helpers for use by Updater, Reindexer, Reloader etc.
//

// keysInBunch is the maximum number of keys sent in a bunch during bulk insertion.
// Since keys (and subkeys) are sent to the DB in prepared statements with parameters and
// each key requires keysNumColumns parameters, keysInBunch < 65536/keysNumColumns.
// 64k (2-byte parameter count) is the current protocol limit for client communication,
// of prepared statements in PostreSQL v13 (see Bind message in
// https://www.postgresql.org/docs/current/protocol-message-formats.html).
const keysInBunch int = 64000 / keysNumColumns

// subkeysInBunch is the maximum number of subkeys sent in a bunch (for at most
// keysInBunch keys sent in a bunch) during bulk insertion. If each subkey requires 2
// parameters, ~32k subkeys can fit in a bunch (see keysInBunch).
const subkeysInBunch int = 64000 / subkeysNumColumns

// uidsInBunch is the maximum number of userids sent in a bunch (for at most
// keysInBunch keys sent in a bunch) during bulk insertion. If each userid requires 4
// parameters, ~16k userids can fit in a bunch (see keysInBunch).
const uidsInBunch int = 64000 / useridsNumColumns

// minKeys2UseBulk is the minimum number of keys in a call to Insert(..) that
// will trigger a bulk insertion. Otherwise, Insert(..) preceeds one key at a time.
const minKeys2UseBulk int = 3500

// bulkSession is a type representing a single connection to the database.
// This is required because postgres temporary tables are local to a particular session,
// therefore we need to be sure that transactions depending on temporary tables are
// always sent over the same connection that the tables were created in.
type bulkSession struct {
	st   *storage
	conn *sql.Conn
	ctx  context.Context
}

func (st *storage) newBulkSession() (bs *bulkSession, err error) {
	ctx := context.Background()
	conn, err := st.DB.Conn(ctx)
	if err != nil {
		return nil, err
	}
	bs = &bulkSession{
		st,
		conn,
		ctx,
	}
	return bs, nil
}

func (bs *bulkSession) Close() (err error) {
	return bs.conn.Close()
}

func (bs *bulkSession) bulkInsertGetStats(result *hkpstorage.InsertError) (maxDups, minDups, keysInserted, subkeysInserted, useridsInserted int) {
	// Get Duplicate stats
	err := bs.conn.QueryRowContext(bs.ctx, bulkInsNumMinDups).Scan(&minDups)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update duplicate stats: %v", err)
		minDups = 0
	}
	// In-file duplicates may be duplicates even if we insert a subkey for a key's rfp
	// FIXME: This might be costly and could be removed...
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsNumPossibleDups).Scan(&maxDups)
	maxDups += minDups
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update duplicate stats: %v", err)
		maxDups = 0
	}
	// Get keys/subkeys inserted
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsertedKeysNum).Scan(&keysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys inserted stats: %v", err)
		keysInserted = 0
	}
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsertedSubkeysNum).Scan(&subkeysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsertedUserIDsNum).Scan(&useridsInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids inserted stats: %v", err)
		useridsInserted = 0
	}
	return
}

func (bs *bulkSession) bulkReloadGetStats(result *hkpstorage.InsertError) (keysUpdated, subkeysInserted, useridsInserted, keysDeleted int) {
	// The number of keys copied and the number updated should be the same (TODO: check this!)
	err := bs.conn.QueryRowContext(bs.ctx, bulkCopiedKeysNum).Scan(&keysUpdated)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys updated stats: %v", err)
		keysUpdated = 0
	}
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsertedSubkeysNum).Scan(&subkeysInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	err = bs.conn.QueryRowContext(bs.ctx, bulkInsertedUserIDsNum).Scan(&useridsInserted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids inserted stats: %v", err)
		useridsInserted = 0
	}
	err = bs.conn.QueryRowContext(bs.ctx, bulkDeletedKeysNum).Scan(&keysDeleted)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys inserted stats: %v", err)
		subkeysInserted = 0
	}
	return
}

func (bs *bulkSession) bulkExecSingleTx(bulkJobString, jobDesc []string) (err error) {
	log.Debugf("transaction started: %q", jobDesc)
	t := time.Now()
	// In single transaction
	tx, err := bs.conn.BeginTx(bs.ctx, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			tx.Rollback()
		}
	}()

	for i := 0; i < len(bulkJobString); i++ {
		bulkTxStmt, err := tx.Prepare(bulkJobString[i])
		if err != nil {
			return errors.Wrapf(err, "preparing DB server job %s", jobDesc[i])
		}
		defer bulkTxStmt.Close()
		result, err := bulkTxStmt.Exec()
		if err != nil {
			return errors.Wrapf(err, "issuing DB server job %s", jobDesc[i])
		}
		ra, err := result.RowsAffected()
		if err != nil {
			log.Debugf("%s will affect %d rows", jobDesc[i], ra)
		}
	}
	log.Debugf("transaction finished in %v", time.Since(t))
	return err
}

func (bs *bulkSession) bulkInsertCheckSubkeys(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := bs.conn.QueryRowContext(bs.ctx, bulkInsNumNullSubkeys).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update subkeys with NULL stats: %v", err)
	}

	// (0) Remove any stale entries from previous transactions
	// (1) Intermediate insert: no NULL fields & no Duplicates (in-file or in DB)
	// (2) Keep only subkeys with Duplicates in subkeys_copyin:
	//     Delete 1st-stage checked subkeys above & those with NULL fields
	// (3) Single-copy of in-file Dups but not in-DB Dups
	txStrs := []string{bulkTxCleanCheckedSubkeys, bulkTxFilterUniqueSubkeys, bulkTxPrepSubkeyStats, bulkTxFilterDupSubkeys}
	msgStrs := []string{"bulkTx-clean-checked-subkeys", "bulkTx-filter-unique-subkeys", "bulkTx-prep-subkeys-stats", "bulkTx-filter-dup-subkeys"}
	err = bs.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check subkeys: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (bs *bulkSession) bulkInsertCheckUserIDs(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := bs.conn.QueryRowContext(bs.ctx, bulkInsNumNullUserIDs).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update userids with NULL stats: %v", err)
	}

	// (0) Remove any stale entries from previous transactions
	// (1) Intermediate insert: no NULL fields & no Duplicates (in-file or in DB)
	// (2) Keep only userids with Duplicates in userids_copyin:
	//     Delete 1st-stage checked userids above & those with NULL fields
	// (3) Single-copy of in-file Dups but not in-DB Dups
	txStrs := []string{bulkTxCleanCheckedUserIds, bulkTxFilterUniqueUserIDs, bulkTxPrepUserIDStats, bulkTxFilterDupUserIDs}
	msgStrs := []string{"bulkTx-clean-checked-userids", "bulkTx-filter-unique-userids", "bulkTx-prep-userids-stats", "bulkTx-filter-dup-userids"}
	err = bs.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check userids: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (bs *bulkSession) bulkInsertCheckKeys(result *hkpstorage.InsertError) (numNulls int, ok bool) {
	// NULLs stats
	err := bs.conn.QueryRowContext(bs.ctx, bulkInsNumNullKeys).Scan(&numNulls)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys with NULL stats: %v", err)
	}

	// (0) Remove any stale entries from previous transactions
	// (1) rfingerprint & md5 are also UNIQUE in keys_checked so no duplicates inside this same file allowed
	// (2) Keep only keys with Duplicates in keys_copyin: delete 1st-stage checked keys & tuples with NULL fields
	// (3) Insert single copy of in-file Duplicates, if they have no Duplicate in final keys table (in DB)
	txStrs := []string{bulkTxCleanCheckedKeys, bulkTxFilterUniqueKeys, bulkTxPrepKeyStats, bulkTxFilterDupKeys}
	msgStrs := []string{"bulkTx-clean-checked-keys", "bulkTx-filter-unique-keys", "bulkTx-prep-key-stats", "bulkTx-filter-dup-keys"}
	err = bs.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not check keys: %v", err)
		return 0, false
	}
	return numNulls, true
}

func (bs *bulkSession) bulkInsertFromCopyinTables(result *hkpstorage.InsertError) (nullKeys, nullSubkeys, nullUserIDs int, ok bool) {
	keysOK, subkeysOK, useridsOK := true, true, true
	// key batch-processing
	if nullKeys, keysOK = bs.bulkInsertCheckKeys(result); !keysOK {
		return 0, 0, 0, false
	}
	// subkey batch-processing
	if nullSubkeys, subkeysOK = bs.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, 0, 0, false
	}
	// userid batch-processing
	if nullUserIDs, useridsOK = bs.bulkInsertCheckUserIDs(result); !useridsOK {
		return 0, 0, 0, false
	}

	// Batch INSERT all checked-for-constraints keys from memory tables (should need no checks!!!!)
	// Final batch-insertion in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{bulkTxInsertKeys, bulkTxInsertSubkeys, bulkTxInsertUserIDs}
	msgStrs := []string{"bulkTx-insert-keys", "bulkTx-insert-subkeys", "bulkTx-insert-userids"}
	err := bs.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not insert keys: %v", err)
		return 0, 0, 0, false
	}
	return nullKeys, nullSubkeys, nullUserIDs, true
}

// bulkReloadFromCopyinTables updates a bunch of keys in-place.
// It is similar to bulkInsertFromCopyinTables but performs no checks on keys (we assume the `keys` table is already sane)
// We still have to check for duplicate subkeys, as these are not stripped from the json docs.
func (bs *bulkSession) bulkReloadFromCopyinTables(result *hkpstorage.InsertError) (nullSubkeys, nullUserIDs int, ok bool) {
	subkeysOK, useridsOK := true, true
	// subkey batch-processing
	if nullSubkeys, subkeysOK = bs.bulkInsertCheckSubkeys(result); !subkeysOK {
		return 0, 0, false
	}
	// userid batch-processing
	if nullUserIDs, useridsOK = bs.bulkInsertCheckUserIDs(result); !useridsOK {
		return 0, 0, false
	}

	// Batch UPDATE all keys from memory tables (should need no checks!!!!)
	// Final batch-update in keys/subkeys tables without any checks: _must not_ give any errors
	txStrs := []string{
		bulkTxCleanCheckedKeys, bulkTxJournalKeys,
		bulkTxClearDupSubkeys, bulkTxClearOrphanSubkeys, bulkTxClearDupUserIDs, bulkTxClearOrphanUserIDs,
		bulkTxClearKeys, bulkTxUpdateKeys,
		bulkTxInsertSubkeys, bulkTxReindexSubkeys, bulkTxInsertUserIDs, bulkTxReindexUserIDs,
	}
	msgStrs := []string{
		"bulkTx-clean-checked-keys", "bulkTx-journal-keys",
		"bulkTx-clear-dup-subkeys", "bulkTx-clear-orphan-subkeys", "bulkTx-clear-dup-userids", "bulkTx-clear-orphan-userids",
		"bulkTx-clear-keys", "bulkTx-update-keys",
		"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys", "bulkTx-insert-userids", "bulkTx-reindex-userids",
	}
	err := bs.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update keys: %v", err)
		return 0, 0, false
	}
	return nullSubkeys, nullUserIDs, true
}

func (bs *bulkSession) bulkInsertSendBunchTx(keystmts []string, msgSpec string, keysValueArgs [][]any) (err error) {
	log.Debugf("transaction started: %q", msgSpec)
	t := time.Now()
	// In single transaction...
	tx, err := bs.conn.BeginTx(bs.ctx, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		} else {
			tx.Commit()
		}
	}()

	for i, keystmt := range keystmts {
		var stmt *sql.Stmt
		stmt, err = tx.Prepare(keystmt)
		if err != nil {
			return errors.Wrapf(err, "failure preparing %s (query='%v')", msgSpec, keystmt)
		}
		defer stmt.Close()
		_, err = stmt.Exec(keysValueArgs[i]...)
		if err != nil {
			return errors.Wrapf(err, "failure executing %s (query='%v')", msgSpec, keystmt)
		}
	}
	log.Debugf("transaction finished in %v", time.Since(t))
	return nil
}

// Insert keys, subkeys, userids to in-mem tables with no constraints at all: should have no errors!
func (bs *bulkSession) bulkInsertDoCopy(keyDocs []types.KeyDoc, subKeyDocs [][]types.SubKeyDoc, uidDocs [][]types.UserIdDoc, result *hkpstorage.InsertError) (ok bool) {
	lenKIA := len(keyDocs)
	for idx, lastIdx := 0, 0; idx < lenKIA; lastIdx = idx {
		totKeyArgs, totSubkeyArgs, totUidArgs := 0, 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]any, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]any, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		uidsValueStrings := make([]string, 0, uidsInBunch)
		uidsValueArgs := make([]any, 0, uidsInBunch*useridsNumColumns) // *** must be less than 64k arguments ***
		for i, j, k := 0, 0, 0; idx < lenKIA; idx, i = idx+1, i+1 {
			lenSKIA := len(subKeyDocs[idx])
			lenUIA := len(uidDocs[idx])
			totKeyArgs += keysNumColumns
			totSubkeyArgs += subkeysNumColumns * lenSKIA
			totUidArgs += useridsNumColumns * lenUIA
			if (totKeyArgs > keysInBunch*keysNumColumns) || (totSubkeyArgs > subkeysInBunch*subkeysNumColumns) {
				totKeyArgs -= keysNumColumns
				totSubkeyArgs -= subkeysNumColumns * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR, $%d::TEXT)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7, i*keysNumColumns+8))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, keyDocs[idx].RFingerprint, keyDocs[idx].Doc,
				insTime, insTime, insTime, keyDocs[idx].MD5, keyDocs[idx].Keywords, keyDocs[idx].VFingerprint)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT)", j*subkeysNumColumns+1, j*subkeysNumColumns+2, j*subkeysNumColumns+3))
				subkeysValueArgs = append(subkeysValueArgs,
					subKeyDocs[idx][sidx].RFingerprint, subKeyDocs[idx][sidx].RSubKeyFp, subKeyDocs[idx][sidx].VSubKeyFp)
			}
			for uidx := 0; uidx < lenUIA; uidx, k = uidx+1, k+1 {
				uidsValueStrings = append(uidsValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT, $%d::INTEGER)", k*useridsNumColumns+1, k*useridsNumColumns+2, k*useridsNumColumns+3, k*useridsNumColumns+4))
				uidsValueArgs = append(uidsValueArgs,
					uidDocs[idx][uidx].RFingerprint, uidDocs[idx][uidx].UidString, uidDocs[idx][uidx].Identity, uidDocs[idx][uidx].Confidence)
			}
		}

		log.Debugf("attempting bulk insertion of %d keys, %d subkeys, %d userids", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
		ok := bs.bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings, keysValueArgs, subkeysValueArgs, uidsValueArgs, result)
		if !ok {
			return false
		}
		log.Debugf("%d keys, %d subkeys, %d userids sent to DB...", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
	}
	return true
}

// bulkInsertSend copies the constructed database rows to the postgres in-memory tables
// Copyin tables are TRUNCATEd inside the transaction instead of DROPping them between transactions, which is racy
func (bs *bulkSession) bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings []string, keysValueArgs, subkeysValueArgs, uidsValueArgs []any, result *hkpstorage.InsertError) (ok bool) {
	// Send all keys to in-mem tables to the pg server; *no constraints checked*
	keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords, vfingerprint) VALUES %s",
		keys_copyin_temp_table_name, strings.Join(keysValueStrings, ","))
	err := bs.bulkInsertSendBunchTx([]string{bulkTxCleanCopyinKeys, keystmt},
		"INSERT INTO "+keys_copyin_temp_table_name,
		[][]any{{}, keysValueArgs})
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send key bunch: %v", err)
		return false
	}

	if len(subkeysValueArgs) > 0 {
		// Send all subkeys to in-mem tables to the pg server; *no constraints checked*
		subkeystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, rsubfp, vsubfp) VALUES %s",
			subkeys_copyin_temp_table_name, strings.Join(subkeysValueStrings, ","))
		err = bs.bulkInsertSendBunchTx([]string{bulkTxCleanCopyinSubkeys, subkeystmt},
			"INSERT INTO "+subkeys_copyin_temp_table_name,
			[][]any{{}, subkeysValueArgs})
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not send subkey bunch: %v", err)
			return false
		}
	}

	if len(uidsValueArgs) > 0 {
		// Send all userids to in-mem tables to the pg server; *no constraints checked*
		useridstmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, uidstring, identity, confidence) VALUES %s",
			userids_copyin_temp_table_name, strings.Join(uidsValueStrings, ","))
		err = bs.bulkInsertSendBunchTx([]string{bulkTxCleanCopyinUserIds, useridstmt},
			"INSERT INTO "+userids_copyin_temp_table_name,
			[][]any{{}, uidsValueArgs})
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not send userid bunch: %v", err)
			return false
		}
	}

	return true
}

func (bs *bulkSession) bulkInsertCopyOld(oldKeys []string, result *hkpstorage.InsertError) (ok bool) {
	keysValueStrings := make([]string, 0, keysInBunch)
	keysValueArgs := make([]any, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
	for index, fp := range oldKeys {
		keysValueStrings = append(keysValueStrings, fmt.Sprintf("($%d::TEXT)", index+1))
		keysValueArgs = append(keysValueArgs, openpgp.Reverse(fp))
	}

	log.Debugf("uploading %d old fps", len(oldKeys))

	keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint) VALUES %s",
		keys_old_temp_table_name, strings.Join(keysValueStrings, ","))
	err := bs.bulkInsertSendBunchTx([]string{bulkTxCleanOldKeys, keystmt},
		"INSERT INTO "+keys_old_temp_table_name,
		[][]any{{}, keysValueArgs})
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not send old key bunch: %v", err)
		return false
	}
	return true
}

func (bs *bulkSession) bulkInsertCopyKeysToServer(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) (int, bool) {
	var key *openpgp.PrimaryKey
	keyDocs := make([]types.KeyDoc, 0, len(keys))
	subKeyDocs := make([][]types.SubKeyDoc, 0, len(keys))
	uidDocs := make([][]types.UserIdDoc, 0, len(keys))
	jsonStrs, theKeywords, uids := make([]string, len(keys)), make([]string, len(keys)), make([][]types.UserIdDoc, len(keys))

	unprocessed, sidx, uidx, i := 0, 0, 0, 0
	for _, key = range keys {
		openpgp.Sort(key)
		jsonKey := jsonhkp.NewPrimaryKey(key)
		jsonBuf, err := json.Marshal(jsonKey)
		if err != nil {
			err = errors.Wrapf(err, "pre-processing cannot serialize rfp=%q", key.RFingerprint)
			result.Errors = append(result.Errors, err)
			log.Warnf("%v", err)
			unprocessed++
			continue
		}
		jsonStrs[i] = string(jsonBuf)
		theKeywords[i], uids[i] = types.KeywordsTSVector(key)
		keyDocs = keyDocs[:i+1] // re-slice +1
		keyDocs[i] = types.KeyDoc{RFingerprint: key.RFingerprint,
			VFingerprint: key.VFingerprint, MD5: key.MD5, Doc: jsonStrs[i], Keywords: theKeywords[i]}

		subKeyDocs = subKeyDocs[:i+1] // re-slice +1
		subKeyDocs[i] = make([]types.SubKeyDoc, 0, len(key.SubKeys))
		for sidx = 0; sidx < len(key.SubKeys); sidx++ {
			subKeyDocs[i] = subKeyDocs[i][:sidx+1] // re-slice +1
			subKeyDocs[i][sidx] = types.SubKeyDoc{RFingerprint: key.RFingerprint,
				RSubKeyFp: key.SubKeys[sidx].RFingerprint, VSubKeyFp: key.SubKeys[sidx].VFingerprint}
		}
		uidDocs = uidDocs[:i+1] // re-slice +1
		uidDocs[i] = make([]types.UserIdDoc, 0, len(uids[i]))
		for uidx = 0; uidx < len(uids[i]); uidx++ {
			uidDocs[i] = uidDocs[i][:uidx+1] // re-slice +1
			uidDocs[i][uidx] = types.UserIdDoc{RFingerprint: key.RFingerprint,
				UidString: uids[i][uidx].UidString, Identity: uids[i][uidx].Identity, Confidence: uids[i][uidx].Confidence}
		}
		i++
	}
	ok := bs.bulkInsertDoCopy(keyDocs, subKeyDocs, uidDocs, result)
	return unprocessed, ok
}

// bulkDrepTempTables cleans up the temporary (in-mem) tables for bulk actions.
func (bs *bulkSession) bulkDropTempTables() error {
	defer bs.Close()
	// Drop the 2 pairs (all) of temporary tables
	err := bs.bulkExecSingleTx(drTempTablesSQL, []string{"dr-temp-tables"})
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// bulkCreateTempTables creates the necessary _temporary_ (in-mem) tables for bulk actions.
// On success, the calling routine MUST immediately defer bulkDropTempTables.
func (st *storage) bulkCreateTempTables() (bs *bulkSession, err error) {
	bs, err = st.newBulkSession()
	if err != nil {
		return nil, errors.Wrap(err, "cannot create bulk session")
	}
	err = bs.bulkExecSingleTx(crTempTablesSQL, []string{"cr-temp-tables"})
	if err != nil {
		return nil, errors.Wrap(err, "cannot create temporary tables")
	}
	return bs, nil
}

// bulkInsert inserts the given keys, and stores any errors in `result`
// If `oldKeys` is a non-empty list of fingerprints, any keys in it but not in `keys` will be deleted.
// The caller MUST invoke bulkCreateTempTables and defer bulkDropTempTables
// (preferably outside the batch-handling loop) BEFORE calling bulkInsert.
func (bs *bulkSession) bulkInsert(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError, oldKeys []string) (keysInserted, keysDeleted int, ok bool) {
	log.Infof("inserting batch of %d keys", len(keys))
	t := time.Now() // FIXME: Remove this
	var keysWithNulls, subkeysWithNulls, useridsWithNulls, maxDups, minDups, subkeysInserted, useridsInserted int
	// (a): Send *all* keys to in-mem tables on the pg server; *no constraints checked*
	if _, ok = bs.bulkInsertCopyKeysToServer(keys, result); !ok {
		return 0, 0, false
	}
	if len(oldKeys) != 0 {
		if !bs.bulkInsertCopyOld(oldKeys, result) {
			return 0, 0, false
		}
		// (b): From _copyin tables update existing on-disk records
		//      remove duplicates, check supplementary table constraints only, not `keys`
		if subkeysWithNulls, useridsWithNulls, ok = bs.bulkReloadFromCopyinTables(result); !ok {
			return 0, 0, false
		}
		keysInserted, subkeysInserted, useridsInserted, keysDeleted = bs.bulkReloadGetStats(result)
		err := bs.BulkNotify(bulkUpdQueryKeyAdded, bulkUpdQueryKeyRemoved)
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not bulk notify insertion/deletion: %v", err)
		}
	} else {
		// (b): From _copyin tables insert new on-disk records
		//      remove duplicates, check *all* constraints & RollBack insertions that err
		if keysWithNulls, subkeysWithNulls, useridsWithNulls, ok = bs.bulkInsertFromCopyinTables(result); !ok {
			return 0, 0, false
		}
		maxDups, minDups, keysInserted, subkeysInserted, useridsInserted = bs.bulkInsertGetStats(result)
		err := bs.BulkNotify(bulkInsQueryKeyChange)
		if err != nil {
			result.Errors = append(result.Errors, err)
			log.Warnf("could not bulk notify insertion: %v", err)
		}
	}

	if minDups == maxDups {
		log.Infof("%d keys and %d subkeys bulk-inserted, %d keys deleted, %d duplicates skipped (%d keys, %d subkeys, %d userids with NULLs) in %v",
			keysInserted, subkeysInserted, keysDeleted, minDups, keysWithNulls, subkeysWithNulls, useridsWithNulls, time.Since(t))
	} else {
		log.Infof("%d keys, %d subkeys, %d userids bulk-inserted, %d keys deleted, at least %d (and up to %d possible) duplicates skipped "+
			"(%d keys, %d subkeys, %d userids with NULLs) in %v",
			keysInserted, subkeysInserted, useridsInserted, keysDeleted, minDups, maxDups, keysWithNulls, subkeysWithNulls, useridsWithNulls, time.Since(t))
	}

	// FIXME: Imitate returning duplicates for reporting. Can be removed.
	result.Duplicates = make([]*openpgp.PrimaryKey, minDups)
	return keysInserted, keysDeleted, true
}

// bulkReindexDoCopy insert keys, subkeys, userids to in-mem tables with no constraints at all: should have no errors!
// TODO: this duplicates a lot of code from bulkInsertDoCopy; find a DRYer way
func (bs *bulkSession) bulkReindexDoCopy(keyDocs iter.Seq[*types.KeyDoc], result *hkpstorage.InsertError) bool {
	keyDocsPull, keyDocsPullStop := iter.Pull(keyDocs)
	defer keyDocsPullStop()
	pullOk := true
	var kd *types.KeyDoc
	for idx, lastIdx := 0, 0; pullOk; lastIdx = idx {
		totKeyArgs, totSubkeyArgs, totUidArgs := 0, 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]any, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]any, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		subKeyDocs := make([][]types.SubKeyDoc, uidsInBunch)
		uidsValueStrings := make([]string, 0, uidsInBunch)
		uidsValueArgs := make([]any, 0, uidsInBunch*useridsNumColumns) // *** must be less than 64k arguments ***
		uidDocs := make([][]types.UserIdDoc, uidsInBunch)
		kd, pullOk = keyDocsPull()
		if !pullOk {
			return true
		}
		for i, j, k := 0, 0, 0; pullOk; idx, i = idx+1, i+1 {
			subKeyDocs[idx], uidDocs[idx], _, _ = kd.Refresh() // ignore errors
			lenSKIA := len(subKeyDocs[idx])
			lenUIA := len(uidDocs[idx])
			totKeyArgs += keysNumColumns
			totSubkeyArgs += subkeysNumColumns * lenSKIA
			totUidArgs += useridsNumColumns * lenUIA
			if (totKeyArgs > keysInBunch*keysNumColumns) || (totSubkeyArgs > subkeysInBunch*subkeysNumColumns) {
				totKeyArgs -= keysNumColumns
				totSubkeyArgs -= subkeysNumColumns * lenSKIA
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR, $%d::TEXT)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7, i*keysNumColumns+8))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, kd.RFingerprint, "{}",
				insTime, insTime, insTime, kd.MD5, kd.Keywords, kd.VFingerprint)

			for sidx := 0; sidx < lenSKIA; sidx, j = sidx+1, j+1 {
				subkeysValueStrings = append(subkeysValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT)", j*subkeysNumColumns+1, j*subkeysNumColumns+2, j*subkeysNumColumns+3))
				subkeysValueArgs = append(subkeysValueArgs,
					subKeyDocs[idx][sidx].RFingerprint, subKeyDocs[idx][sidx].RSubKeyFp, subKeyDocs[idx][sidx].VSubKeyFp)
			}
			for uidx := 0; uidx < lenUIA; uidx, k = uidx+1, k+1 {
				uidsValueStrings = append(uidsValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT, $%d::INTEGER)", k*useridsNumColumns+1, k*useridsNumColumns+2, k*useridsNumColumns+3, k*useridsNumColumns+4))
				uidsValueArgs = append(uidsValueArgs,
					uidDocs[idx][uidx].RFingerprint, uidDocs[idx][uidx].UidString, uidDocs[idx][uidx].Identity, uidDocs[idx][uidx].Confidence)
			}
			kd, pullOk = keyDocsPull()
		}

		log.Debugf("attempting bulk insertion of %d keys, %d subkeys, %d userids", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
		ok := bs.bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings, keysValueArgs, subkeysValueArgs, uidsValueArgs, result)
		if !ok {
			return false
		}
		log.Debugf("%d keys, %d subkeys, %d userids sent to DB...", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
	}
	return true
}

func (bs *bulkSession) bulkReindexGetStats(result *hkpstorage.InsertError) int {
	var keysReindexed int
	err := bs.conn.QueryRowContext(bs.ctx, bulkCopiedKeysNum).Scan(&keysReindexed)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update reindex stats: %v", err)
		keysReindexed = 0
	}
	return keysReindexed
}

func (bs *bulkSession) bulkReindexFromCopyinTables(result *hkpstorage.InsertError) bool {
	subkeysOK, useridsOK := true, true
	// subkey batch-processing
	if _, subkeysOK = bs.bulkInsertCheckSubkeys(result); !subkeysOK {
		return false
	}
	// userid batch-processing
	if _, useridsOK = bs.bulkInsertCheckUserIDs(result); !useridsOK {
		return false
	}

	// We don't clean up dups/orphans because Reindex doesn't delete keys (unlike Reload)
	if log.GetLevel() >= log.DebugLevel {
		// update each table on disk separately, and fail fast to see which transaction failed
		// write to the keys table last, so that reindex will retry on the next pass
		txStrs := []string{bulkTxInsertSubkeys, bulkTxReindexSubkeys}
		msgStrs := []string{"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys"}
		err := bs.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex subkeys: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
		txStrs = []string{bulkTxInsertUserIDs, bulkTxReindexUserIDs}
		msgStrs = []string{"bulkTx-insert-userids", "bulk-Tx-reindex-userids"}
		err = bs.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex userids: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
		txStrs = []string{bulkTxReindexKeys}
		msgStrs = []string{"bulkTx-reindex-keys"}
		err = bs.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex keys: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
	} else {
		// update all tables on-disk in a single transaction
		txStrs := []string{
			bulkTxClearDupSubkeys, bulkTxInsertSubkeys, bulkTxReindexSubkeys,
			bulkTxClearDupUserIDs, bulkTxInsertUserIDs, bulkTxReindexUserIDs,
			bulkTxReindexKeys,
		}
		msgStrs := []string{
			"bulkTx-insert-subkeys", "bulkTx-reindex-subkeys",
			"bulkTx-insert-userids", "bulk-Tx-reindex-userids",
			"bulkTx-reindex-keys",
		}
		err := bs.bulkExecSingleTx(txStrs, msgStrs)
		if err != nil {
			log.Warnf("could not reindex: %v", err)
			result.Errors = append(result.Errors, err)
			return false
		}
	}
	return true
}

// bulkReindex reindexes a batch of keys in a small number of transactions.
// The caller MUST invoke bulkCreateTempTables and defer bulkDropTempTables
// (preferably outside the batch-handling loop) BEFORE calling bulkReindex.
func (bs *bulkSession) bulkReindex(keyDocs map[string]*types.KeyDoc, result *hkpstorage.InsertError) (int, bool) {
	log.Infof("reindexing batch of %d keys", len(keyDocs))
	keysReindexed := 0
	if !bs.bulkReindexDoCopy(maps.Values(keyDocs), result) {
		return 0, false
	}
	if !bs.bulkReindexFromCopyinTables(result) {
		return 0, false
	}

	keysReindexed = bs.bulkReindexGetStats(result)
	return keysReindexed, true
}
