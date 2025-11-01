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
	"fmt"
	"iter"
	"maps"
	"time"

	_ "github.com/lib/pq"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

//
// Reindexer implementation
//

// bulkReindexDoCopy insert keys, subkeys, userids to in-mem tables with no constraints at all: should have no errors!
// TODO: this duplicates a lot of code from bulkInsertDoCopy; find a DRYer way
func (st *storage) bulkReindexDoCopy(keyDocs iter.Seq[*types.KeyDoc], result *hkpstorage.InsertError) bool {
	keyDocsPull, keyDocsPullStop := iter.Pull(keyDocs)
	defer keyDocsPullStop()
	pullOk := true
	var kd *types.KeyDoc
	for idx, lastIdx := 0, 0; pullOk; lastIdx = idx {
		totKeyArgs, totSubkeyArgs, totUidArgs := 0, 0, 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns) // *** must be less than 64k arguments ***
		subkeysValueStrings := make([]string, 0, subkeysInBunch)
		subkeysValueArgs := make([]interface{}, 0, subkeysInBunch*subkeysNumColumns) // *** must be less than 64k arguments ***
		subkeysDocs := make([][]types.SubKeyDoc, uidsInBunch)
		uidsValueStrings := make([]string, 0, uidsInBunch)
		uidsValueArgs := make([]interface{}, 0, uidsInBunch*useridsNumColumns) // *** must be less than 64k arguments ***
		uidDocs := make([][]types.UserIdDoc, uidsInBunch)
		kd, pullOk = keyDocsPull()
		if !pullOk {
			return true
		}
		for i, j, k := 0, 0, 0; pullOk; idx, i = idx+1, i+1 {
			subkeysDocs[idx], uidDocs[idx], _, _ = kd.Refresh() // ignore errors
			lenSKIA := len(subkeysDocs[idx])
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
					subkeysDocs[idx][sidx].RFingerprint, subkeysDocs[idx][sidx].RSubKeyFp, subkeysDocs[idx][sidx].VSubKeyFp)
			}
			for uidx := 0; uidx < lenUIA; uidx, k = uidx+1, k+1 {
				uidsValueStrings = append(uidsValueStrings, fmt.Sprintf("($%d::TEXT, $%d::TEXT, $%d::TEXT, $%d::INTEGER)", k*useridsNumColumns+1, k*useridsNumColumns+2, k*useridsNumColumns+3, k*useridsNumColumns+4))
				uidsValueArgs = append(uidsValueArgs,
					uidDocs[idx][uidx].RFingerprint, uidDocs[idx][uidx].UidString, uidDocs[idx][uidx].Identity, uidDocs[idx][uidx].Confidence)
			}
			kd, pullOk = keyDocsPull()
		}

		log.Debugf("attempting bulk insertion of %d keys, %d subkeys, %d userids", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
		ok := st.bulkInsertSend(keysValueStrings, subkeysValueStrings, uidsValueStrings, keysValueArgs, subkeysValueArgs, uidsValueArgs, result)
		if !ok {
			return false
		}
		log.Debugf("%d keys, %d subkeys, %d userids sent to DB...", idx-lastIdx, totSubkeyArgs/subkeysNumColumns, totUidArgs/useridsNumColumns)
	}
	return true
}

func (st *storage) bulkReindexGetStats(result *hkpstorage.InsertError) int {
	var keysReindexed int
	err := st.QueryRow(bulkCopiedKeysNum).Scan(&keysReindexed)
	if err != nil {
		result.Errors = append(result.Errors, err)
		log.Warnf("could not update reindex stats: %v", err)
		keysReindexed = 0
	}
	return keysReindexed
}

func (st *storage) bulkReindexKeys(result *hkpstorage.InsertError) bool {
	log.Debugf("attempting bulk update of keys, subkeys, userids")
	subkeysOK, useridsOK := true, true
	// subkey batch-processing
	if _, subkeysOK = st.bulkInsertCheckSubkeys(result); !subkeysOK {
		return false
	}
	// userid batch-processing
	if _, useridsOK = st.bulkInsertCheckUserIDs(result); !useridsOK {
		return false
	}

	// We don't clean up orphans because Reindex doesn't delete keys (unlike Reload)
	txStrs := []string{bulkTxReindexKeys, bulkTxClearDupSubkeys, bulkTxClearDupUserIDs, bulkTxInsertSubkeys, bulkTxReindexSubkeys, bulkTxInsertUserIDs, bulkTxReindexUserIDs}
	msgStrs := []string{"bulkTx-reindex-keys", "bulkTx-clear-dup-subkeys", "bulkTx-clear-dup-userids", "bulkTx-insert-subkeys", "bulkTx-reindex-subkeys", "bulkTx-insert-userids", "bulk-Tx-reindex-userids"}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		log.Warnf("could not reindex: %v", err)
		result.Errors = append(result.Errors, err)
		return false
	}
	return true
}

func (st *storage) bulkReindex(keyDocs map[string]*types.KeyDoc, result *hkpstorage.InsertError) (int, bool) {
	log.Infof("attempting bulk reindex of %d keys", len(keyDocs))
	// We only use the `keys_copyin` temp table, but reuse the full complement for simplicity.
	err := st.bulkCreateTempTables()
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	defer st.bulkDropTempTables()
	keysReindexed := 0
	if !st.bulkReindexDoCopy(maps.Values(keyDocs), result) {
		return 0, false
	}
	if !st.bulkReindexKeys(result) {
		return 0, false
	}

	keysReindexed = st.bulkReindexGetStats(result)
	err = st.bulkDropTempTables()
	if err != nil {
		result.Errors = append(result.Errors, err)
	}
	return keysReindexed, true
}

// refreshBunch fetches a bunch of keyDocs from the DB and returns freshened copies of the ones with stale records.
//
// TODO: ModifiedSince does not return keys in any particular sort order (FIXME!),
// so we use a map (not an array) to deduplicate the returned keyDocs,
// and explicitly compare timestamps instead of assuming monotonicity.
// (reverting these mitigations will almost certainly improve the performance)
func (st *storage) refreshBunch(bookmark *time.Time, newKeyDocs map[string]*types.KeyDoc, result *hkpstorage.InsertError) (count int, finished bool) {
	// ModifiedSince uses LIMIT, so this is safe
	rfps, err := st.ModifiedSince(*bookmark)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	if len(rfps) == 0 {
		return 0, true
	}
	keyDocs, err := st.fetchKeyDocs(rfps)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return 0, false
	}
	count = len(keyDocs)
	log.Debugf("reindexing %d records", count)
	for _, kd := range keyDocs {
		// Can't trust MTime to be monotonically increasing, so compare as we go.
		if bookmark.Before(kd.MTime) {
			*bookmark = kd.MTime
		}
		_, _, changed, err := kd.Refresh()
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if changed {
			newKeyDocs[kd.MD5] = kd
		}
	}
	log.Infof("found %d stale records up to %v", len(newKeyDocs), bookmark)
	return count, false
}

// Reindex is a goroutine that reindexes the keydb in-place, oldest-modified items first.
// It does not update CTime, MTime, MD5 or Doc, and does not call Notify.
// It always returns nil, as reindex failure is not fatal.
func (st *storage) Reindex() error {
	bookmark := time.Time{}
	newKeyDocs := make(map[string]*types.KeyDoc, keysInBunch)
	result := hkpstorage.InsertError{}
	total := 0

	for {
		select {
		case <-st.t.Dying():
			return nil
		default:
		}

		t := time.Now()
		count, finished := st.refreshBunch(&bookmark, newKeyDocs, &result)
		total += count
		if finished || len(newKeyDocs) > keysInBunch-100 {
			n, bulkOK := st.bulkReindex(newKeyDocs, &result)
			if !bulkOK {
				log.Debugf("bulkReindex not ok: %q", result.Errors)
				if count, max := len(result.Errors), maxInsertErrors; count > max {
					log.Errorf("too many reindexing errors (%d > %d), bailing...", count, max)
					return nil
				}
			}
			log.Infof("%d keys reindexed in %v; total scanned %d", n, time.Since(t), total)
			newKeyDocs = make(map[string]*types.KeyDoc, keysInBunch)
		}
		if finished {
			log.Infof("reindexing complete")
			return nil
		}
	}
}

// Start reindexing in the background. This should only be done after server startup, not during load or dump.
func (st *storage) StartReindex(reindexGraceSecs int) {
	if st.oldestIdxTime().Add(time.Second * time.Duration(reindexGraceSecs)).Before(time.Now()) {
		st.t.Go(st.Reindex)
	}
}
