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
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"iter"
	"maps"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

//
// Reindexer implementation
//

func (st *storage) fetchKeyDocs(rfps []string) ([]*keyDoc, error) {
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT rfingerprint, doc, md5, ctime, mtime, idxtime, keywords FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*keyDoc
	defer rows.Close()
	for rows.Next() {
		var kd keyDoc
		err = rows.Scan(&kd.RFingerprint, &kd.Doc, &kd.MD5, &kd.CTime, &kd.MTime, &kd.IdxTime, &kd.Keywords)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, &kd)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

func (st *storage) bulkReindexDoCopy(keyDocs iter.Seq[*keyDoc], result *hkpstorage.InsertError) bool {
	keyDocsPull, keyDocsPullStop := iter.Pull(keyDocs)
	defer keyDocsPullStop()
	pullOk := true
	var kd *keyDoc
	for idx, lastIdx := 0, 0; pullOk; lastIdx = idx {
		totKeyArgs := 0
		keysValueStrings := make([]string, 0, keysInBunch)
		keysValueArgs := make([]interface{}, 0, keysInBunch*keysNumColumns)
		kd, pullOk = keyDocsPull()
		if !pullOk {
			return true
		}
		for i := 0; pullOk; idx, i = idx+1, i+1 {
			totKeyArgs += keysNumColumns
			if totKeyArgs > keysInBunch*keysNumColumns {
				totKeyArgs -= keysNumColumns
				break
			}
			keysValueStrings = append(keysValueStrings,
				fmt.Sprintf("($%d::TEXT, $%d::JSONB, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TIMESTAMP, $%d::TEXT, $%d::TSVECTOR)",
					i*keysNumColumns+1, i*keysNumColumns+2, i*keysNumColumns+3, i*keysNumColumns+4, i*keysNumColumns+5, i*keysNumColumns+6, i*keysNumColumns+7))
			insTime := time.Now().UTC()
			keysValueArgs = append(keysValueArgs, kd.RFingerprint, "{}",
				insTime, insTime, insTime, kd.MD5, kd.Keywords)
			kd, pullOk = keyDocsPull()
		}
		log.Debugf("attempting bulk copy of %d keys", idx-lastIdx)
		keystmt := fmt.Sprintf("INSERT INTO %s (rfingerprint, doc, ctime, mtime, idxtime, md5, keywords) VALUES %s",
			keys_copyin_temp_table_name, strings.Join(keysValueStrings, ","))

		err := st.bulkInsertSendBunchTx(keystmt, "reindexes", keysValueArgs)
		if err != nil {
			result.Errors = append(result.Errors, err)
			return false
		}
		log.Debugf("%d updates sent to DB...", idx-lastIdx)
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
	log.Debugf("attempting bulk update of keys")
	txStrs := []string{bulkTxReindexKeys}
	msgStrs := []string{"bulkTx-reindex-keys"}
	err := st.bulkExecSingleTx(txStrs, msgStrs)
	if err != nil {
		result.Errors = append(result.Errors, err)
		return false
	}
	return true
}

func (st *storage) bulkReindex(keyDocs map[string]*keyDoc, result *hkpstorage.InsertError) (int, bool) {
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

// refresh updates the keyDoc fields that cache values from the jsonb document.
// This is called by refreshBunch to ensure the DB columns are correctly populated,
// for example after changes to the keyword indexing policy, or to the DB schema.
func (kd *keyDoc) refresh() (changed bool, err error) {
	// Unmarshal the doc
	var pk jsonhkp.PrimaryKey
	err = json.Unmarshal([]byte(kd.Doc), &pk)
	if err != nil {
		return false, err
	}
	rfp := openpgp.Reverse(pk.Fingerprint)
	key, err := readOneKey(pk.Bytes(), rfp)
	if err != nil {
		return false, err
	}
	if key == nil {
		// This should never happen, but has been observed in testing.
		// Something is corrupt in the DB!
		log.Errorf("nil returned successfully from readOneKey(%v)", pk)
		return false, errors.Errorf("nil returned successfully from readOneKey(%v)", pk)
	}

	// Regenerate keywords
	newKeywords, _, _ := keywordsFromKey(key)
	oldKeywords := keywordsFromTSVector(kd.Keywords)
	slices.Sort(newKeywords)
	slices.Sort(oldKeywords)
	if !slices.Equal(oldKeywords, newKeywords) {
		log.Debugf("keyword mismatch on fp=%s, was %q now %q", pk.Fingerprint, oldKeywords, newKeywords)
		kd.Keywords, err = keywordsToTSVector(newKeywords, " ")
		changed = true
	}

	// In future we may add further tasks here.
	// DO NOT update the md5 field, as this is used by bulkReindex to prevent simultaneous updates.

	return changed, err
}

// refreshBunch fetches a bunch of keyDocs from the DB and returns freshened copies of the ones with stale records.
// TODO: ModifiedSince habitually yields the same entries multiple times (FIXME!),
// so we use a map (not an array) to deduplicate the returned keyDocs.
func (st *storage) refreshBunch(bookmark *time.Time, newKeyDocs map[string]*keyDoc, result *hkpstorage.InsertError) (count int, finished bool) {
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
		*bookmark = kd.MTime
		changed, err := kd.refresh()
		if err != nil {
			result.Errors = append(result.Errors, err)
		} else if changed {
			newKeyDocs[kd.MD5] = kd
		}
	}
	log.Infof("found %d stale records up to %v", len(newKeyDocs), bookmark)
	return count, false
}

// Reindex is a goroutine that reindexes the keydb in-place, oldest items first.
// It does not update CTime, MTime, MD5 or Doc, and does not call Notify.
// It always returns nil, as reindex failure is not fatal.
func (st *storage) Reindex() error {
	bookmark := time.Time{}
	newKeyDocs := make(map[string]*keyDoc, keysInBunch)
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
				log.Debugf("bulkReindex not ok, result: %q", result)
				if count, max := len(result.Errors), maxInsertErrors; count > max {
					log.Errorf("too many reindexing errors (%d > %d), bailing...", count, max)
					return nil
				}
			}
			log.Infof("%d keys reindexed in %v; total scanned %d", n, time.Since(t), total)
			newKeyDocs = make(map[string]*keyDoc, keysInBunch)
		}
		if finished {
			log.Infof("reindexing complete")
			return nil
		}
	}
}

// Start reindexing in the background. This should only be done after server startup, not during load or dump.
func (st *storage) StartReindex() {
	st.t.Go(st.Reindex)
}
