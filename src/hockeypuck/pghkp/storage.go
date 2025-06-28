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
	"bytes"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"gopkg.in/tomb.v2"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	log "github.com/sirupsen/logrus"
)

const (
	maxInsertErrors = 100
)

type storage struct {
	*sql.DB
	dbName  string
	options []openpgp.KeyReaderOption

	mu        sync.Mutex
	listeners []func(hkpstorage.KeyChange) error

	t tomb.Tomb
}

var _ hkpstorage.Storage = (*storage)(nil)

// These are necessary for array unrolling in the bulk update routines below.
// They MUST match the table definitions here.
const keysNumColumns = 7
const subkeysNumColumns = 2

var crTablesSQL = []string{
	// keys is always created with its initial six columns.
	// Additional columns should be defined using ALTER TABLE to enable seamless migration.
	`CREATE TABLE IF NOT EXISTS keys
(
rfingerprint TEXT NOT NULL PRIMARY KEY,
doc jsonb NOT NULL,
ctime TIMESTAMPTZ NOT NULL,
mtime TIMESTAMPTZ NOT NULL,
md5 TEXT NOT NULL UNIQUE,
keywords tsvector
)`,
	// For seamless migration, we use NOT NULL DEFAULT so that existing records get populated.
	// Then we immediately DROP DEFAULT to force future records to be set explicitly.
	`ALTER TABLE keys ADD IF NOT EXISTS idxtime
TIMESTAMPTZ NOT NULL DEFAULT '1970-01-01T00:00:00Z'`,
	`ALTER TABLE keys ALTER idxtime
DROP DEFAULT`,
	// subkeys is always created with its initial two columns.
	// Additional columns should be defined using ALTER TABLE to enable seamless migration.
	`CREATE TABLE IF NOT EXISTS subkeys
(
rfingerprint TEXT NOT NULL,
rsubfp TEXT NOT NULL PRIMARY KEY,
FOREIGN KEY (rfingerprint) REFERENCES keys(rfingerprint)
)
`,
	`CREATE TABLE IF NOT EXISTS pks_status (
	addr TEXT NOT NULL PRIMARY KEY,
	last_sync TIMESTAMP WITH TIME ZONE,
	last_error TEXT
	)
`,
}

var crIndexesSQL = []string{
	`CREATE INDEX IF NOT EXISTS keys_rfp
ON keys(rfingerprint text_pattern_ops);`,
	`CREATE INDEX IF NOT EXISTS keys_ctime
ON keys(ctime);`,
	`CREATE INDEX IF NOT EXISTS keys_mtime
ON keys(mtime);`,
	`CREATE INDEX IF NOT EXISTS keys_idxtime
ON keys(idxtime);`,
	`CREATE INDEX IF NOT EXISTS keys_keywords
ON keys USING gin(keywords);`,
	`CREATE INDEX IF NOT EXISTS subkeys_rfp
ON subkeys(rsubfp text_pattern_ops);`,
}

var drConstraintsSQL = []string{
	`ALTER TABLE keys DROP CONSTRAINT keys_pk;`,
	`ALTER TABLE keys DROP CONSTRAINT keys_md5;`,
	`DROP INDEX keys_rfp;`,
	`DROP INDEX keys_ctime;`,
	`DROP INDEX keys_mtime;`,
	`DROP INDEX keys_idxtime;`,
	`DROP INDEX keys_keywords;`,

	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_pk;`,
	`ALTER TABLE subkeys DROP CONSTRAINT subkeys_fk;`,
	`DROP INDEX subkeys_rfp;`,
}

// Dial returns PostgreSQL storage connected to the given database URL.
func Dial(url string, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return New(db, options)
}

// New returns a PostgreSQL storage implementation for an HKP service.
func New(db *sql.DB, options []openpgp.KeyReaderOption) (hkpstorage.Storage, error) {
	st := &storage{
		DB:      db,
		options: options,
	}
	err := st.createTables()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create tables")
	}
	err = st.createIndexes()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create indexes")
	}
	return st, nil
}

// Convert up to the first newline of the input string to a space-free identifier.
// Useful when we haven't created a statement array programmatically but still want pretty logs.
func sqlDesc(in []string) (out []string) {
	out = make([]string, 0, len(in))
	for _, val := range in {
		init, _, _ := strings.Cut(val, "\n")
		out = append(out, strings.Replace(init, " ", "_", -1))
	}
	return
}

func (st *storage) createTables() error {
	err := st.bulkExecSingleTx(crTablesSQL, sqlDesc(crTablesSQL))
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

func (st *storage) createIndexes() error {
	err := st.bulkExecSingleTx(crIndexesSQL, sqlDesc(crIndexesSQL))
	if err != nil {
		return errors.WithStack(err)
	}
	return nil
}

// keyDoc is a nearly-raw copy of a row in the PostgreSQL `keys` table.
type keyDoc struct {
	RFingerprint string
	CTime        time.Time
	MTime        time.Time
	IdxTime      time.Time
	MD5          string
	Doc          string
	Keywords     string
}

func readOneKey(b []byte, rfingerprint string) (*openpgp.PrimaryKey, error) {
	kr := openpgp.NewKeyReader(bytes.NewBuffer(b))
	keys, err := kr.Read()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if len(keys) == 0 {
		return nil, nil
	} else if len(keys) > 1 {
		return nil, errors.Errorf("multiple keys in record: %v, %v", keys[0].Fingerprint(), keys[1].Fingerprint())
	}
	if keys[0].RFingerprint != rfingerprint {
		return nil, errors.Errorf("RFingerprint mismatch: expected=%q got=%q",
			rfingerprint, keys[0].RFingerprint)
	}
	return keys[0], nil
}

func keywordsTSVector(key *openpgp.PrimaryKey) string {
	keywords, _, _ := keywordsFromKey(key)
	tsv, err := keywordsToTSVector(keywords, " ")
	if err != nil {
		// In this case we've found a key that generated
		// an invalid tsvector - this is pretty much guaranteed
		// to be a bogus key, since having a valid key with
		// user IDs that exceed limits is highly unlikely.
		// In the future we should catch this earlier and
		// reject it as a bad key, but for now we just skip
		// storing keyword information.
		log.Warningf("keywords for rfp=%q exceeds limit, ignoring: %v", key.RFingerprint, err)
		return ""
	}
	return tsv
}

func keywordsTSQuery(query string) (string, error) {
	keywords, _ := keywordsFromSearch(query)
	tsq, err := keywordsToTSVector(keywords, " & ")
	if err != nil {
		log.Warningf("cannot convert search string to tsquery: %v", err)
		return "", err
	}
	return tsq, nil
}

// A woefully incomplete list of PostgreSQL stop words to minimise TSVector churn.
// https://github.com/postgres/postgres/blob/master/src/backend/snowball/stopwords/english.stop
var pgEnglishStopWords = []string{
	"i", "me", "my", "myself", "we", "our", "ours", "ourselves", "you", "your", "yours", "yourself", "yourselves",
	"he", "him", "his", "himself", "she", "her", "hers", "herself", "it", "its", "itself",
	"they", "them", "their", "theirs", "themselves", "what", "which", "who", "whom", "this", "that", "these", "those",
	"am", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "having", "do", "does", "did", "doing",
	"a", "an", "the", "and", "but", "if", "or",
	"because", "as", "until", "while", "of", "at", "by", "for", "with", "about", "against", "between", "into",
	"through", "during", "before", "after", "above", "below",
	"to", "from", "up", "down", "in", "out", "on", "off", "over", "under", "again", "further",
	"then", "once", "here", "there", "when", "where", "why", "how", "all", "any", "both", "each",
	"few", "more", "most", "other", "some", "such",
	"no", "nor", "not", "only", "own", "same", "so", "than", "too", "very",
	"s", "t", "can", "will", "just", "don", "should", "now",
	"[", "\\", "]", "^", "_", "`", "{", "|", "}", "~", // easier to list these than calculate a formula
}

// sanitiseForTSVector escapes characters that have special meaning to ::TSVECTOR
func sanitiseForTSVector(s string) string {
	s = strings.ReplaceAll(s, `'`, `''`)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return s
}

// keywordsToTSVector converts a slice of keywords to a
// PostgreSQL tsvector. If the resulting tsvector would
// be considered invalid by PostgreSQL an error is
// returned instead.
// `sep` SHOULD be either " " or "&". If "&", the output
// string is a tsquery rather than a tsvector.
func keywordsToTSVector(keywords []string, sep string) (string, error) {
	const (
		lexemeLimit   = 2048            // 2KB for single lexeme
		tsvectorLimit = 1 * 1024 * 1024 // 1MB for lexemes + positions
	)
	newKeywords := []string{}
	for _, k := range keywords {
		if l := len(k); l >= lexemeLimit {
			return "", fmt.Errorf("keyword exceeds limit (%d >= %d)", l, lexemeLimit)
		}
		newKeywords = append(newKeywords, fmt.Sprintf("'%s'", sanitiseForTSVector(k)))
	}
	tsv := strings.Join(newKeywords, sep)

	if l := len(tsv); l >= tsvectorLimit {
		return "", fmt.Errorf("keywords exceeds limit (%d >= %d)", l, tsvectorLimit)
	}
	return tsv, nil
}

// keywordsFromTSVector converts a PostgreSQL tsvector back into a slice of tokens.
func keywordsFromTSVector(tsv string) (result []string) {
	m := make(map[string]bool)
	var s string
	for {
		i := strings.Index(tsv, "'")
		if i == -1 {
			break
		}
		tsv = tsv[i+1:]
		i = strings.Index(tsv, "'")
		if i == -1 {
			break
		}
		s, tsv = tsv[:i], tsv[i+1:]
		m[s] = true
	}
	for k := range m {
		result = append(result, k)
	}
	return
}

// keywordsFromKey returns slices of keyword tokens, email addresses, and UIDs
// extracted from the UserID packets of the given key.
//
// TODO: shouldn't this be a method on openpgp.PrimaryKey instead?
// It's not specific to PostgreSQL, or even to storage.
func keywordsFromKey(key *openpgp.PrimaryKey) (keywords []string, emails []string, uids []string) {
	keywordMap := make(map[string]bool)
	emailMap := make(map[string]bool)
	uidMap := make(map[string]bool)
	for _, uid := range key.UserIDs {
		s := strings.ToLower(uid.Keywords)
		// always include full text of UserID (lowercased)
		keywordMap[s] = true
		uidMap[s] = true
		email := ""
		commentary := s
		lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
		if lbr != -1 && rbr > lbr {
			email = s[lbr+1 : rbr]
			commentary = s[:lbr]
		} else {
			email = s
			commentary = ""
		}
		// TODO: this still doesn't recognise all possible forms of UID :confounded:
		if email != "" {
			keywordMap[email] = true
			emailMap[email] = true
			parts := strings.SplitN(email, "@", 2)
			if len(parts) == 2 {
				keywordMap[parts[0]] = true
				keywordMap[parts[1]] = true
			}
		}
		if commentary != "" {
			for _, field := range strings.FieldsFunc(commentary, func(r rune) bool {
				return !utf8.ValidRune(r) || // split on invalid runes
					!(unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '@') // split on [^[:alnum:]@-]
			}) {
				keywordMap[field] = true
				for _, part := range strings.Split(field, "-") {
					keywordMap[part] = true
				}
			}
		}
	}
	for k := range keywordMap {
		// discard empty strings, low ASCII symbols, single digits, stop words
		if k == "" || (len(k) == 1 && k[0] < 0x41) || slices.Contains(pgEnglishStopWords, k) {
			continue
		}
		keywords = append(keywords, k)
	}
	for k := range emailMap {
		if k == "" {
			continue
		}
		emails = append(emails, k)
	}
	for k := range uidMap {
		if k == "" {
			continue
		}
		uids = append(uids, k)
	}
	return
}

// keywordsFromSearch returns slices of keyword tokens and email addresses
// extracted from the supplied search string.
//
// TODO: shouldn't this also be generic?
func keywordsFromSearch(search string) (keywords []string, emails []string) {
	keywordMap := make(map[string]bool)
	emailMap := make(map[string]bool)
	s := strings.ToLower(search)
	email := s
	lbr, rbr := strings.Index(s, "<"), strings.LastIndex(s, ">")
	if lbr != -1 && rbr > lbr {
		email = s[lbr+1 : rbr]
		keywordMap[email] = true
		emailMap[email] = true
	} else {
		for _, field := range strings.FieldsFunc(s, func(r rune) bool {
			return !utf8.ValidRune(r) || unicode.IsSpace(r) // split on invalid runes and whitespace
		}) {
			keywordMap[field] = true
		}
	}
	for k := range keywordMap {
		// discard empty strings, low ASCII symbols, single digits, stop words
		if k == "" || (len(k) == 1 && k[0] < 0x41) || slices.Contains(pgEnglishStopWords, k) {
			continue
		}
		keywords = append(keywords, k)
	}
	for k := range emailMap {
		if k == "" {
			continue
		}
		emails = append(emails, k)
	}
	return
}

func subkeys(key *openpgp.PrimaryKey) []string {
	var result []string
	for _, subkey := range key.SubKeys {
		result = append(result, subkey.RFingerprint)
	}
	return result
}
