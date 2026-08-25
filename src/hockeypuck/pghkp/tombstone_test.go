/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2026 Casey Marshall and the Hockeypuck Contributors

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

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	gc "gopkg.in/check.v1"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pgtest"
	hktesting "hockeypuck/testing"
)

// TS exercises blocklist tombstones against a real database. It needs its own
// suite rather than reusing S, because the policy has to carry a trusted
// blocklist origin and S builds one without.
type TS struct {
	pgtest.PGSuite
	db      *sql.DB
	storage *storage
	// signer issues blocks for the trusted origin; origin is its public half as
	// the server holds it.
	signer *gocrypto.Entity
	origin *openpgp.PrimaryKey
}

var _ = gc.Suite(&TS{})

const tsOrigin = "keys.example.com"

func (s *TS) SetUpTest(c *gc.C) {
	s.PGSuite.SetUpTest(c)

	var err error
	s.db, err = sql.Open("postgres", s.URL)
	c.Assert(err, gc.IsNil)
	s.db.Exec("DROP DATABASE hkp")

	// Mint the origin's signing key before the policy, so its fingerprint can be
	// the trusted one.
	s.signer, err = gocrypto.NewEntity("Blocklist Origin", "", "origin@example.com", nil)
	c.Assert(err, gc.IsNil)
	var pub bytes.Buffer
	c.Assert(s.signer.Serialize(&pub), gc.IsNil)
	origins, err := openpgp.NewKeyReader(bytes.NewReader(pub.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(origins, gc.HasLen, 1)
	s.origin = origins[0]

	policy, err := openpgp.NewPolicy(
		openpgp.BlocklistOrigin(tsOrigin),
		openpgp.TrustBlocklistOrigin(tsOrigin, []string{s.origin.Fingerprint}),
	)
	c.Assert(err, gc.IsNil)
	st, err := New(s.db, policy, 100)
	c.Assert(err, gc.IsNil)
	s.storage = st.(*storage)
}

func (s *TS) TearDownTest(c *gc.C) {
	if s.db != nil {
		s.db.Exec("DROP DATABASE hkp")
		s.db.Close()
	}
	s.PGSuite.TearDownTest(c)
}

// victim reads a key to be blocked, and stores it.
func (s *TS) victim(c *gc.C) *openpgp.PrimaryKey {
	keys, err := openpgp.ReadArmorKeys(hktesting.MustInput("uat.asc"))
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	return keys[0]
}

// trustOrigin stores the origin's public key, without which no block can be
// admitted: verification needs the key to be present in the keyserver.
func (s *TS) trustOrigin(c *gc.C) {
	_, err := s.storage.Upsert(s.origin)
	c.Assert(err, gc.IsNil)
}

func (s *TS) block(c *gc.C, fingerprint string, signed bool) *openpgp.PrimaryKey {
	ts := openpgp.Tombstone{Fingerprint: fingerprint, Origin: tsOrigin, Reason: "abuse"}
	if !signed {
		tombstone, err := openpgp.NewTombstone(ts)
		c.Assert(err, gc.IsNil)
		return tombstone
	}
	sig, err := openpgp.SignTombstone(ts, s.signer)
	c.Assert(err, gc.IsNil)
	tombstone, err := openpgp.NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)
	return tombstone
}

func (s *TS) storedTag(c *gc.C, fingerprint string) (isTombstone, present bool) {
	records, err := s.storage.FetchRecordsByFp([]string{fingerprint}, hkpstorage.IncludeTombstones)
	c.Assert(err, gc.IsNil)
	for _, record := range records {
		if record.Fingerprint == fingerprint {
			return openpgp.IsTombstone(record.PrimaryKey), true
		}
	}
	return false, false
}

func (s *TS) componentCounts(c *gc.C, fingerprint string) (subkeys, userids int) {
	rfp := reverse(fingerprint)
	c.Assert(s.db.QueryRow("SELECT count(*) FROM subkeys WHERE rfingerprint = $1", rfp).Scan(&subkeys), gc.IsNil)
	c.Assert(s.db.QueryRow("SELECT count(*) FROM userids WHERE rfingerprint = $1", rfp).Scan(&userids), gc.IsNil)
	return subkeys, userids
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// TestUnsignedBlockRefused: a block with no signature is never admitted, however
// trusted its origin.
func (s *TS) TestUnsignedBlockRefused(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, false))
	c.Assert(err, gc.NotNil)
	c.Check(hkpstorage.IsBlockRefused(err), gc.Equals, true)
	_, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, false)
}

// TestUntrustedOriginRefused: a correctly signed block from an origin this
// server does not trust is refused. Here the origin's key is simply absent.
func (s *TS) TestUntrustedOriginRefused(c *gc.C) {
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.NotNil)
	c.Check(hkpstorage.IsBlockRefused(err), gc.Equals, true)
}

// TestBlockReplacesKeyMaterial is the core behaviour: a block takes the key's
// place, and the key's components go with it.
func (s *TS) TestBlockReplacesKeyMaterial(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(victim)
	c.Assert(err, gc.IsNil)
	subkeys, userids := s.componentCounts(c, victim.Fingerprint)
	c.Assert(subkeys+userids > 0, gc.Equals, true, gc.Commentf("victim should have components to lose"))

	_, err = s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true)
	c.Check(isTombstone, gc.Equals, true)
	subkeys, userids = s.componentCounts(c, victim.Fingerprint)
	c.Check(subkeys, gc.Equals, 0)
	c.Check(userids, gc.Equals, 0, gc.Commentf("a block must not leave the blocked key's user IDs behind"))
}

// TestBlockedKeyRefusedOnReingest: once blocked, the key cannot come back.
func (s *TS) TestBlockedKeyRefusedOnReingest(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	kc, err := s.storage.Upsert(victim)
	c.Assert(err, gc.IsNil)
	_, refused := kc.(hkpstorage.KeyBlocked)
	c.Check(refused, gc.Equals, true)
	c.Check(kc.InsertDigests(), gc.HasLen, 0,
		gc.Commentf("a refused key must not be advertised to partners"))

	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Check(isTombstone, gc.Equals, true)
}

// TestReplaceDoesNotWithdrawABlock: Replace deletes before inserting, so without
// a guard ordinary key material would quietly remove a block and take its place.
// Only an explicit unblock may withdraw one.
func (s *TS) TestReplaceDoesNotWithdrawABlock(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	kc, err := s.storage.Replace(victim)
	c.Assert(err, gc.IsNil)
	_, refused := kc.(hkpstorage.KeyBlocked)
	c.Check(refused, gc.Equals, true)

	isTombstone, _ := s.storedTag(c, victim.Fingerprint)
	c.Check(isTombstone, gc.Equals, true, gc.Commentf("the block must survive a Replace"))
}

// TestQueryVisibility: to a caller asking for key material a blocked key is
// simply absent, but reconciliation and dumps must still see it.
func (s *TS) TestQueryVisibility(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, err := s.storage.Upsert(s.block(c, victim.Fingerprint, true))
	c.Assert(err, gc.IsNil)

	records, err := s.storage.FetchRecordsByFp([]string{victim.Fingerprint})
	c.Assert(err, gc.IsNil)
	c.Check(records, gc.HasLen, 0, gc.Commentf("a block must not answer a key material query"))

	records, err = s.storage.FetchRecordsByFp([]string{victim.Fingerprint}, hkpstorage.IncludeTombstones)
	c.Assert(err, gc.IsNil)
	c.Check(records, gc.HasLen, 1)
}

// TestInsertAdmitsBlocksAfterKeyMaterial covers a keydump restore: the trusted
// signing key and the blocks it signed arrive in one batch, and a block cannot
// be admitted until the key vouching for it is stored.
func (s *TS) TestInsertAdmitsBlocksAfterKeyMaterial(c *gc.C) {
	victim := s.victim(c)
	batch := []*openpgp.PrimaryKey{
		s.block(c, victim.Fingerprint, true), // deliberately before the key that vouches for it
		s.origin,
	}
	_, _, err := s.storage.Insert(batch)
	c.Assert(err, gc.IsNil)

	isTombstone, present := s.storedTag(c, victim.Fingerprint)
	c.Check(present, gc.Equals, true, gc.Commentf("restoring a dump must not drop its blocks"))
	c.Check(isTombstone, gc.Equals, true)
}

// TestInsertCountsBlocks guards the counter: the bulk result used to overwrite
// the tombstones already counted, under-reporting mixed batches.
func (s *TS) TestInsertCountsBlocks(c *gc.C) {
	s.trustOrigin(c)
	victim := s.victim(c)
	_, n, err := s.storage.Insert([]*openpgp.PrimaryKey{s.block(c, victim.Fingerprint, true)})
	c.Assert(err, gc.IsNil)
	c.Check(n, gc.Equals, 1, gc.Commentf("a stored block should be counted as inserted"))
}
