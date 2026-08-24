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

package openpgp

import (
	"bytes"
	"time"

	gocrypto "github.com/ProtonMail/go-crypto/openpgp"
	gc "gopkg.in/check.v1"
)

type TombstoneVerifySuite struct{}

var _ = gc.Suite(&TombstoneVerifySuite{})

// originKey mints a throwaway key to stand in for an operator's blocklist
// signing key, returning both the private entity and the public form the
// server would hold.
func (s *TombstoneVerifySuite) originKey(c *gc.C) (*gocrypto.Entity, *PrimaryKey) {
	entity, err := gocrypto.NewEntity("Blocklist Origin", "", "origin@example.com", nil)
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(entity.Serialize(&buf), gc.IsNil)
	keys, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(keys, gc.HasLen, 1)
	return entity, keys[0]
}

func (s *TombstoneVerifySuite) sign(c *gc.C, entity *gocrypto.Entity, message []byte) *Signature {
	var buf bytes.Buffer
	c.Assert(gocrypto.DetachSign(&buf, entity, bytes.NewReader(message), nil), gc.IsNil)
	op, err := newOpaquePacket(buf.Bytes())
	c.Assert(err, gc.IsNil)
	sig, err := ParseSignature(op, time.Time{}, "", "")
	c.Assert(err, gc.IsNil)
	return sig
}

// TestSignedTombstoneSurvivesTheWire is the whole point of the signature: a
// tombstone that has been serialised, sent and re-read must still verify.
func (s *TombstoneVerifySuite) TestSignedTombstoneSurvivesTheWire(c *gc.C) {
	entity, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}

	tombstone, err := NewTombstone(ts, s.sign(c, entity, ts.SigningMessage()))
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(WritePackets(&buf, tombstone), gc.IsNil)
	received, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(received, gc.HasLen, 1)

	gotTS, gotSigs, err := TombstoneOf(received[0])
	c.Assert(err, gc.IsNil)
	c.Assert(gotSigs, gc.HasLen, 1, gc.Commentf("the signature must survive serialisation"))

	fp, err := VerifyTombstone(*gotTS, gotSigs, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)
	c.Check(fp, gc.Equals, pub.Fingerprint)
}

func (s *TombstoneVerifySuite) TestRejectsUntrustedSigner(c *gc.C) {
	entity, _ := s.originKey(c)
	_, otherPub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}

	sig := s.sign(c, entity, ts.SigningMessage())
	_, err := VerifyTombstone(ts, []*Signature{sig}, []*PrimaryKey{otherPub})
	c.Check(err, gc.ErrorMatches, ".*no trusted signature.*")
}

func (s *TombstoneVerifySuite) TestRejectsUnsigned(c *gc.C) {
	_, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	_, err := VerifyTombstone(ts, nil, []*PrimaryKey{pub})
	c.Check(err, gc.ErrorMatches, ".*carries no signature.*")
}

func (s *TombstoneVerifySuite) TestRejectsWhenNothingIsTrusted(c *gc.C) {
	entity, _ := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, ts.SigningMessage())
	_, err := VerifyTombstone(ts, []*Signature{sig}, nil)
	c.Check(err, gc.ErrorMatches, ".*no keys are trusted for origin.*")
}

// TestSignatureBindsEveryField is the attack the signature exists to stop:
// taking a validly signed tombstone and re-pointing it at another key, another
// origin, or another reason.
func (s *TombstoneVerifySuite) TestSignatureBindsEveryField(c *gc.C) {
	entity, pub := s.originKey(c)
	signed := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}
	sig := s.sign(c, entity, signed.SigningMessage())

	// Sanity: it verifies as issued.
	_, err := VerifyTombstone(signed, []*Signature{sig}, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)

	for _, altered := range []Tombstone{
		{Fingerprint: tsFpB, Origin: "pgpkeys.eu", Reason: "abuse"},
		{Fingerprint: tsFpA, Origin: "evil.example", Reason: "abuse"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "gdpr"},
		{Fingerprint: tsFpA, Origin: "pgpkeys.eu"},
	} {
		_, err := VerifyTombstone(altered, []*Signature{sig}, []*PrimaryKey{pub})
		c.Check(err, gc.NotNil, gc.Commentf("re-pointed tombstone %+v must not verify", altered))
	}
}

// TestCaseFoldingDoesNotBreakVerification guards the normalisation seam: a
// tombstone signed with an uppercase fingerprint must still verify once stored
// in the lowercase form everything else uses.
func (s *TombstoneVerifySuite) TestCaseFoldingDoesNotBreakVerification(c *gc.C) {
	entity, pub := s.originKey(c)
	upper := Tombstone{Fingerprint: "10FE8CF1B483F7525039AA2A361BC1F023E0DCCA", Origin: "pgpkeys.eu"}
	sig := s.sign(c, entity, upper.SigningMessage())

	lower := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu"}
	_, err := VerifyTombstone(lower, []*Signature{sig}, []*PrimaryKey{pub})
	c.Check(err, gc.IsNil)
}

// TestSignThenVerifyRoundTrip closes the loop: what SignTombstone produces is
// what VerifyTombstone accepts, so the tooling that issues blocks and the
// server that admits them agree.
func (s *TombstoneVerifySuite) TestSignThenVerifyRoundTrip(c *gc.C) {
	entity, pub := s.originKey(c)
	ts := Tombstone{Fingerprint: tsFpA, Origin: "pgpkeys.eu", Reason: "abuse"}

	sig, err := SignTombstone(ts, entity)
	c.Assert(err, gc.IsNil)

	tombstone, err := NewTombstone(ts, sig)
	c.Assert(err, gc.IsNil)

	var buf bytes.Buffer
	c.Assert(WritePackets(&buf, tombstone), gc.IsNil)
	received, err := NewKeyReader(bytes.NewReader(buf.Bytes())).Read()
	c.Assert(err, gc.IsNil)
	c.Assert(received, gc.HasLen, 1)

	gotTS, gotSigs, err := TombstoneOf(received[0])
	c.Assert(err, gc.IsNil)
	fp, err := VerifyTombstone(*gotTS, gotSigs, []*PrimaryKey{pub})
	c.Assert(err, gc.IsNil)
	c.Check(fp, gc.Equals, pub.Fingerprint)
}

func (s *TombstoneVerifySuite) TestSignRequiresAPrivateKey(c *gc.C) {
	_, err := SignTombstone(Tombstone{Fingerprint: tsFpA, Origin: "x"}, nil)
	c.Check(err, gc.ErrorMatches, ".*requires a private key.*")
}
