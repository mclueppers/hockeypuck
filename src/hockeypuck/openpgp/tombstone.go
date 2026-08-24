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
	"crypto/md5"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

// A tombstone is a certificate consisting of a single trust packet, stored
// under the fingerprint of a key this server refuses to hold. It replaces the
// key material rather than sitting alongside it, so a blocked fingerprint's row
// is occupied and an incoming copy of the key collides with it on insert.
//
// The trust packet uses the noisy SKS app context, which means its SKS digest
// covers only its first subpacket (see trustPacketSKSView). The first notation
// is therefore the whole of a tombstone's reconciliation identity: two operators
// who block the same key agree on its digest however much their annotations
// differ, so reconciliation converges instead of churning. Everything after the
// first notation - origin, reason, the signature binding them - rides along
// outside the SKS digest and is covered by the trust digest instead.
const (
	// trustTypeBlockedKey marks a trust packet as a tombstone. Like
	// trustTypeRedactedUserID it is carried as the trust packet's type notation,
	// which for a noisy packet is the second notation.
	trustTypeBlockedKey = "blockedKey"

	// tombstoneVersion is the value of the type notation. It exists so the
	// format can be revised without another flag day.
	tombstoneVersion = "1"

	// tombstoneFingerprintNotation carries the blocked key's fingerprint and
	// MUST be the first notation; see the note above on reconciliation identity.
	tombstoneFingerprintNotation = "blockedFingerprint"

	// tombstoneOriginNotation names the operator who issued the block. A peer
	// decides whether to accept a tombstone by checking this against its
	// configured trusted origins, and the signature is what makes it mean
	// anything.
	tombstoneOriginNotation = "blocklistOrigin"

	// tombstoneReasonNotation carries a short reason code. It deliberately does
	// not carry free text: a tombstone is published to every peer, so anything
	// written here is disclosed to all of them.
	tombstoneReasonNotation = "blocklistReason"
)

// ErrNotTombstone is returned when a certificate is not a blocklist tombstone.
var ErrNotTombstone = fmt.Errorf("not a blocklist tombstone")

// Tombstone describes a blocked key.
type Tombstone struct {
	// Fingerprint is the blocked key's fingerprint, lowercase hex.
	Fingerprint string
	// Origin names the operator who issued the block, e.g. a hostname.
	Origin string
	// Reason is an optional short code. It MUST NOT be free text; see
	// tombstoneReasonNotation.
	Reason string
}

// Validate checks that a Tombstone can be safely serialised and signed.
func (ts Tombstone) Validate() error {
	fp := strings.ToLower(ts.Fingerprint)
	switch len(fp) {
	case 32, 40, 64: // v3, v4, v6 fingerprints
	default:
		return errors.Errorf("%q is not a fingerprint (expected 32, 40 or 64 hex digits, got %d)",
			ts.Fingerprint, len(ts.Fingerprint))
	}
	for _, r := range fp {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return errors.Errorf("%q is not hexadecimal", ts.Fingerprint)
		}
	}
	if ts.Origin == "" {
		return errors.New("tombstone origin is required")
	}
	// The signing message is newline delimited, so a newline in a field would
	// let one field impersonate another.
	for _, field := range []string{ts.Origin, ts.Reason} {
		if strings.ContainsAny(field, "\n\r") {
			return errors.Errorf("tombstone fields must not contain newlines: %q", field)
		}
	}
	return nil
}

// normalise returns a copy with the fingerprint folded to lowercase.
func (ts Tombstone) normalise() Tombstone {
	ts.Fingerprint = strings.ToLower(ts.Fingerprint)
	return ts
}

// SigningMessage returns the canonical bytes an origin signs to bind its name to
// this block. It covers every field the tombstone asserts, so a peer that
// verifies the signature knows the origin really did issue this block for this
// fingerprint, and not merely that some node passed it along.
func (ts Tombstone) SigningMessage() []byte {
	ts = ts.normalise()
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s=%s\n", tombstoneFingerprintNotation, ts.Fingerprint)
	fmt.Fprintf(&buf, "%s=%s\n", tombstoneOriginNotation, ts.Origin)
	if ts.Reason != "" {
		fmt.Fprintf(&buf, "%s=%s\n", tombstoneReasonNotation, ts.Reason)
	}
	return buf.Bytes()
}

func (ts Tombstone) String() string {
	if ts.Reason != "" {
		return fmt.Sprintf("0x%s blocked by %s (%s)", ts.Fingerprint, ts.Origin, ts.Reason)
	}
	return fmt.Sprintf("0x%s blocked by %s", ts.Fingerprint, ts.Origin)
}

// notations renders the tombstone as an ordered notation set. The order is
// load-bearing: the fingerprint must come first so that it alone determines the
// SKS digest, and the type notation must come second because that is where
// Trust.TrustTypeNotation looks for it.
func (ts Tombstone) notations() []*packet.Notation {
	ts = ts.normalise()
	ns := []*packet.Notation{
		{Name: tombstoneFingerprintNotation, Value: []byte(ts.Fingerprint), IsCritical: true},
		{Name: trustTypeBlockedKey, Value: []byte(tombstoneVersion), IsCritical: true},
		{Name: tombstoneOriginNotation, Value: []byte(ts.Origin)},
	}
	if ts.Reason != "" {
		ns = append(ns, &packet.Notation{Name: tombstoneReasonNotation, Value: []byte(ts.Reason)})
	}
	return ns
}

// NewTombstone builds the certificate that stands in for a blocked key. The
// supplied signatures should be over ts.SigningMessage(); a tombstone with none
// is only ever acceptable from a local operator, never from a peer.
func NewTombstone(ts Tombstone, sigs ...*Signature) (*PrimaryKey, error) {
	if err := ts.Validate(); err != nil {
		return nil, errors.WithStack(err)
	}
	ts = ts.normalise()

	trust := &Trust{
		AppContext: trustAppContextNoisySKS,
		// A tombstone has no parent packet, so it is nobody's child.
		PacketContext: 0,
		Notations:     ts.notations(),
		Signatures:    sigs,
	}
	if err := trust.UpdatePacket(); err != nil {
		return nil, errors.WithStack(err)
	}

	pubkey := &PrimaryKey{
		PublicKey: PublicKey{
			Fingerprint: ts.Fingerprint,
			Packet: Packet{
				UUID: ts.Fingerprint,
				Tag:  trust.Tag,
				Data: trust.Data,
			},
		},
	}
	var err error
	pubkey.MD5, pubkey.TrustMD5, err = SksDigest(pubkey, md5.New(), md5.New())
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pubkey.Length = len(trust.Data)
	return pubkey, nil
}

// IsTombstone reports whether a certificate stands in for a blocked key rather
// than carrying real key material. Real certificates are rooted at a public key
// packet (tag 6); only a tombstone is rooted at a trust packet.
func IsTombstone(pubkey *PrimaryKey) bool {
	return pubkey != nil && pubkey.Tag == 12
}

// TombstoneOf returns what a tombstone certificate asserts, along with the
// signatures offered in support of it. It returns ErrNotTombstone if pubkey is
// ordinary key material.
func TombstoneOf(pubkey *PrimaryKey) (*Tombstone, []*Signature, error) {
	if !IsTombstone(pubkey) {
		return nil, nil, errors.WithStack(ErrNotTombstone)
	}
	op, err := newOpaquePacket(pubkey.Data)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	trust, err := ParseTrust(op, pubkey.Creation, pubkey.UUID, pubkey.UUID)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}
	return tombstoneOfTrust(trust)
}

func tombstoneOfTrust(trust *Trust) (*Tombstone, []*Signature, error) {
	typeNotation := trust.TrustTypeNotation()
	if typeNotation == nil || typeNotation.Name != trustTypeBlockedKey {
		return nil, nil, errors.WithStack(ErrNotTombstone)
	}
	if version := string(typeNotation.Value); version != tombstoneVersion {
		return nil, nil, errors.Errorf("unsupported tombstone version %q", version)
	}
	// The fingerprint must be the FIRST notation, not merely present: its
	// position is what fixes the SKS digest, so accepting it elsewhere would
	// accept a tombstone whose identity does not match its digest.
	if len(trust.Notations) == 0 || trust.Notations[0].Name != tombstoneFingerprintNotation {
		return nil, nil, errors.Errorf("tombstone does not lead with %s", tombstoneFingerprintNotation)
	}
	ts := &Tombstone{Fingerprint: string(trust.Notations[0].Value)}
	if n := trust.GetNotationByName(tombstoneOriginNotation); n != nil {
		ts.Origin = string(n.Value)
	}
	if n := trust.GetNotationByName(tombstoneReasonNotation); n != nil {
		ts.Reason = string(n.Value)
	}
	if err := ts.Validate(); err != nil {
		return nil, nil, errors.WithStack(err)
	}
	*ts = ts.normalise()
	return ts, trust.Signatures, nil
}

// isTombstonePacket cheaply reports whether an opaque trust packet is a bare
// tombstone rather than an annotation attached to the key material before it.
// The reader needs to tell the two apart without parsing, so that a tombstone in
// the middle of a keydump starts its own certificate instead of being attached
// to whatever key happened to precede it.
func isTombstonePacket(op *packet.OpaquePacket) bool {
	if op.Tag != 12 || len(op.Contents) < 6 {
		return false
	}
	// An attached trust packet names the packet type it annotates; a tombstone
	// annotates nothing.
	if op.Contents[5] != 0 {
		return false
	}
	if string(op.Contents[2:5]) != trustAppContextNoisySKS {
		return false
	}
	subpackets, err := packet.OpaqueSubpackets(op.Contents[6:])
	if err != nil || len(subpackets) == 0 {
		return false
	}
	if subpackets[0].SubType&0x7f != 20 { // notation
		return false
	}
	notation, err := parseNotation(subpackets[0])
	if err != nil {
		return false
	}
	return notation.Name == tombstoneFingerprintNotation
}

// parseTombstoneCert builds the certificate for a bare trust packet found where
// a public key packet would otherwise start a certificate.
func parseTombstoneCert(op *packet.OpaquePacket) (*PrimaryKey, error) {
	trust, err := ParseTrust(op, time.Time{}, "", "")
	if err != nil {
		return nil, errors.Wrap(err, "unreadable tombstone trust packet")
	}
	ts, sigs, err := tombstoneOfTrust(trust)
	if err != nil {
		return nil, err
	}
	// Rebuild rather than adopting the incoming bytes, so that a tombstone is
	// stored in exactly one canonical form however a peer chose to serialise it.
	pubkey, err := NewTombstone(*ts, sigs...)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

// publicKeyPacket returns the parsed public key packet for a component key.
func publicKeyPacket(pub *PublicKey) (*packet.PublicKey, error) {
	op, err := pub.opaquePacket()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	parsed, err := op.Parse()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	pk, ok := parsed.(*packet.PublicKey)
	if !ok {
		return nil, errors.WithStack(ErrInvalidPacketType)
	}
	return pk, nil
}

// VerifyTombstone reports the fingerprint of the trusted key that vouches for a
// tombstone, or an error if none does.
//
// This is what makes the origin notation mean anything. Without it a tombstone
// asserts an origin that any node could have written, and a peer accepting on
// the strength of that name alone would take a block from anyone willing to
// type it. With it, accepting a tombstone means the named origin really did
// issue this block for this fingerprint, whoever passed it along.
//
// The caller supplies the keys it trusts for the tombstone's origin; deciding
// which those are is configuration, not cryptography.
func VerifyTombstone(ts Tombstone, sigs []*Signature, trusted []*PrimaryKey) (string, error) {
	if err := ts.Validate(); err != nil {
		return "", errors.WithStack(err)
	}
	if len(sigs) == 0 {
		return "", errors.Errorf("tombstone for 0x%s carries no signature", ts.Fingerprint)
	}
	if len(trusted) == 0 {
		return "", errors.Errorf("no keys are trusted for origin %q", ts.Origin)
	}
	message := ts.SigningMessage()

	var lastErr error
	for _, sig := range sigs {
		s, err := sig.signaturePacket()
		if err != nil {
			lastErr = err
			continue
		}
		// The signing message is a bare byte string, so only a binary document
		// signature can be over it. Accepting other types would let a signature
		// made for some other purpose be replayed as a block.
		if s.SigType != packet.SigTypeBinary {
			lastErr = errors.Errorf("tombstone signature has type %d, want a binary document signature", s.SigType)
			continue
		}
		if !s.Hash.Available() {
			lastErr = errors.Errorf("tombstone signature uses unavailable hash %v", s.Hash)
			continue
		}
		for _, key := range trusted {
			// A signing subkey is the usual arrangement, so try those too.
			candidates := []*PublicKey{&key.PublicKey}
			for i := range key.SubKeys {
				candidates = append(candidates, &key.SubKeys[i].PublicKey)
			}
			for _, candidate := range candidates {
				pub, err := publicKeyPacket(candidate)
				if err != nil {
					lastErr = err
					continue
				}
				if !pub.CanSign() {
					continue
				}
				h := s.Hash.New()
				if _, err := h.Write(message); err != nil {
					lastErr = err
					continue
				}
				if err := pub.VerifySignature(h, s); err != nil {
					lastErr = err
					continue
				}
				return key.Fingerprint, nil
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no trusted key matched")
	}
	return "", errors.Wrapf(lastErr, "no trusted signature on tombstone for 0x%s claiming origin %q",
		ts.Fingerprint, ts.Origin)
}
