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
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
)

// admitTombstone decides whether an incoming blocklist tombstone may be stored.
//
// A tombstone makes this server drop key material, so it is only honoured when
// the operator has said whose blocks to honour: its origin must be configured
// as trusted, and its signature must verify against one of that origin's keys.
// Nothing is trusted by default, so a server that has not been configured for
// blocklists ignores every tombstone offered to it.
//
// This sits in storage rather than at each ingress because every route that
// writes key material converges here, so reconciliation, HKP submission and
// keydump loading are all covered by the one check.
func (st *storage) admitTombstone(key *openpgp.PrimaryKey) error {
	if !openpgp.IsTombstone(key) {
		return nil
	}
	ts, sigs, err := openpgp.TombstoneOf(key)
	if err != nil {
		return errors.Wrap(hkpstorage.ErrBlockRefused, "malformed tombstone: "+err.Error())
	}

	fingerprints := st.policy.TrustedBlocklistKeys(ts.Origin)
	if len(fingerprints) == 0 {
		return errors.Wrapf(hkpstorage.ErrBlockRefused,
			"tombstone for 0x%s: no keys are trusted for blocklist origin %q",
			ts.Fingerprint, ts.Origin)
	}

	// Deliberately without AutoPreen: this runs on the ingest path, and a
	// write-back here would mutate storage while it is being written to.
	// Tombstones are filtered out of this query, so one cannot vouch for another.
	records, err := st.FetchRecordsByFp(fingerprints)
	if err != nil {
		return errors.Wrapf(err, "cannot load trusted keys for blocklist origin %q", ts.Origin)
	}
	var trusted []*openpgp.PrimaryKey
	for _, record := range records {
		if record.PrimaryKey != nil {
			trusted = append(trusted, record.PrimaryKey)
		}
	}
	if len(trusted) == 0 {
		return errors.Wrapf(hkpstorage.ErrBlockRefused,
			"tombstone for 0x%s: none of the keys trusted for origin %q are in this keyserver",
			ts.Fingerprint, ts.Origin)
	}

	signer, err := openpgp.VerifyTombstone(*ts, sigs, trusted)
	if err != nil {
		return errors.Wrapf(hkpstorage.ErrBlockRefused, "tombstone for 0x%s: %v", ts.Fingerprint, err)
	}
	log.Debugf("admitted tombstone for 0x%s from origin %q, signed by 0x%s",
		ts.Fingerprint, ts.Origin, signer)
	return nil
}

// admitTombstones splits a batch into the keys that may be stored and the
// errors for those that may not, so that one refused tombstone does not sink a
// whole keydump.
func (st *storage) admitTombstones(keys []*openpgp.PrimaryKey, result *hkpstorage.InsertError) []*openpgp.PrimaryKey {
	admitted := make([]*openpgp.PrimaryKey, 0, len(keys))
	for _, key := range keys {
		if err := st.admitTombstone(key); err != nil {
			log.Warn(err)
			result.Errors = append(result.Errors, err)
			continue
		}
		admitted = append(admitted, key)
	}
	return admitted
}
