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
	"time"

	_ "github.com/lib/pq"

	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

//
// Reloader implementation
//

// Reload is a function that reloads the keydb in-place, oldest items first.
// It MUST NOT be called within a goroutine, as it performs no clean shutdown.
func (st *storage) Reload() (int, error) {
	bookmark := time.Time{}
	newKeyDocs := make(map[string]*types.KeyDoc, keysInBunch)
	result := hkpstorage.InsertError{}
	total := 0

	for {
		t := time.Now()
		count, finished := st.getReloadBunch(&bookmark, newKeyDocs, &result)
		total += count
		if finished || len(newKeyDocs) > keysInBunch-100 {
			n, bulkOK := st.bulkReload(newKeyDocs, &result)
			if !bulkOK {
				log.Debugf("bulkReload not ok, result: %q", result)
				if count, max := len(result.Errors), maxInsertErrors; count > max {
					log.Errorf("too many reload errors (%d > %d), bailing...", count, max)
					return total, nil
				}
			}
			log.Infof("%d keys reloaded in %v; total scanned %d", n, time.Since(t), total)
			newKeyDocs = make(map[string]*types.KeyDoc, keysInBunch)
		}
		if finished {
			log.Infof("reload complete")
			return total, nil
		}
	}
}
