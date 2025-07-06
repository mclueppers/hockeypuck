package server

import (
	"fmt"
	"time"

	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	phkpstorage "github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
)

// StorageAdapter bridges Hockeypuck's storage with the plugin system's storage interface
type StorageAdapter struct {
	storage storage.Storage
}

// NewStorageAdapter creates a new storage adapter
func NewStorageAdapter(st storage.Storage) *StorageAdapter {
	return &StorageAdapter{storage: st}
}

// Close implements io.Closer
func (sa *StorageAdapter) Close() error {
	return sa.storage.Close()
}

// MatchMD5 implements Queryer
func (sa *StorageAdapter) MatchMD5(md5s []string) ([]string, error) {
	return sa.storage.MatchMD5(md5s)
}

// Resolve implements Queryer
func (sa *StorageAdapter) Resolve(ids []string) ([]string, error) {
	return sa.storage.Resolve(ids)
}

// MatchKeyword implements Queryer
func (sa *StorageAdapter) MatchKeyword(keywords []string) ([]string, error) {
	return sa.storage.MatchKeyword(keywords)
}

// ModifiedSince implements Queryer
func (sa *StorageAdapter) ModifiedSince(since time.Time) ([]string, error) {
	return sa.storage.ModifiedSince(since)
}

// FetchKeys implements Queryer - converts between key types
func (sa *StorageAdapter) FetchKeys(fps []string, filters ...string) ([]*phkpstorage.PrimaryKey, error) {
	hkpKeys, err := sa.storage.FetchKeys(fps, filters...)
	if err != nil {
		return nil, err
	}

	// Convert Hockeypuck keys to plugin system keys
	var pluginKeys []*phkpstorage.PrimaryKey
	for _, hkpKey := range hkpKeys {
		pluginKey := convertHKPKeyToPlugin(hkpKey)
		pluginKeys = append(pluginKeys, pluginKey)
	}

	return pluginKeys, nil
}

// FetchRecords implements Queryer - converts between record types
func (sa *StorageAdapter) FetchRecords(fps []string, filters ...string) ([]*phkpstorage.Record, error) {
	hkpRecords, err := sa.storage.FetchRecords(fps, filters...)
	if err != nil {
		return nil, err
	}

	// Convert Hockeypuck records to plugin system records
	var pluginRecords []*phkpstorage.Record
	for _, hkpRecord := range hkpRecords {
		pluginRecord := &phkpstorage.Record{
			PrimaryKey: convertHKPKeyToPlugin(hkpRecord.PrimaryKey),
			CTime:      hkpRecord.CTime,
			MTime:      hkpRecord.MTime,
		}
		pluginRecords = append(pluginRecords, pluginRecord)
	}

	return pluginRecords, nil
}

// Insert implements Inserter - converts from plugin keys to HKP keys
func (sa *StorageAdapter) Insert(keys []*phkpstorage.PrimaryKey) (int, int, error) {
	// Convert plugin keys to Hockeypuck keys
	var hkpKeys []*openpgp.PrimaryKey
	for _, pluginKey := range keys {
		hkpKey := convertPluginKeyToHKP(pluginKey)
		hkpKeys = append(hkpKeys, hkpKey)
	}

	return sa.storage.Insert(hkpKeys)
}

// Update implements Updater
func (sa *StorageAdapter) Update(pubkey *phkpstorage.PrimaryKey, priorID string, priorMD5 string) error {
	hkpKey := convertPluginKeyToHKP(pubkey)
	return sa.storage.Update(hkpKey, priorID, priorMD5)
}

// Replace implements Updater
func (sa *StorageAdapter) Replace(pubkey *phkpstorage.PrimaryKey) (string, error) {
	hkpKey := convertPluginKeyToHKP(pubkey)
	return sa.storage.Replace(hkpKey)
}

// Delete implements Deleter
func (sa *StorageAdapter) Delete(fp string) (string, error) {
	return sa.storage.Delete(fp)
}

// Subscribe implements Notifier
func (sa *StorageAdapter) Subscribe(callback func(phkpstorage.KeyChange) error) {
	// Convert the callback to work with Hockeypuck's KeyChange type
	hkpCallback := func(change storage.KeyChange) error {
		// Convert HKP key change to plugin key change
		pluginChange := sa.ConvertHKPChangeToPlugin(change)
		return callback(pluginChange)
	}
	sa.storage.Subscribe(hkpCallback)
}

// Notify implements Notifier
func (sa *StorageAdapter) Notify(change phkpstorage.KeyChange) error {
	// Convert plugin key change to HKP key change
	hkpChange := convertPluginChangeToHKP(change)
	return sa.storage.Notify(hkpChange)
}

// RenotifyAll implements Notifier
func (sa *StorageAdapter) RenotifyAll() error {
	return sa.storage.RenotifyAll()
}

// StartReindex implements Reindexer
func (sa *StorageAdapter) StartReindex() {
	sa.storage.StartReindex()
}

// Conversion helpers

func convertHKPKeyToPlugin(hkpKey *openpgp.PrimaryKey) *phkpstorage.PrimaryKey {
	if hkpKey == nil {
		return nil
	}

	return &phkpstorage.PrimaryKey{
		PublicKey: phkpstorage.PublicKey{
			Packet: phkpstorage.Packet{
				UUID: hkpKey.UUID,
			},
			RFingerprint: hkpKey.RFingerprint,
			RKeyID:       hkpKey.RKeyID,
		},
		MD5: hkpKey.MD5,
	}
}

func convertPluginKeyToHKP(pluginKey *phkpstorage.PrimaryKey) *openpgp.PrimaryKey {
	if pluginKey == nil {
		return nil
	}

	// Create a minimal HKP key with required fields
	// In a real implementation, this would need to preserve more data
	return &openpgp.PrimaryKey{
		PublicKey: openpgp.PublicKey{
			Packet: openpgp.Packet{
				UUID: pluginKey.UUID,
			},
			RFingerprint: pluginKey.RFingerprint,
			RKeyID:       pluginKey.RKeyID,
		},
		MD5: pluginKey.MD5,
	}
}

// ConvertHKPChangeToPlugin converts Hockeypuck KeyChange to plugin KeyChange
func (sa *StorageAdapter) ConvertHKPChangeToPlugin(hkpChange storage.KeyChange) phkpstorage.KeyChange {
	// Map HKP key changes to plugin key changes
	switch c := hkpChange.(type) {
	case storage.KeyAdded:
		return phkpstorage.KeyAdded{
			ID:     c.ID,
			Digest: c.Digest,
		}
	case storage.KeyRemoved:
		return phkpstorage.KeyRemoved{
			ID:     c.ID,
			Digest: c.Digest,
		}
	case storage.KeyReplaced:
		return phkpstorage.KeyReplaced{
			OldID:     c.OldID,
			OldDigest: c.OldDigest,
			NewID:     c.NewID,
			NewDigest: c.NewDigest,
		}
	case storage.KeyNotChanged:
		return phkpstorage.KeyNotChanged{
			ID:     c.ID,
			Digest: c.Digest,
		}
	default:
		// Return a generic key change
		return phkpstorage.KeyNotChanged{
			ID:     fmt.Sprintf("%v", hkpChange),
			Digest: "",
		}
	}
}

func convertPluginChangeToHKP(pluginChange phkpstorage.KeyChange) storage.KeyChange {
	// Map plugin key changes to HKP key changes
	switch c := pluginChange.(type) {
	case phkpstorage.KeyAdded:
		return storage.KeyAdded{
			ID:     c.ID,
			Digest: c.Digest,
		}
	case phkpstorage.KeyRemoved:
		return storage.KeyRemoved{
			ID:     c.ID,
			Digest: c.Digest,
		}
	case phkpstorage.KeyReplaced:
		return storage.KeyReplaced{
			OldID:     c.OldID,
			OldDigest: c.OldDigest,
			NewID:     c.NewID,
			NewDigest: c.NewDigest,
		}
	case phkpstorage.KeyNotChanged:
		return storage.KeyNotChanged{
			ID:     c.ID,
			Digest: c.Digest,
		}
	default:
		// Return a generic key change
		return storage.KeyNotChanged{
			ID:     fmt.Sprintf("%v", pluginChange),
			Digest: "",
		}
	}
}
