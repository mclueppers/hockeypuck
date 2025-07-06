// Package hkpstorage provides Hockeypuck-compatible storage interfaces
// This is a clean-room implementation based on interface patterns (no AGPL code copied)
package hkpstorage

import (
	"io"
	"time"
)

// Storage defines the complete storage interface compatible with Hockeypuck
// This mirrors Hockeypuck's storage interface structure without copying AGPL code
type Storage interface {
	io.Closer
	Queryer
	Updater
	Deleter
	Notifier
	Reindexer
	PKSStorage
}

// Queryer defines the storage API for search and retrieval
type Queryer interface {
	// MatchMD5 returns matching fingerprint IDs for public key MD5 hashes
	MatchMD5([]string) ([]string, error)

	// Resolve returns matching fingerprint IDs for key IDs (short/long/full)
	Resolve([]string) ([]string, error)

	// MatchKeyword returns matching fingerprint IDs for keyword search
	MatchKeyword([]string) ([]string, error)

	// ModifiedSince returns fingerprint IDs modified since given time
	ModifiedSince(time.Time) ([]string, error)

	// FetchKeys returns public key material for given fingerprints
	FetchKeys([]string, ...string) ([]*PrimaryKey, error)

	// FetchRecords returns database records for given fingerprints
	FetchRecords([]string, ...string) ([]*Record, error)
}

// Updater defines the storage API for writing key material
type Updater interface {
	Inserter

	// Update updates stored key if current contents match given digest
	Update(pubkey *PrimaryKey, priorID string, priorMD5 string) error

	// Replace unconditionally replaces existing key with given contents
	Replace(pubkey *PrimaryKey) (string, error)
}

// Inserter defines the storage API for inserting key material
type Inserter interface {
	// Insert inserts new public keys or updates existing ones
	// Returns (updated, inserted, error)
	Insert([]*PrimaryKey) (int, int, error)
}

// Deleter defines the storage API for deleting keys
type Deleter interface {
	// Delete unconditionally deletes key with given fingerprint
	Delete(fp string) (string, error)
}

// Notifier defines the storage notification interface
type Notifier interface {
	// Subscribe registers a key change callback function
	Subscribe(func(KeyChange) error)

	// Notify invokes all registered callbacks with key change notification
	Notify(change KeyChange) error

	// RenotifyAll invokes all callbacks with KeyAdded for each key
	RenotifyAll() error
}

// Reindexer defines the reindexing interface
type Reindexer interface {
	StartReindex()
}

// PKSStorage defines additional PKS-specific storage methods
type PKSStorage interface {
	// Add methods specific to PKS operations as needed
}

// Record represents a primary key with database metadata
type Record struct {
	*PrimaryKey
	CTime time.Time
	MTime time.Time
}

// PrimaryKey represents an OpenPGP primary key
// This is our own implementation, compatible with Hockeypuck's structure
type PrimaryKey struct {
	PublicKey

	// Primary key specific fields
	MD5    string // MD5 hash of the key material
	Length int    // Total length of key material including packets

	// Associated data
	SubKeys []*SubKey
	UserIDs []*UserID
}

// PublicKey represents the base public key information
type PublicKey struct {
	Packet

	// Key identifiers (reversed for efficient prefix search)
	RFingerprint string // Reversed fingerprint (40 hex chars)
	RKeyID       string // Reversed key ID (16 hex chars)
	RShortID     string // Reversed short ID (8 hex chars)

	// Key metadata
	Version    uint8     // OpenPGP version (3 or 4)
	Creation   time.Time // Key creation timestamp
	Expiration time.Time // Key expiration timestamp (zero if none)
	Algorithm  int       // Public key algorithm
	BitLen     int       // Bit length of the key
	Curve      string    // ECC curve name (empty for non-ECC)

	// Associated signatures
	Signatures []*Signature
}

// Packet represents raw OpenPGP packet data
type Packet struct {
	UUID   string // Unique identifier (usually RFingerprint)
	Tag    uint8  // OpenPGP packet tag type
	Count  int    // Number of times this packet occurs
	Packet []byte // Raw packet bytes
}

// SubKey represents a subkey
type SubKey struct {
	PublicKey
}

// UserID represents a user identity
type UserID struct {
	Packet

	Keywords []string // Indexed keywords for search

	// Associated signatures
	Signatures []*Signature
}

// Signature represents an OpenPGP signature
type Signature struct {
	Packet

	SigType          uint8     // Signature type
	RIssuerKeyID     string    // Reversed issuer key ID
	Creation         time.Time // Signature creation time
	Expiration       time.Time // Signature expiration time
	RevocationReason *uint8    // Revocation reason code if revoked
	Primary          bool      // Whether this is a primary user ID signature
}

// KeyChange interface for storage notifications
type KeyChange interface {
	InsertDigests() []string
	RemoveDigests() []string
	String() string
}

// Specific key change implementations
type KeyAdded struct {
	ID     string
	Digest string
}

func (ka KeyAdded) InsertDigests() []string { return []string{ka.Digest} }
func (ka KeyAdded) RemoveDigests() []string { return nil }
func (ka KeyAdded) String() string          { return "key " + ka.ID + " added" }

type KeyRemoved struct {
	ID     string
	Digest string
}

func (kr KeyRemoved) InsertDigests() []string { return nil }
func (kr KeyRemoved) RemoveDigests() []string { return []string{kr.Digest} }
func (kr KeyRemoved) String() string          { return "key " + kr.ID + " removed" }

type KeyReplaced struct {
	OldID     string
	OldDigest string
	NewID     string
	NewDigest string
}

func (kr KeyReplaced) InsertDigests() []string { return []string{kr.NewDigest} }
func (kr KeyReplaced) RemoveDigests() []string { return []string{kr.OldDigest} }
func (kr KeyReplaced) String() string {
	return "key " + kr.OldID + " replaced by " + kr.NewID
}

type KeyNotChanged struct {
	ID     string
	Digest string
}

func (knc KeyNotChanged) InsertDigests() []string { return nil }
func (knc KeyNotChanged) RemoveDigests() []string { return nil }
func (knc KeyNotChanged) String() string          { return "key " + knc.ID + " not changed" }
