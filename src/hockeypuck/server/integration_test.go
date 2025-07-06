/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025  Casey Marshall and Hockeypuck Contributors

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

package server

import (
	"testing"
	"time"

	pksstorage "hockeypuck/hkp/pks/storage"
	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"

	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	log "github.com/sirupsen/logrus"
)

// MockStorage implements a minimal storage interface for testing
type MockStorage struct{}

func (ms *MockStorage) Close() error                                                 { return nil }
func (ms *MockStorage) MatchMD5([]string) ([]string, error)                          { return []string{}, nil }
func (ms *MockStorage) Resolve([]string) ([]string, error)                           { return []string{}, nil }
func (ms *MockStorage) MatchKeyword([]string) ([]string, error)                      { return []string{}, nil }
func (ms *MockStorage) ModifiedSince(time.Time) ([]string, error)                    { return []string{}, nil }
func (ms *MockStorage) FetchKeys([]string, ...string) ([]*openpgp.PrimaryKey, error) { return nil, nil }
func (ms *MockStorage) FetchRecords([]string, ...string) ([]*storage.Record, error)  { return nil, nil }
func (ms *MockStorage) Insert([]*openpgp.PrimaryKey) (int, int, error)               { return 0, 0, nil }
func (ms *MockStorage) Update(*openpgp.PrimaryKey, string, string) error             { return nil }
func (ms *MockStorage) Replace(*openpgp.PrimaryKey) (string, error)                  { return "", nil }
func (ms *MockStorage) Delete(string) (string, error)                                { return "", nil }
func (ms *MockStorage) Subscribe(func(storage.KeyChange) error)                      {}
func (ms *MockStorage) Notify(storage.KeyChange) error                               { return nil }
func (ms *MockStorage) RenotifyAll() error                                           { return nil }
func (ms *MockStorage) StartReindex()                                                {}

// PKS methods - these are minimal implementations for testing
func (ms *MockStorage) PKSInit(string, time.Time) error           { return nil }
func (ms *MockStorage) PKSAll() ([]*pksstorage.Status, error)     { return nil, nil }
func (ms *MockStorage) PKSUpdate(*pksstorage.Status) error        { return nil }
func (ms *MockStorage) PKSRemove(string) error                    { return nil }
func (ms *MockStorage) PKSGet(string) (*pksstorage.Status, error) { return nil, nil }

// TestPluginHostIntegration tests the basic plugin host integration
func TestPluginHostIntegration(t *testing.T) {
	// Create a minimal server setup
	settings := DefaultSettings()
	server := &Server{
		settings: &settings,
		st:       &MockStorage{},
	}

	// Create plugin host
	pluginHost := NewServerPluginHost(server)

	// Test storage adapter
	storage := pluginHost.Storage()
	if storage == nil {
		t.Error("Plugin host should return a storage adapter")
	}

	// Test configuration
	config := pluginHost.Config()
	if config == nil {
		t.Error("Plugin host should return configuration")
	}

	if !config.Plugins.Enabled {
		t.Error("Plugins should be enabled by default")
	}

	// Test logger
	logger := pluginHost.Logger()
	if logger == nil {
		t.Error("Plugin host should return a logger")
	}

	// Test metrics
	metrics := pluginHost.Metrics()
	if metrics == nil {
		t.Error("Plugin host should return metrics")
	}
}

// TestEventBusIntegration tests the event bus integration
func TestEventBusIntegration(t *testing.T) {
	// Create event bus
	eventBus := events.NewEventBus(log.StandardLogger())

	// Test event subscription
	var receivedEvent events.PluginEvent
	handler := func(event events.PluginEvent) error {
		receivedEvent = event
		return nil
	}

	err := eventBus.SubscribeEvent("test.event", handler)
	if err != nil {
		t.Fatalf("Failed to subscribe to event: %v", err)
	}

	// Test event publishing
	testEvent := events.PluginEvent{
		Type:      "test.event",
		Source:    "test",
		Timestamp: time.Now(),
		Data:      map[string]interface{}{"test": "data"},
	}

	err = eventBus.PublishEvent(testEvent)
	if err != nil {
		t.Fatalf("Failed to publish event: %v", err)
	}

	// Verify event was received
	if receivedEvent.Type != "test.event" {
		t.Errorf("Expected event type 'test.event', got '%s'", receivedEvent.Type)
	}

	if receivedEvent.Source != "test" {
		t.Errorf("Expected event source 'test', got '%s'", receivedEvent.Source)
	}
}

// TestStorageAdapter tests the storage adapter functionality
func TestStorageAdapter(t *testing.T) {
	mockStorage := &MockStorage{}
	adapter := NewStorageAdapter(mockStorage)

	// Test basic methods exist and don't panic
	err := adapter.Close()
	if err != nil {
		t.Errorf("Close should not return error: %v", err)
	}

	// Test key change conversion
	hkpChange := storage.KeyAdded{
		ID:     "test-key",
		Digest: "test-digest",
	}

	pluginChange := adapter.ConvertHKPChangeToPlugin(hkpChange)

	if pluginChange == nil {
		t.Error("Should convert HKP change to plugin change")
	}

	// Verify the conversion
	if added, ok := pluginChange.(hkpstorage.KeyAdded); ok {
		if added.ID != "test-key" {
			t.Errorf("Expected ID 'test-key', got '%s'", added.ID)
		}
		if added.Digest != "test-digest" {
			t.Errorf("Expected digest 'test-digest', got '%s'", added.Digest)
		}
	} else {
		t.Error("Expected KeyAdded type")
	}
}

// TestPluginIntegrationWorkflow tests the complete integration workflow
func TestPluginIntegrationWorkflow(t *testing.T) {
	// Create a minimal server
	settings := DefaultSettings()
	server := &Server{
		settings: &settings,
		st:       &MockStorage{},
	}

	// Create plugin host
	pluginHost := NewServerPluginHost(server)

	// Create and set event bus
	eventBus := events.NewEventBus(log.StandardLogger())
	pluginHost.SetEventBus(eventBus)

	// Test that we can subscribe to key changes
	var receivedChange hkpstorage.KeyChange
	err := eventBus.SubscribeKeyChanges(func(change hkpstorage.KeyChange) error {
		receivedChange = change
		return nil
	})

	if err != nil {
		t.Fatalf("Failed to subscribe to key changes: %v", err)
	}

	// Simulate a key change notification
	testChange := hkpstorage.KeyAdded{
		ID:     "test-key-workflow",
		Digest: "test-digest-workflow",
	}

	err = eventBus.NotifyKeyChange(testChange)
	if err != nil {
		t.Fatalf("Failed to notify key change: %v", err)
	}

	// Verify the key change was received
	if receivedChange == nil {
		t.Error("Should have received key change notification")
	}

	if added, ok := receivedChange.(hkpstorage.KeyAdded); ok {
		if added.ID != "test-key-workflow" {
			t.Errorf("Expected ID 'test-key-workflow', got '%s'", added.ID)
		}
	} else {
		t.Error("Expected KeyAdded type in workflow")
	}
}
