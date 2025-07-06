// Package plugin manager implementation
package plugin

import (
	"context"
	"fmt"
	"net/http"
	"sync"
)

// PluginManager manages the entire plugin system
type PluginManager struct {
	registry *PluginRegistry
	host     PluginHost
	logger   Logger
	mu       sync.RWMutex
}

// NewPluginManager creates a new plugin manager
func NewPluginManager(host PluginHost, logger Logger) *PluginManager {
	registry := NewPluginRegistry(host)
	return &PluginManager{
		registry: registry,
		host:     host,
		logger:   logger,
	}
}

// Register registers a plugin with the manager
func (pm *PluginManager) Register(plugin Plugin) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return pm.registry.Register(plugin)
}

// Initialize initializes all registered plugins
func (pm *PluginManager) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Initialize(ctx, configs)
}

// Shutdown shuts down all plugins
func (pm *PluginManager) Shutdown(ctx context.Context) error {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Shutdown(ctx)
}

// GetPlugin gets a plugin by name
func (pm *PluginManager) GetPlugin(name string) (Plugin, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.Get(name)
}

// ListPlugins lists all registered plugins
func (pm *PluginManager) ListPlugins() []Plugin {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.registry.List()
}

// LoadPlugin loads and initializes a plugin
func (pm *PluginManager) LoadPlugin(ctx context.Context, plugin Plugin, config map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Register the plugin
	if err := pm.registry.Register(plugin); err != nil {
		return err
	}

	// Initialize the plugin
	return plugin.Initialize(ctx, pm.host, config)
}

// GetRoutes returns HTTP routes from all plugins
func (pm *PluginManager) GetRoutes() map[string]http.HandlerFunc {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	routes := make(map[string]http.HandlerFunc)
	// This is a simplified implementation
	// In practice, you'd collect routes from plugins that implement HTTP interfaces
	return routes
}

// Global plugin registry
var globalRegistry *PluginRegistry

// Register registers a plugin globally
func Register(plugin Plugin) {
	if globalRegistry == nil {
		// Initialize with a nil host - will be set when server starts
		globalRegistry = NewPluginRegistry(nil)
	}
	if err := globalRegistry.Register(plugin); err != nil {
		panic(fmt.Sprintf("Failed to register plugin %s: %v", plugin.Name(), err))
	}
}

// GetRegistry returns the global plugin registry
func GetRegistry() *PluginRegistry {
	return globalRegistry
}

// SetHost sets the plugin host for the global registry
func SetHost(host PluginHost) {
	if globalRegistry != nil {
		globalRegistry.host = host
	}
}