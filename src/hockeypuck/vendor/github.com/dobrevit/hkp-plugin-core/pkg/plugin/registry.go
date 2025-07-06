// Package plugin registry implementation
package plugin

import (
	"context"
	"fmt"
	"sync"
)

// PluginRegistry manages plugins for a host system
type PluginRegistry struct {
	plugins   map[string]Plugin
	order     []string
	mu        sync.RWMutex
	host      PluginHost
	lifecycle *PluginLifecycle
}

// NewPluginRegistry creates a new plugin registry
func NewPluginRegistry(host PluginHost) *PluginRegistry {
	registry := &PluginRegistry{
		plugins: make(map[string]Plugin),
		host:    host,
	}
	registry.lifecycle = NewPluginLifecycle(registry)
	return registry
}

// Register registers a plugin
func (r *PluginRegistry) Register(plugin Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := plugin.Name()
	if name == "" {
		return fmt.Errorf("plugin name cannot be empty")
	}

	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %s already registered", name)
	}

	r.plugins[name] = plugin
	r.order = append(r.order, name)

	return nil
}

// Get retrieves a plugin by name
func (r *PluginRegistry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plugin, exists := r.plugins[name]
	return plugin, exists
}

// List returns all registered plugins
func (r *PluginRegistry) List() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	plugins := make([]Plugin, 0, len(r.plugins))
	for _, name := range r.order {
		if plugin, exists := r.plugins[name]; exists {
			plugins = append(plugins, plugin)
		}
	}
	return plugins
}

// Initialize initializes all plugins
func (r *PluginRegistry) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	return r.lifecycle.Initialize(ctx, configs)
}

// Shutdown shuts down all plugins
func (r *PluginRegistry) Shutdown(ctx context.Context) error {
	return r.lifecycle.Shutdown(ctx)
}