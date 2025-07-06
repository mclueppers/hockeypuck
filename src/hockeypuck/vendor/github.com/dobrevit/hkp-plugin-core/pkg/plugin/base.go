// Package plugin base implementation
package plugin

import (
	"context"
	"sync"
)

// BasePlugin provides a base implementation for plugins
type BasePlugin struct {
	name        string
	version     string
	description string
	initialized bool
	mu          sync.RWMutex
}

// Name returns the plugin name
func (p *BasePlugin) Name() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.name
}

// Version returns the plugin version
func (p *BasePlugin) Version() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version
}

// Description returns the plugin description
func (p *BasePlugin) Description() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.description
}

// SetInfo sets the plugin information
func (p *BasePlugin) SetInfo(name, version, description string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.name = name
	p.version = version
	p.description = description
}

// IsInitialized returns whether the plugin is initialized
func (p *BasePlugin) IsInitialized() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.initialized
}

// SetInitialized sets the initialization status
func (p *BasePlugin) SetInitialized(initialized bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.initialized = initialized
}

// Dependencies returns an empty dependency list by default
func (p *BasePlugin) Dependencies() []PluginDependency {
	return []PluginDependency{}
}

// Default implementation of Shutdown
func (p *BasePlugin) Shutdown(ctx context.Context) error {
	p.SetInitialized(false)
	return nil
}