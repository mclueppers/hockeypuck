// Package management provides plugin lifecycle management functionality
// This package can be used by Hockeypuck and other servers for plugin management
package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/integration"
	pluginapi "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

// PluginState represents the state of a plugin
type PluginState int

const (
	PluginStateLoading PluginState = iota
	PluginStateActive
	PluginStateReloading
	PluginStateUnloading
	PluginStateFailed
	PluginStateDisabled
)

// PluginManager manages plugin lifecycle for HTTP servers
type PluginManager struct {
	pluginSystem   *integration.PluginSystem
	pluginStates   map[string]PluginState
	rollbackStates map[string]*PluginSnapshot
	activeRequests map[string]map[string]*ActiveRequest
	requestDrainer *RequestDrainer
	host           pluginapi.PluginHost
	config         *config.Settings
	logger         *log.Logger
	mu             sync.RWMutex
	startTime      time.Time
}

// PluginSnapshot represents a rollback state for a plugin
type PluginSnapshot struct {
	PluginName    string
	Configuration map[string]interface{}
	State         PluginState
	Timestamp     time.Time
	Version       int
}

// ActiveRequest represents an active HTTP request
type ActiveRequest struct {
	ID         string
	StartTime  time.Time
	Context    context.Context
	Cancel     context.CancelFunc
	PluginName string
}

// RequestDrainer manages graceful request draining during plugin transitions
type RequestDrainer struct {
	activeRequests map[string]*ActiveRequest
	drainTimeout   time.Duration
	pollInterval   time.Duration
	mutex          sync.RWMutex
}

// NewPluginManager creates a new plugin lifecycle manager
func NewPluginManager(pluginSystem *integration.PluginSystem, config *config.Settings, logger *log.Logger) (*PluginManager, error) {
	if pluginSystem == nil {
		return nil, fmt.Errorf("plugin system cannot be nil")
	}

	return &PluginManager{
		pluginSystem:   pluginSystem,
		config:         config,
		logger:         logger,
		pluginStates:   make(map[string]PluginState),
		rollbackStates: make(map[string]*PluginSnapshot),
		activeRequests: make(map[string]map[string]*ActiveRequest),
		requestDrainer: NewRequestDrainer(),
		startTime:      time.Now(),
	}, nil
}

// NewRequestDrainer creates a new request drainer
func NewRequestDrainer() *RequestDrainer {
	return &RequestDrainer{
		activeRequests: make(map[string]*ActiveRequest),
		drainTimeout:   60 * time.Second,
		pollInterval:   500 * time.Millisecond,
	}
}

// SetPluginSystem sets the plugin system instance
func (pm *PluginManager) SetPluginSystem(ps *integration.PluginSystem) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.pluginSystem = ps
}

// GetPluginStatus returns overall plugin system status
func (pm *PluginManager) GetPluginStatus() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stateInfo := make(map[string]string)
	for pluginName, state := range pm.pluginStates {
		stateInfo[pluginName] = pm.getStateString(state)
	}

	pluginCount := 0
	if pm.pluginSystem != nil {
		pluginCount = len(pm.pluginSystem.ListPlugins())
	}

	return map[string]interface{}{
		"plugin_system": map[string]interface{}{
			"enabled":         pm.config.Plugins.Enabled,
			"total_plugins":   pluginCount,
			"active_plugins":  pm.countActivePlugins(),
			"plugin_dir":      pm.config.Plugins.Directory,
			"active_requests": pm.getActiveRequestCount(),
			"plugin_states":   stateInfo,
		},
		"health_status": pm.getPluginHealthSummary(),
		"uptime":        time.Since(pm.startTime).String(),
		"timestamp":     time.Now().Unix(),
		"draining": map[string]interface{}{
			"timeout":       pm.requestDrainer.drainTimeout.String(),
			"poll_interval": pm.requestDrainer.pollInterval.String(),
		},
	}
}

// GetPluginsList returns detailed list of all plugins
func (pm *PluginManager) GetPluginsList() []map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	plugins := []map[string]interface{}{}
	if pm.pluginSystem != nil {
		for _, pluginName := range pm.pluginSystem.ListPlugins() {
			pluginInfo := map[string]interface{}{
				"name":   pluginName,
				"status": pm.getStateString(pm.pluginStates[pluginName]),
				"health": pm.getPluginHealth(pluginName),
			}
			plugins = append(plugins, pluginInfo)
		}
	}

	return plugins
}

// GetPluginsHealth returns health check for all plugins
func (pm *PluginManager) GetPluginsHealth() map[string]interface{} {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	health := map[string]interface{}{
		"overall_status": "healthy",
		"plugins":        map[string]interface{}{},
		"timestamp":      time.Now().Unix(),
	}

	overallHealthy := true
	pluginHealthMap := make(map[string]interface{})

	if pm.pluginSystem != nil {
		for _, pluginName := range pm.pluginSystem.ListPlugins() {
			pluginHealth := pm.getPluginHealth(pluginName)
			pluginHealthMap[pluginName] = pluginHealth

			if status, ok := pluginHealth["status"].(string); ok && status != "healthy" {
				overallHealthy = false
			}
		}
	}

	health["plugins"] = pluginHealthMap
	if !overallHealthy {
		health["overall_status"] = "degraded"
	}

	return health
}

// ReloadPlugin reloads a specific plugin with graceful draining
func (pm *PluginManager) ReloadPlugin(pluginName string) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.pluginSystem == nil {
		return fmt.Errorf("plugin system not initialized")
	}

	// Find the plugin
	var targetPlugin pluginapi.Plugin
	if ps, exists := pm.pluginSystem.GetPlugin(pluginName); exists {
		targetPlugin = ps
	} else {
		return fmt.Errorf("plugin %s not found", pluginName)
	}

	pm.logger.WithField("plugin", pluginName).Info("Attempting to reload plugin with graceful draining")

	// Create rollback state before making changes
	if err := pm.createRollbackSnapshot(pluginName); err != nil {
		pm.logger.WithFields(log.Fields{
			"plugin": pluginName,
			"error":  err,
		}).Warn("Failed to create rollback snapshot")
	}

	// Transition to reloading state and drain requests
	if err := pm.transitionToReloading(pluginName); err != nil {
		return fmt.Errorf("failed to transition to reloading: %w", err)
	}

	// Graceful shutdown with request draining
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := targetPlugin.Shutdown(shutdownCtx); err != nil {
		pm.logger.WithFields(log.Fields{
			"plugin": pluginName,
			"error":  err,
		}).Error("Failed to shutdown plugin for reload")
		// Attempt rollback
		pm.rollbackPlugin(pluginName)
		return fmt.Errorf("failed to shutdown plugin: %w", err)
	}

	// Re-initialize the plugin with current configuration
	var config map[string]interface{}
	if cfg := pm.config.GetPluginConfig(pluginName); cfg != nil {
		config = cfg
	} else {
		config = make(map[string]interface{})
	}

	if err := targetPlugin.Initialize(context.Background(), pm.host, config); err != nil {
		pm.logger.WithFields(log.Fields{
			"plugin": pluginName,
			"error":  err,
		}).Error("Failed to reinitialize plugin after reload")
		// Attempt rollback
		pm.rollbackPlugin(pluginName)
		return fmt.Errorf("failed to reinitialize plugin: %w", err)
	}

	// Transition back to active state
	pm.pluginStates[pluginName] = PluginStateActive

	pm.logger.WithField("plugin", pluginName).Info("Plugin reloaded successfully")
	return nil
}

// UpdatePluginConfig updates a plugin's configuration
func (pm *PluginManager) UpdatePluginConfig(pluginName string, newConfig map[string]interface{}) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Update configuration
	pm.config.Plugins.Config[pluginName] = newConfig

	// Find and reinitialize the plugin with new config
	if pm.pluginSystem != nil {
		if targetPlugin, exists := pm.pluginSystem.GetPlugin(pluginName); exists {
			// Shutdown and reinitialize with new config
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := targetPlugin.Shutdown(shutdownCtx); err != nil {
				pm.logger.WithFields(log.Fields{
					"plugin": pluginName,
					"error":  err,
				}).Error("Failed to shutdown plugin for config update")
			}

			if err := targetPlugin.Initialize(context.Background(), pm.host, newConfig); err != nil {
				pm.logger.WithFields(log.Fields{
					"plugin": pluginName,
					"error":  err,
				}).Error("Failed to reinitialize plugin with new config")
				return fmt.Errorf("failed to apply new configuration: %w", err)
			}

			pm.logger.WithField("plugin", pluginName).Info("Plugin configuration updated successfully")
			return nil
		}
	}

	return fmt.Errorf("plugin %s not found", pluginName)
}

// Helper methods

func (pm *PluginManager) countActivePlugins() int {
	if pm.pluginSystem == nil {
		return 0
	}
	return len(pm.pluginSystem.ListPlugins())
}

func (pm *PluginManager) getPluginHealthSummary() map[string]interface{} {
	healthy := 0
	total := pm.countActivePlugins()

	if pm.pluginSystem != nil {
		for _, pluginName := range pm.pluginSystem.ListPlugins() {
			health := pm.getPluginHealth(pluginName)
			if status, ok := health["status"].(string); ok && status == "healthy" {
				healthy++
			}
		}
	}

	return map[string]interface{}{
		"healthy_count":   healthy,
		"unhealthy_count": total - healthy,
		"total_count":     total,
		"overall_status": func() string {
			if healthy == total {
				return "healthy"
			} else if healthy > 0 {
				return "degraded"
			}
			return "unhealthy"
		}(),
	}
}

func (pm *PluginManager) getPluginHealth(pluginName string) map[string]interface{} {
	state, stateExists := pm.pluginStates[pluginName]

	status := "healthy"
	if !stateExists || state == PluginStateFailed {
		status = "unhealthy"
	} else if state == PluginStateReloading || state == PluginStateLoading {
		status = "transitioning"
	}

	health := map[string]interface{}{
		"status":     status,
		"state":      pm.getStateString(state),
		"last_check": time.Now().Unix(),
		"checks":     map[string]interface{}{},
	}

	// Add active request count
	if activeReqs, exists := pm.activeRequests[pluginName]; exists {
		health["checks"].(map[string]interface{})["active_requests"] = len(activeReqs)
	} else {
		health["checks"].(map[string]interface{})["active_requests"] = 0
	}

	return health
}

func (pm *PluginManager) getStateString(state PluginState) string {
	switch state {
	case PluginStateLoading:
		return "loading"
	case PluginStateActive:
		return "active"
	case PluginStateReloading:
		return "reloading"
	case PluginStateUnloading:
		return "unloading"
	case PluginStateFailed:
		return "failed"
	case PluginStateDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

func (pm *PluginManager) transitionToReloading(pluginName string) error {
	pm.pluginStates[pluginName] = PluginStateReloading
	return pm.drainPluginRequests(pluginName)
}

func (pm *PluginManager) drainPluginRequests(pluginName string) error {
	pm.logger.WithField("plugin", pluginName).Info("Draining requests for plugin")

	// Wait for active requests to complete
	deadline := time.Now().Add(pm.requestDrainer.drainTimeout)

	for time.Now().Before(deadline) {
		activeCount := pm.getActiveRequestCount()
		if activeCount == 0 {
			break
		}

		pm.logger.WithFields(log.Fields{
			"count":  activeCount,
			"plugin": pluginName,
		}).Debug("Waiting for active requests")
		time.Sleep(pm.requestDrainer.pollInterval)
	}

	// Force-cancel remaining requests if needed
	remaining := pm.getActiveRequestCount()
	if remaining > 0 {
		pm.logger.WithFields(log.Fields{
			"count":  remaining,
			"plugin": pluginName,
		}).Warn("Force-canceling remaining requests")
		pm.requestDrainer.mutex.Lock()
		for _, req := range pm.requestDrainer.activeRequests {
			req.Cancel()
		}
		pm.requestDrainer.mutex.Unlock()
	}

	return nil
}

func (pm *PluginManager) getActiveRequestCount() int {
	pm.requestDrainer.mutex.RLock()
	defer pm.requestDrainer.mutex.RUnlock()
	return len(pm.requestDrainer.activeRequests)
}

func (pm *PluginManager) createRollbackSnapshot(pluginName string) error {
	currentState, exists := pm.pluginStates[pluginName]
	if !exists {
		return fmt.Errorf("plugin %s not found in state map", pluginName)
	}

	snapshot := &PluginSnapshot{
		PluginName:    pluginName,
		State:         currentState,
		Timestamp:     time.Now(),
		Version:       1,
		Configuration: make(map[string]interface{}),
	}

	// Copy current configuration
	if cfg := pm.config.GetPluginConfig(pluginName); cfg != nil {
		for k, v := range cfg {
			snapshot.Configuration[k] = v
		}
	}

	pm.rollbackStates[pluginName] = snapshot
	pm.logger.WithField("plugin", pluginName).Debug("Created rollback snapshot")
	return nil
}

func (pm *PluginManager) rollbackPlugin(pluginName string) error {
	snapshot, exists := pm.rollbackStates[pluginName]
	if !exists {
		pm.logger.WithField("plugin", pluginName).Warn("No rollback snapshot available")
		return fmt.Errorf("no rollback snapshot for plugin %s", pluginName)
	}

	pm.logger.WithField("plugin", pluginName).Info("Rolling back plugin to previous state")

	// Restore previous state
	pm.pluginStates[pluginName] = snapshot.State

	// Clean up snapshot
	delete(pm.rollbackStates, pluginName)

	return nil
}

// HTTP Handlers for plugin management endpoints (httprouter compatible)

// HandleStatus returns plugin system status
func (pm *PluginManager) HandleStatus(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	status := pm.GetPluginStatus()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(status); err != nil {
		http.Error(w, "Failed to encode plugin status", http.StatusInternalServerError)
		return
	}
}

// HandleList returns list of all plugins
func (pm *PluginManager) HandleList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	plugins := pm.GetPluginsList()

	response := map[string]interface{}{
		"plugins":     plugins,
		"total_count": len(plugins),
		"timestamp":   time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, "Failed to encode plugins list", http.StatusInternalServerError)
		return
	}
}

// HandleHealth returns health check for all plugins
func (pm *PluginManager) HandleHealth(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	health := pm.GetPluginsHealth()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(health); err != nil {
		http.Error(w, "Failed to encode health status", http.StatusInternalServerError)
		return
	}
}

// HandleReload handles plugin reload requests
func (pm *PluginManager) HandleReload(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	result := map[string]interface{}{
		"plugin":    pluginName,
		"timestamp": time.Now().Unix(),
	}

	if err := pm.ReloadPlugin(pluginName); err != nil {
		result["status"] = "error"
		result["message"] = err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(result)
		return
	}

	result["status"] = "success"
	result["message"] = "Plugin reloaded successfully with graceful draining"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// HandleConfig handles plugin configuration retrieval
func (pm *PluginManager) HandleConfig(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	// Get current plugin configuration - we'll need to implement this method
	var config map[string]interface{}
	if pm.pluginSystem != nil {
		// For now, return empty config - in real implementation, get from plugin system
		config = make(map[string]interface{})
	}

	response := map[string]interface{}{
		"plugin":    pluginName,
		"config":    config,
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// HandleConfigUpdate handles plugin configuration updates
func (pm *PluginManager) HandleConfigUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	pluginName := r.URL.Query().Get("plugin")
	if pluginName == "" {
		http.Error(w, "Plugin name is required", http.StatusBadRequest)
		return
	}

	// Update plugin configuration
	var newConfig map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
		http.Error(w, "Invalid JSON configuration", http.StatusBadRequest)
		return
	}

	result := map[string]interface{}{
		"plugin":    pluginName,
		"timestamp": time.Now().Unix(),
	}

	if err := pm.UpdatePluginConfig(pluginName, newConfig); err != nil {
		result["status"] = "error"
		result["message"] = err.Error()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(result)
		return
	}

	result["status"] = "success"
	result["message"] = "Configuration updated and plugin reloaded"

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
