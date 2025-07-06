// Package plugin types and configuration structures
package plugin

import (
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
)

// Legacy Settings type - deprecated, use config.Settings instead
// Kept for backward compatibility
type Settings = config.Settings

// PluginDependency represents a plugin dependency
type PluginDependency struct {
	Name     string         `json:"name"`
	Version  string         `json:"version"`
	Type     DependencyType `json:"type"`
	Optional bool           `json:"optional"`
}

// DependencyType represents the type of dependency
type DependencyType string

const (
	DependencyRequired DependencyType = "required"
	DependencyOptional DependencyType = "optional"
	DependencyConflict DependencyType = "conflict"
)

// Legacy types - use events package instead
type PluginEvent = events.PluginEvent
type PluginEventHandler = events.PluginEventHandler
type EndpointProtectionRequest = events.EndpointProtectionRequest

// Legacy constants - use events package instead
const (
	EventEndpointProtectionRequest = events.EventEndpointProtectionRequest
	EventEndpointProtectionUpdate  = events.EventEndpointProtectionUpdate
	EventEndpointAccessDenied      = events.EventEndpointAccessDenied
	EventEndpointAccessGranted     = events.EventEndpointAccessGranted
	EventSecurityThreatDetected    = events.EventSecurityThreatDetected
	EventSecurityAnomalyDetected   = events.EventSecurityAnomalyDetected
)

// Configuration Structures

// MiddlewareConfig provides configuration for middleware creation
type MiddlewareConfig struct {
	Path     string                 `json:"path"`
	Priority int                    `json:"priority"`
	Config   map[string]interface{} `json:"config"`
}

// StorageConfig provides configuration for storage backend creation
type StorageConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// AuthConfig provides configuration for authentication providers
type AuthConfig struct {
	Type     string                 `json:"type"`
	Provider string                 `json:"provider"`
	Config   map[string]interface{} `json:"config"`
}

// AuditConfig provides configuration for audit logging
type AuditConfig struct {
	Level  string                 `json:"level"`
	Output string                 `json:"output"`
	Config map[string]interface{} `json:"config"`
}

// AuditEvent represents an audit event
type AuditEvent struct {
	Timestamp time.Time              `json:"timestamp"`
	User      string                 `json:"user"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Result    string                 `json:"result"`
	Details   map[string]interface{} `json:"details"`
}

// EncryptionConfig provides configuration for encryption providers
type EncryptionConfig struct {
	Algorithm string                 `json:"algorithm"`
	KeySize   int                    `json:"key_size"`
	Config    map[string]interface{} `json:"config"`
}

// MetricsConfig provides configuration for metrics collectors
type MetricsConfig struct {
	Type     string                 `json:"type"`
	Endpoint string                 `json:"endpoint"`
	Config   map[string]interface{} `json:"config"`
}

// AlertConfig provides configuration for alert providers
type AlertConfig struct {
	Provider string                 `json:"provider"`
	Webhook  string                 `json:"webhook"`
	Config   map[string]interface{} `json:"config"`
}

// Alert represents an alert
type Alert struct {
	Level       string                 `json:"level"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Timestamp   time.Time              `json:"timestamp"`
	Tags        map[string]string      `json:"tags"`
	Data        map[string]interface{} `json:"data"`
}

// DashboardConfig provides configuration for dashboard providers
type DashboardConfig struct {
	Type     string                 `json:"type"`
	Endpoint string                 `json:"endpoint"`
	Config   map[string]interface{} `json:"config"`
}

// Logger interface for plugin logging
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
	Debug(msg string, args ...interface{})
}

// Server represents the Hockeypuck server (placeholder interface)
type Server struct {
	// Server implementation details would go here
}