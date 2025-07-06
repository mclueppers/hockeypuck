package plugin

import (
	"context"
	"net/http"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"
)

// Plugin represents a loadable module that extends Hockeypuck functionality
type Plugin interface {
	// Initialize the plugin with server context and configuration
	Initialize(ctx context.Context, server PluginHost, config map[string]interface{}) error

	// Name returns the unique plugin identifier
	Name() string

	// Version returns the plugin version
	Version() string

	// Description returns human-readable plugin description
	Description() string

	// Dependencies returns required plugin dependencies
	Dependencies() []PluginDependency

	// Shutdown gracefully stops the plugin
	Shutdown(ctx context.Context) error
}

// PluginHost provides server context and services to plugins
type PluginHost interface {
	// Register middleware handlers (still uses http.Handler for interpose compatibility)
	RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error

	// Register API endpoints using httprouter.Handle
	RegisterHandler(pattern string, handler httprouter.Handle) error

	// Access storage backend
	Storage() hkpstorage.Storage

	// Access configuration
	Config() *config.Settings

	// Access metrics system
	Metrics() *metrics.Metrics

	// Access logger
	Logger() *log.Logger

	// Register periodic tasks
	RegisterTask(name string, interval time.Duration, task func(context.Context) error) error

	// Publish events to plugin system
	PublishEvent(event events.PluginEvent) error

	// Subscribe to plugin events
	SubscribeEvent(eventType string, handler events.PluginEventHandler) error

	// Subscribe to Hockeypuck-style key change notifications
	SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error

	// Convenience methods for common events
	PublishThreatDetected(threat events.ThreatInfo) error
	PublishRateLimitViolation(violation events.RateLimitViolation) error
	PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error
}

// CoreExtensionPlugin extends fundamental server capabilities
type CoreExtensionPlugin interface {
	Plugin

	// Extend server initialization
	ExtendServerInit(server *Server) error

	// Modify server configuration
	ModifyConfig(config *Settings) error

	// Register custom services
	RegisterServices(host PluginHost) error
}

// StoragePlugin provides custom storage implementations
type StoragePlugin interface {
	Plugin

	// Create storage backend instance
	CreateStorage(config StorageConfig) (hkpstorage.Storage, error)

	// Backend type identifier
	BackendType() string

	// Required configuration schema
	ConfigSchema() map[string]interface{}
}

// SecurityPlugin provides security enhancements
type SecurityPlugin interface {
	Plugin

	// Authentication providers
	CreateAuthProvider(config AuthConfig) (AuthProvider, error)

	// Audit logging enhancements
	CreateAuditLogger(config AuditConfig) (AuditLogger, error)

	// Encryption providers
	CreateEncryptionProvider(config EncryptionConfig) (EncryptionProvider, error)
}

// AuthProvider interface for authentication providers
type AuthProvider interface {
	Authenticate(username, password string) (bool, error)
	ValidateToken(token string) (bool, error)
}

// AuditLogger interface for audit logging
type AuditLogger interface {
	LogEvent(event AuditEvent) error
}

// EncryptionProvider interface for encryption providers
type EncryptionProvider interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// MonitoringPlugin provides observability enhancements
type MonitoringPlugin interface {
	Plugin

	// Custom metrics collectors
	CreateMetricsCollector(config MetricsConfig) (MetricsCollector, error)

	// Alert providers
	CreateAlertProvider(config AlertConfig) (AlertProvider, error)

	// Dashboard providers
	CreateDashboardProvider(config DashboardConfig) (DashboardProvider, error)
}

// MetricsCollector interface for custom metrics
type MetricsCollector interface {
	Collect() (map[string]interface{}, error)
	Name() string
}

// AlertProvider interface for alerting
type AlertProvider interface {
	SendAlert(alert Alert) error
}

// DashboardProvider interface for dashboard providers
type DashboardProvider interface {
	CreateDashboard(config DashboardConfig) error
	UpdateDashboard(id string, config DashboardConfig) error
}

// MiddlewarePlugin provides HTTP request/response processing
type MiddlewarePlugin interface {
	Plugin

	// Create middleware handler
	CreateMiddleware(config MiddlewareConfig) (func(http.Handler) http.Handler, error)

	// Middleware priority (lower numbers run first)
	Priority() int

	// Paths this middleware applies to
	ApplicablePaths() []string
}
