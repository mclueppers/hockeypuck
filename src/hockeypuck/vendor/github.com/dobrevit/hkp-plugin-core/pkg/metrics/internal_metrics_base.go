// Package metrics provides comprehensive metrics collection for Hockeypuck
package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsInstance *Metrics
	metricsOnce     sync.Once
)

// Metrics represents the main metrics system
type Metrics struct {
	registry   *prometheus.Registry
	collectors map[string]MetricsCollector
	mu         sync.RWMutex

	// Core server metrics
	ServerMetrics *ServerMetrics

	// Storage metrics
	StorageMetrics *StorageMetrics

	// Rate limiting metrics
	RateLimitMetrics *RateLimitMetrics

	// Plugin metrics
	PluginMetrics *PluginMetrics

	// HTTP metrics
	HTTPMetrics *HTTPMetrics

	// Custom metrics
	CustomMetrics map[string]interface{}
}

// NewMetrics creates a new metrics system (singleton)
func NewMetrics() *Metrics {
	metricsOnce.Do(func() {
		registry := prometheus.NewRegistry()

		m := &Metrics{
			registry:      registry,
			collectors:    make(map[string]MetricsCollector),
			CustomMetrics: make(map[string]interface{}),
		}

		// Initialize core metrics with custom registry
		m.ServerMetrics = NewServerMetrics(registry)
		m.StorageMetrics = NewStorageMetrics(registry)
		m.RateLimitMetrics = NewRateLimitMetrics(registry)
		m.PluginMetrics = NewPluginMetrics(registry)
		m.HTTPMetrics = NewHTTPMetrics(registry)

		metricsInstance = m
	})

	return metricsInstance
}

// MetricsCollector interface for custom metrics collectors
type MetricsCollector interface {
	Collect() (map[string]interface{}, error)
	Name() string
	Description() string
}

// ServerMetrics contains core server metrics
type ServerMetrics struct {
	StartTime       prometheus.Gauge
	Uptime          prometheus.Gauge
	Version         *prometheus.GaugeVec
	BuildInfo       *prometheus.GaugeVec
	GoVersion       prometheus.Gauge
	GoRoutines      prometheus.Gauge
	MemoryUsage     prometheus.Gauge
	CPUUsage        prometheus.Gauge
	FileDescriptors prometheus.Gauge

	// Request metrics
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	RequestSize     *prometheus.HistogramVec
	ResponseSize    *prometheus.HistogramVec

	// Connection metrics
	ActiveConnections prometheus.Gauge
	TotalConnections  prometheus.Counter
}

// NewServerMetrics creates new server metrics
func NewServerMetrics(registry *prometheus.Registry) *ServerMetrics {
	metrics := &ServerMetrics{
		StartTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_start_time_seconds",
			Help: "Unix timestamp of when Hockeypuck started",
		}),

		Uptime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_uptime_seconds",
			Help: "Number of seconds since Hockeypuck started",
		}),

		Version: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_version_info",
			Help: "Version information about Hockeypuck",
		}, []string{"version", "commit", "branch", "build_date"}),

		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_build_info",
			Help: "Build information about Hockeypuck",
		}, []string{"go_version", "compiler", "platform"}),

		GoVersion: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_go_version_info",
			Help: "Go version information",
		}),

		GoRoutines: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_goroutines",
			Help: "Number of active goroutines",
		}),

		MemoryUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_memory_usage_bytes",
			Help: "Memory usage in bytes",
		}),

		CPUUsage: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_cpu_usage_percent",
			Help: "CPU usage percentage",
		}),

		FileDescriptors: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_file_descriptors",
			Help: "Number of open file descriptors",
		}),

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_server_requests_total",
			Help: "Total number of server requests",
		}, []string{"method", "path", "status"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_server_request_duration_seconds",
			Help:    "Server request duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"method", "path"}),

		RequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_server_request_size_bytes",
			Help:    "Server request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		}, []string{"method", "path"}),

		ResponseSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_server_response_size_bytes",
			Help:    "Server response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		}, []string{"method", "path"}),

		ActiveConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_active_connections",
			Help: "Number of active connections",
		}),

		TotalConnections: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_total_connections",
			Help: "Total number of connections handled",
		}),
	}

	// Register all metrics with the custom registry
	registry.MustRegister(
		metrics.StartTime,
		metrics.Uptime,
		metrics.Version,
		metrics.BuildInfo,
		metrics.GoVersion,
		metrics.GoRoutines,
		metrics.MemoryUsage,
		metrics.CPUUsage,
		metrics.FileDescriptors,
		metrics.RequestsTotal,
		metrics.RequestDuration,
		metrics.RequestSize,
		metrics.ResponseSize,
		metrics.ActiveConnections,
		metrics.TotalConnections,
	)

	return metrics
}

// StorageMetrics contains storage-related metrics
type StorageMetrics struct {
	KeysTotal      prometheus.Gauge
	KeysInserted   prometheus.Counter
	KeysUpdated    prometheus.Counter
	KeysDeleted    prometheus.Counter
	KeysIgnored    prometheus.Counter
	KeysDuplicated prometheus.Counter

	// Storage operations
	OperationsTotal   *prometheus.CounterVec
	OperationDuration *prometheus.HistogramVec
	OperationErrors   *prometheus.CounterVec

	// Database metrics
	DatabaseConnections     prometheus.Gauge
	DatabaseConnectionsIdle prometheus.Gauge
	DatabaseQueries         *prometheus.CounterVec
	DatabaseQueryDuration   *prometheus.HistogramVec
	DatabaseSize            prometheus.Gauge

	// Index metrics
	IndexSize        *prometheus.GaugeVec
	IndexUsage       *prometheus.CounterVec
	IndexMaintenance *prometheus.CounterVec
}

// NewStorageMetrics creates new storage metrics
func NewStorageMetrics(registry *prometheus.Registry) *StorageMetrics {
	metrics := &StorageMetrics{
		KeysTotal: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_keys_total",
			Help: "Total number of keys in storage",
		}),

		KeysInserted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_keys_inserted_total",
			Help: "Total number of keys inserted",
		}),

		KeysUpdated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_keys_updated_total",
			Help: "Total number of keys updated",
		}),

		KeysDeleted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_keys_deleted_total",
			Help: "Total number of keys deleted",
		}),

		KeysIgnored: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_keys_ignored_total",
			Help: "Total number of keys ignored during import",
		}),

		KeysDuplicated: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "hockeypuck_keys_duplicated_total",
			Help: "Total number of duplicate keys encountered",
		}),

		OperationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_storage_operations_total",
			Help: "Total number of storage operations",
		}, []string{"operation", "status"}),

		OperationDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_storage_operation_duration_seconds",
			Help:    "Storage operation duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"operation"}),

		OperationErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_storage_operation_errors_total",
			Help: "Total number of storage operation errors",
		}, []string{"operation", "error_type"}),

		DatabaseConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_database_connections",
			Help: "Number of active database connections",
		}),

		DatabaseConnectionsIdle: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_database_connections_idle",
			Help: "Number of idle database connections",
		}),

		DatabaseQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_database_queries_total",
			Help: "Total number of database queries",
		}, []string{"query_type", "status"}),

		DatabaseQueryDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_database_query_duration_seconds",
			Help:    "Database query duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"query_type"}),

		DatabaseSize: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_database_size_bytes",
			Help: "Database size in bytes",
		}),

		IndexSize: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_index_size_bytes",
			Help: "Index size in bytes",
		}, []string{"index_name"}),

		IndexUsage: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_index_usage_total",
			Help: "Total index usage count",
		}, []string{"index_name", "operation"}),

		IndexMaintenance: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_index_maintenance_total",
			Help: "Total index maintenance operations",
		}, []string{"index_name", "operation"}),
	}

	// Register all metrics with the custom registry
	registry.MustRegister(
		metrics.KeysTotal,
		metrics.KeysInserted,
		metrics.KeysUpdated,
		metrics.KeysDeleted,
		metrics.KeysIgnored,
		metrics.KeysDuplicated,
		metrics.OperationsTotal,
		metrics.OperationDuration,
		metrics.OperationErrors,
		metrics.DatabaseConnections,
		metrics.DatabaseConnectionsIdle,
		metrics.DatabaseQueries,
		metrics.DatabaseQueryDuration,
		metrics.DatabaseSize,
		metrics.IndexSize,
		metrics.IndexUsage,
		metrics.IndexMaintenance,
	)

	return metrics
}

// RateLimitMetrics contains rate limiting metrics
type RateLimitMetrics struct {
	ViolationsTotal *prometheus.CounterVec
	BannedIPs       *prometheus.GaugeVec
	TrackedIPs      prometheus.Gauge
	TorExitCount    prometheus.Gauge
	BackendDuration *prometheus.HistogramVec
	BackendErrors   *prometheus.CounterVec

	// Connection metrics
	ConnectionsRejected *prometheus.CounterVec
	ConnectionsActive   *prometheus.GaugeVec

	// Request metrics
	RequestsRejected *prometheus.CounterVec
	RequestRate      *prometheus.GaugeVec

	// Error tracking
	ErrorRate   *prometheus.GaugeVec
	ErrorsTotal *prometheus.CounterVec
}

// NewRateLimitMetrics creates new rate limiting metrics
func NewRateLimitMetrics(registry *prometheus.Registry) *RateLimitMetrics {
	metrics := &RateLimitMetrics{
		ViolationsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_violations_total",
			Help: "Total number of rate limit violations",
		}, []string{"reason", "is_tor", "violation_type"}),

		BannedIPs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_banned_ips",
			Help: "Number of currently banned IPs",
		}, []string{"is_tor", "ban_type"}),

		TrackedIPs: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_tracked_ips",
			Help: "Number of IPs being tracked",
		}),

		TorExitCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_tor_exits",
			Help: "Number of known Tor exit nodes",
		}),

		BackendDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_rate_limit_backend_duration_seconds",
			Help:    "Duration of rate limit backend operations",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}, []string{"operation", "backend_type"}),

		BackendErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_backend_errors_total",
			Help: "Total number of rate limit backend errors",
		}, []string{"operation", "backend_type", "error_type"}),

		ConnectionsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_connections_rejected_total",
			Help: "Total number of connections rejected by rate limiting",
		}, []string{"reason", "is_tor"}),

		ConnectionsActive: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_connections_active",
			Help: "Number of active connections per IP",
		}, []string{"is_tor"}),

		RequestsRejected: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_requests_rejected_total",
			Help: "Total number of requests rejected by rate limiting",
		}, []string{"reason", "is_tor", "method", "path"}),

		RequestRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_request_rate",
			Help: "Current request rate per IP",
		}, []string{"is_tor"}),

		ErrorRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_rate_limit_error_rate",
			Help: "Current error rate per IP",
		}, []string{"is_tor"}),

		ErrorsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_rate_limit_errors_total",
			Help: "Total number of errors tracked by rate limiting",
		}, []string{"status_code", "is_tor"}),
	}

	// Register all metrics with the custom registry
	registry.MustRegister(
		metrics.ViolationsTotal,
		metrics.BannedIPs,
		metrics.TrackedIPs,
		metrics.TorExitCount,
		metrics.BackendDuration,
		metrics.BackendErrors,
		metrics.ConnectionsRejected,
		metrics.ConnectionsActive,
		metrics.RequestsRejected,
		metrics.RequestRate,
		metrics.ErrorRate,
		metrics.ErrorsTotal,
	)

	return metrics
}

// PluginMetrics contains plugin-related metrics
type PluginMetrics struct {
	PluginsLoaded     prometheus.Gauge
	PluginLoadTime    *prometheus.HistogramVec
	PluginErrors      *prometheus.CounterVec
	PluginInitTime    *prometheus.HistogramVec
	PluginMemoryUsage *prometheus.GaugeVec
	PluginCPUUsage    *prometheus.GaugeVec

	// Plugin lifecycle
	PluginLifecycle    *prometheus.CounterVec
	PluginDependencies *prometheus.GaugeVec

	// Plugin performance
	PluginExecution *prometheus.HistogramVec
	PluginCalls     *prometheus.CounterVec
}

// NewPluginMetrics creates new plugin metrics
func NewPluginMetrics(registry *prometheus.Registry) *PluginMetrics {
	metrics := &PluginMetrics{
		PluginsLoaded: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_plugins_loaded",
			Help: "Number of loaded plugins",
		}),

		PluginLoadTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_plugin_load_duration_seconds",
			Help:    "Plugin load duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}, []string{"plugin_name", "plugin_type"}),

		PluginErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_plugin_errors_total",
			Help: "Total number of plugin errors",
		}, []string{"plugin_name", "error_type", "severity"}),

		PluginInitTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_plugin_init_duration_seconds",
			Help:    "Plugin initialization duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}, []string{"plugin_name"}),

		PluginMemoryUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_plugin_memory_usage_bytes",
			Help: "Plugin memory usage in bytes",
		}, []string{"plugin_name"}),

		PluginCPUUsage: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_plugin_cpu_usage_percent",
			Help: "Plugin CPU usage percentage",
		}, []string{"plugin_name"}),

		PluginLifecycle: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_plugin_lifecycle_total",
			Help: "Total plugin lifecycle events",
		}, []string{"plugin_name", "event", "status"}),

		PluginDependencies: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_plugin_dependencies",
			Help: "Number of plugin dependencies",
		}, []string{"plugin_name", "dependency_type"}),

		PluginExecution: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_plugin_execution_duration_seconds",
			Help:    "Plugin execution duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"plugin_name", "method"}),

		PluginCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_plugin_calls_total",
			Help: "Total number of plugin method calls",
		}, []string{"plugin_name", "method", "status"}),
	}

	// Register all metrics with the custom registry
	registry.MustRegister(
		metrics.PluginsLoaded,
		metrics.PluginLoadTime,
		metrics.PluginErrors,
		metrics.PluginInitTime,
		metrics.PluginMemoryUsage,
		metrics.PluginCPUUsage,
		metrics.PluginLifecycle,
		metrics.PluginDependencies,
		metrics.PluginExecution,
		metrics.PluginCalls,
	)

	return metrics
}

// HTTPMetrics contains HTTP-related metrics
type HTTPMetrics struct {
	RequestsInFlight prometheus.Gauge
	RequestsTotal    *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestSize      *prometheus.HistogramVec
	ResponseSize     *prometheus.HistogramVec
	ResponseTime     *prometheus.HistogramVec

	// Status code metrics
	StatusCodes *prometheus.CounterVec

	// Endpoint metrics
	EndpointCalls    *prometheus.CounterVec
	EndpointDuration *prometheus.HistogramVec
	EndpointErrors   *prometheus.CounterVec

	// User agent metrics
	UserAgents *prometheus.CounterVec

	// Geographic metrics
	RequestsByCountry *prometheus.CounterVec
}

// NewHTTPMetrics creates new HTTP metrics
func NewHTTPMetrics(registry *prometheus.Registry) *HTTPMetrics {
	metrics := &HTTPMetrics{
		RequestsInFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_http_requests_in_flight",
			Help: "Number of HTTP requests currently being processed",
		}),

		RequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_requests_total",
			Help: "Total number of HTTP requests",
		}, []string{"method", "endpoint", "status_class"}),

		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"method", "endpoint"}),

		RequestSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_http_request_size_bytes",
			Help:    "HTTP request size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		}, []string{"method", "endpoint"}),

		ResponseSize: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_http_response_size_bytes",
			Help:    "HTTP response size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 8),
		}, []string{"method", "endpoint"}),

		ResponseTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_http_response_time_seconds",
			Help:    "HTTP response time in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"method", "endpoint"}),

		StatusCodes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_status_codes_total",
			Help: "Total HTTP status codes returned",
		}, []string{"code", "method", "endpoint"}),

		EndpointCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_endpoint_calls_total",
			Help: "Total calls to each endpoint",
		}, []string{"endpoint", "method"}),

		EndpointDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_http_endpoint_duration_seconds",
			Help:    "Endpoint processing duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		}, []string{"endpoint"}),

		EndpointErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_endpoint_errors_total",
			Help: "Total endpoint errors",
		}, []string{"endpoint", "error_type"}),

		UserAgents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_user_agents_total",
			Help: "Total requests by user agent",
		}, []string{"user_agent_family"}),

		RequestsByCountry: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "hockeypuck_http_requests_by_country_total",
			Help: "Total requests by country",
		}, []string{"country_code"}),
	}

	// Register all metrics with the registry
	registry.MustRegister(
		metrics.RequestsInFlight,
		metrics.RequestsTotal,
		metrics.RequestDuration,
		metrics.RequestSize,
		metrics.ResponseSize,
		metrics.ResponseTime,
		metrics.StatusCodes,
		metrics.EndpointCalls,
		metrics.EndpointDuration,
		metrics.EndpointErrors,
		metrics.UserAgents,
		metrics.RequestsByCountry,
	)

	return metrics
}

// RegisterCollector registers a custom metrics collector
func (m *Metrics) RegisterCollector(collector MetricsCollector) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := collector.Name()
	if _, exists := m.collectors[name]; exists {
		return fmt.Errorf("collector %s already registered", name)
	}

	m.collectors[name] = collector
	return nil
}

// UnregisterCollector unregisters a metrics collector
func (m *Metrics) UnregisterCollector(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.collectors[name]; !exists {
		return fmt.Errorf("collector %s not found", name)
	}

	delete(m.collectors, name)
	return nil
}

// Collect collects metrics from all registered collectors
func (m *Metrics) Collect() (map[string]interface{}, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]interface{})

	// Collect from registered collectors
	for name, collector := range m.collectors {
		if data, err := collector.Collect(); err == nil {
			result[name] = data
		} else {
			result[name] = map[string]interface{}{
				"error": err.Error(),
			}
		}
	}

	// Add custom metrics
	for name, data := range m.CustomMetrics {
		result[name] = data
	}

	return result, nil
}

// SetCustomMetric sets a custom metric value
func (m *Metrics) SetCustomMetric(name string, value interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CustomMetrics[name] = value
}

// GetCustomMetric gets a custom metric value
func (m *Metrics) GetCustomMetric(name string) (interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, exists := m.CustomMetrics[name]
	return value, exists
}

// DeleteCustomMetric deletes a custom metric
func (m *Metrics) DeleteCustomMetric(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.CustomMetrics, name)
}

// PrometheusHandler returns a Prometheus metrics HTTP handler
func (m *Metrics) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
		Registry:          m.registry,
	})
}

// JSONHandler returns a JSON metrics HTTP handler
func (m *Metrics) JSONHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		data, err := m.Collect()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(data)
	}
}

// HealthMetrics contains health check metrics
type HealthMetrics struct {
	HealthChecks        *prometheus.GaugeVec
	HealthCheckDuration *prometheus.HistogramVec
	ComponentStatus     *prometheus.GaugeVec
	LastHealthCheck     prometheus.Gauge
}

// NewHealthMetrics creates new health metrics
func NewHealthMetrics() *HealthMetrics {
	return &HealthMetrics{
		HealthChecks: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_health_checks",
			Help: "Health check status (1 = healthy, 0 = unhealthy)",
		}, []string{"component", "check_type"}),

		HealthCheckDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "hockeypuck_health_check_duration_seconds",
			Help:    "Health check duration in seconds",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
		}, []string{"component", "check_type"}),

		ComponentStatus: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "hockeypuck_component_status",
			Help: "Component status (1 = up, 0 = down)",
		}, []string{"component"}),

		LastHealthCheck: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "hockeypuck_last_health_check_timestamp",
			Help: "Timestamp of last health check",
		}),
	}
}

// Timer provides timing functionality for metrics
type Timer struct {
	start    time.Time
	observer prometheus.Observer
}

// NewTimer creates a new timer
func NewTimer(observer prometheus.Observer) *Timer {
	return &Timer{
		start:    time.Now(),
		observer: observer,
	}
}

// ObserveDuration observes the elapsed time since timer creation
func (t *Timer) ObserveDuration() {
	if t.observer != nil {
		t.observer.Observe(time.Since(t.start).Seconds())
	}
}

// Counter provides a simple counter interface
type Counter struct {
	counter prometheus.Counter
}

// NewCounter creates a new counter
func NewCounter(name, help string) *Counter {
	return &Counter{
		counter: prometheus.NewCounter(prometheus.CounterOpts{
			Name: name,
			Help: help,
		}),
	}
}

// Inc increments the counter
func (c *Counter) Inc() {
	c.counter.Inc()
}

// Add adds a value to the counter
func (c *Counter) Add(value float64) {
	c.counter.Add(value)
}

// Gauge provides a simple gauge interface
type Gauge struct {
	gauge prometheus.Gauge
}

// NewGauge creates a new gauge
func NewGauge(name, help string) *Gauge {
	return &Gauge{
		gauge: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: name,
			Help: help,
		}),
	}
}

// Set sets the gauge value
func (g *Gauge) Set(value float64) {
	g.gauge.Set(value)
}

// Inc increments the gauge
func (g *Gauge) Inc() {
	g.gauge.Inc()
}

// Dec decrements the gauge
func (g *Gauge) Dec() {
	g.gauge.Dec()
}

// Add adds a value to the gauge
func (g *Gauge) Add(value float64) {
	g.gauge.Add(value)
}

// Sub subtracts a value from the gauge
func (g *Gauge) Sub(value float64) {
	g.gauge.Sub(value)
}

// UpdaterFunc represents a function that updates metrics
type UpdaterFunc func(context.Context) error

// MetricsUpdater manages periodic metrics updates
type MetricsUpdater struct {
	updaters []UpdaterFunc
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewMetricsUpdater creates a new metrics updater
func NewMetricsUpdater(interval time.Duration) *MetricsUpdater {
	ctx, cancel := context.WithCancel(context.Background())
	return &MetricsUpdater{
		updaters: make([]UpdaterFunc, 0),
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// AddUpdater adds a metrics updater function
func (mu *MetricsUpdater) AddUpdater(updater UpdaterFunc) {
	mu.updaters = append(mu.updaters, updater)
}

// Start starts the metrics updater
func (mu *MetricsUpdater) Start() {
	ticker := time.NewTicker(mu.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			for _, updater := range mu.updaters {
				if err := updater(mu.ctx); err != nil {
					// Log error but continue with other updaters
					continue
				}
			}
		case <-mu.ctx.Done():
			return
		}
	}
}

// Stop stops the metrics updater
func (mu *MetricsUpdater) Stop() {
	mu.cancel()
}

// Registry provides access to the Prometheus registry
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
