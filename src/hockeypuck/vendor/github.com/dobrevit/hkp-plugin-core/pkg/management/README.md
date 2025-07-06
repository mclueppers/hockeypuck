# Plugin Lifecycle Management

This package provides comprehensive plugin lifecycle management functionality that can be easily integrated into Hockeypuck and other servers.

## Features

- **Plugin Status Monitoring**: Real-time status of all plugins
- **Health Checks**: Comprehensive health monitoring for each plugin
- **Hot Reload**: Graceful plugin reloading with request draining
- **Configuration Management**: Dynamic plugin configuration updates
- **Request Draining**: Ensures no requests are lost during plugin transitions
- **Rollback Support**: Automatic rollback on failed operations
- **HTTP Endpoints**: Ready-to-use HTTP handlers for management

## HTTP Endpoints

### GET /plugins/status
Returns overall plugin system status including:
- Plugin states and counts
- Active request counts
- Health summary
- System uptime

```json
{
  "plugin_system": {
    "enabled": true,
    "total_plugins": 3,
    "active_plugins": 3,
    "plugin_dir": "/etc/hockeypuck/plugins",
    "active_requests": 0,
    "plugin_states": {
      "ratelimit-geo": "active",
      "zerotrust": "active"
    }
  },
  "health_status": {
    "healthy_count": 3,
    "unhealthy_count": 0,
    "total_count": 3,
    "overall_status": "healthy"
  },
  "uptime": "2h15m30s",
  "timestamp": 1751731600
}
```

### GET /plugins/list
Returns detailed list of all plugins:

```json
{
  "plugins": [
    {
      "name": "ratelimit-geo",
      "status": "active",
      "health": {
        "status": "healthy",
        "state": "active",
        "last_check": 1751731600,
        "checks": {
          "active_requests": 0
        }
      }
    }
  ],
  "total_count": 1,
  "timestamp": 1751731600
}
```

### GET /plugins/health
Returns health status for all plugins:

```json
{
  "overall_status": "healthy",
  "plugins": {
    "ratelimit-geo": {
      "status": "healthy",
      "state": "active",
      "last_check": 1751731600,
      "checks": {
        "active_requests": 0
      }
    }
  },
  "timestamp": 1751731600
}
```

### POST /plugins/reload?plugin=<name>
Reloads a specific plugin with graceful request draining:

```json
{
  "plugin": "ratelimit-geo",
  "status": "success",
  "message": "Plugin reloaded successfully with graceful draining",
  "timestamp": 1751731600
}
```

### GET /plugins/config?plugin=<name>
Gets current plugin configuration:

```json
{
  "plugin": "ratelimit-geo",
  "config": {
    "enabled": true,
    "geoip_database_path": "/usr/share/GeoIP/GeoLite2-City.mmdb"
  },
  "timestamp": 1751731600
}
```

### PUT /plugins/config?plugin=<name>
Updates plugin configuration (with request body containing new config):

```json
{
  "plugin": "ratelimit-geo",
  "status": "success", 
  "message": "Configuration updated and plugin reloaded",
  "timestamp": 1751731600
}
```

## Integration with Hockeypuck

### Basic Integration

```go
import "github.com/dobrevit/hkp-plugin-core/pkg/management"

// In your server struct
type HockeypuckServer struct {
    pluginManager *management.PluginManager
    // ... other fields
}

// During initialization
func (s *HockeypuckServer) initPlugins() error {
    host := NewServerPluginHost(s)
    settings := convertToPluginSettings(s.config)
    
    // Create plugin manager
    s.pluginManager = management.NewPluginManager(host, settings, s.logger)
    
    // Initialize plugin system
    pluginSystem, err := integration.InitializePlugins(ctx, host, settings)
    if err != nil {
        return err
    }
    
    s.pluginManager.SetPluginSystem(pluginSystem)
    return nil
}

// Register HTTP endpoints
func (s *HockeypuckServer) registerRoutes() {
    s.mux.HandleFunc("/plugins/status", s.pluginManager.StatusHandler)
    s.mux.HandleFunc("/plugins/list", s.pluginManager.ListHandler)
    s.mux.HandleFunc("/plugins/health", s.pluginManager.HealthHandler)
    s.mux.HandleFunc("/plugins/reload", s.pluginManager.ReloadHandler)
    s.mux.HandleFunc("/plugins/config", s.pluginManager.ConfigHandler)
}
```

### Advanced Usage

```go
// Programmatic plugin management
func (s *HockeypuckServer) reloadPlugin(name string) error {
    return s.pluginManager.ReloadPlugin(name)
}

func (s *HockeypuckServer) updatePluginConfig(name string, config map[string]interface{}) error {
    return s.pluginManager.UpdatePluginConfig(name, config)
}

// Get plugin status for monitoring
func (s *HockeypuckServer) getPluginMetrics() map[string]interface{} {
    return s.pluginManager.GetPluginStatus()
}
```

## Plugin States

Plugins can be in the following states:

- **loading**: Plugin is being initialized
- **active**: Plugin is running normally
- **reloading**: Plugin is being reloaded (graceful transition)
- **unloading**: Plugin is being shut down
- **failed**: Plugin failed to initialize or encountered an error
- **disabled**: Plugin is intentionally disabled

## Request Draining

During plugin transitions (reload/shutdown), the system:

1. Stops accepting new requests for the plugin
2. Waits for active requests to complete (up to drain timeout)
3. Force-cancels remaining requests if timeout is reached
4. Proceeds with the plugin operation

Default drain timeout is 60 seconds, configurable per deployment.

## Error Handling

The plugin manager includes comprehensive error handling:

- **Rollback**: Failed operations attempt to restore previous state
- **Graceful Degradation**: Individual plugin failures don't affect the system
- **Detailed Logging**: All operations are logged with structured logging
- **Status Tracking**: Real-time status updates for monitoring

## Production Considerations

1. **Monitoring**: Use the health endpoints for monitoring systems
2. **Alerting**: Set up alerts for plugin state changes
3. **Backup**: Consider backing up plugin configurations
4. **Testing**: Test plugin reloads in staging before production
5. **Capacity**: Monitor active request counts during peak loads

This package is designed to be production-ready and provides the foundation for reliable plugin lifecycle management in Hockeypuck deployments.