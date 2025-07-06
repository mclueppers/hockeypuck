# Plugin Package Documentation

## Overview

The plugin package provides the foundation for Hockeypuck's plugin system. It has been restructured into logical components for better maintainability and now supports `httprouter` for improved performance.

## File Structure

- **`interface.go`** - Core plugin interfaces and contracts
- **`types.go`** - Basic types, dependencies, and configuration structures
- **`base.go`** - BasePlugin implementation for plugins to extend
- **`registry.go`** - Plugin registration and discovery
- **`lifecycle.go`** - Dependency resolution and initialization/shutdown ordering
- **`manager.go`** - High-level plugin management and global registry
- **`adapters.go`** - HTTP handler adapters for httprouter compatibility

## HTTP Handler Migration

The plugin system now uses `httprouter.Handle` for better performance. If your plugin uses standard `http.HandlerFunc` handlers, you can easily adapt them using the provided adapters.

### Using the Adapter

```go
// Old way (no longer works directly)
host.RegisterHandler("/api/endpoint", p.handleRequest)

// New way with adapter
host.RegisterHandler("/api/endpoint", plugin.WrapStandardHandler(p.handleRequest))
```

### Example Plugin Handler

```go
// Your existing handler remains unchanged
func (p *MyPlugin) handleRequest(w http.ResponseWriter, r *http.Request) {
    // Handle the request
    w.Write([]byte("Hello from plugin"))
}

// In your Initialize method
func (p *MyPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
    // Register handlers with the adapter
    host.RegisterHandler("/api/status", plugin.WrapStandardHandler(p.handleStatus))
    host.RegisterHandler("/api/data", plugin.WrapStandardHandler(p.handleData))
    
    return nil
}
```

### Using URL Parameters

If you need access to httprouter's URL parameters, you can create handlers that use them directly:

```go
// Handler that uses httprouter params
func (p *MyPlugin) handleUserRequest(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
    userID := ps.ByName("id")
    // Handle the request with the user ID
    w.Write([]byte("User: " + userID))
}

// Register it
host.RegisterHandler("/api/user/:id", plugin.HTTPHandlerWithParamsAdapter(p.handleUserRequest))
```

## Creating a Plugin

### Basic Plugin Structure

```go
package myplugin

import (
    "context"
    "net/http"
    
    "github.com/dobrevit/hkp-plugin-core/pkg/plugin"
)

type MyPlugin struct {
    plugin.BasePlugin
    // Your plugin fields
}

func (p *MyPlugin) Initialize(ctx context.Context, host plugin.PluginHost, config map[string]interface{}) error {
    p.SetInfo("my-plugin", "1.0.0", "My awesome plugin")
    
    // Register HTTP handlers
    host.RegisterHandler("/my-plugin/status", plugin.WrapStandardHandler(p.handleStatus))
    
    // Register middleware
    host.RegisterMiddleware("/", p.authMiddleware)
    
    // Subscribe to events
    host.SubscribeEvent("security.threat", p.handleThreatEvent)
    
    p.SetInitialized(true)
    return nil
}

func (p *MyPlugin) handleStatus(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`{"status": "ok"}`))
}

func (p *MyPlugin) authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Authentication logic
        next.ServeHTTP(w, r)
    })
}

func (p *MyPlugin) handleThreatEvent(event plugin.PluginEvent) error {
    // Handle security threat event
    return nil
}
```

## Plugin Dependencies

Plugins can declare dependencies on other plugins:

```go
func (p *MyPlugin) Dependencies() []plugin.PluginDependency {
    return []plugin.PluginDependency{
        {
            Name:     "base-security",
            Version:  "1.0.0",
            Type:     plugin.DependencyRequired,
        },
        {
            Name:     "advanced-features",
            Version:  "2.0.0",
            Type:     plugin.DependencyOptional,
            Optional: true,
        },
    }
}
```

## Testing Plugins

Use the provided mock implementations for testing:

```go
func TestMyPlugin(t *testing.T) {
    host := NewMockPluginHost()
    plugin := &MyPlugin{}
    
    config := map[string]interface{}{
        "setting": "value",
    }
    
    err := plugin.Initialize(context.Background(), host, config)
    if err != nil {
        t.Fatalf("Failed to initialize plugin: %v", err)
    }
    
    // Test your plugin functionality
}
```

## Performance Considerations

The migration to `httprouter` provides:
- Faster route matching with radix tree implementation
- Lower memory allocation per request
- Built-in support for URL parameters
- Better performance under high load

## Migration Guide

For existing plugins:

1. Update handler registrations to use `plugin.WrapStandardHandler()`
2. No changes needed to handler implementations
3. Optional: Update handlers to use `httprouter.Params` for better URL parameter handling
4. Test thoroughly to ensure compatibility

## Best Practices

1. Always use the `BasePlugin` for common functionality
2. Properly handle initialization and shutdown
3. Use the adapter functions for HTTP handler compatibility
4. Declare dependencies explicitly
5. Handle errors gracefully
6. Use structured logging with appropriate log levels
7. Write comprehensive tests for your plugin