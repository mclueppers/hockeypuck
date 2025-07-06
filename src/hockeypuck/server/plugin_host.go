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
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/julienschmidt/httprouter"
	log "github.com/sirupsen/logrus"

	"github.com/dobrevit/hkp-plugin-core/pkg/config"
	"github.com/dobrevit/hkp-plugin-core/pkg/events"
	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	"github.com/dobrevit/hkp-plugin-core/pkg/metrics"
)

// TaskInfo represents a registered task
type TaskInfo struct {
	Name     string
	Interval time.Duration
	Task     func(context.Context) error
	Cancel   context.CancelFunc
}

// ServerPluginHost implements the PluginHost interface for the server
type ServerPluginHost struct {
	server   *Server
	eventBus *events.EventBus
	tasks    map[string]TaskInfo
}

// NewServerPluginHost creates a new server plugin host
func NewServerPluginHost(server *Server) *ServerPluginHost {
	return &ServerPluginHost{
		server: server,
		tasks:  make(map[string]TaskInfo),
	}
}

// SetEventBus sets the event bus for this host
func (ph *ServerPluginHost) SetEventBus(eventBus *events.EventBus) {
	ph.eventBus = eventBus
}

// Implement PluginHost interface
func (ph *ServerPluginHost) RegisterMiddleware(path string, middleware func(http.Handler) http.Handler) error {
	// Integrate with the actual Hockeypuck middleware system
	if ph.server != nil && ph.server.middle != nil {
		// Add middleware to the interpose middleware chain
		ph.server.middle.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Apply middleware only to the specified path (if specified)
				if path == "" || r.URL.Path == path || strings.HasPrefix(r.URL.Path, path) {
					wrappedHandler := middleware(next)
					wrappedHandler.ServeHTTP(w, r)
				} else {
					next.ServeHTTP(w, r)
				}
			})
		})
	}

	log.WithFields(log.Fields{
		"path": path,
	}).Debug("Plugin middleware registered with Hockeypuck middleware chain")
	return nil
}

func (ph *ServerPluginHost) RegisterHandler(pattern string, handler httprouter.Handle) error {
	// Register with the actual Hockeypuck router
	if ph.server != nil && ph.server.r != nil {
		// Register for all HTTP methods that make sense for plugins
		ph.server.r.GET(pattern, handler)
		ph.server.r.POST(pattern, handler)
		ph.server.r.PUT(pattern, handler)
		ph.server.r.DELETE(pattern, handler)
	}

	log.WithFields(log.Fields{
		"pattern": pattern,
	}).Debug("Plugin handler registered")
	return nil
}

func (ph *ServerPluginHost) Storage() hkpstorage.Storage {
	// Return the actual Hockeypuck storage wrapped in an adapter
	if ph.server != nil && ph.server.st != nil {
		return NewStorageAdapter(ph.server.st)
	}
	return nil
}

func (ph *ServerPluginHost) Config() *config.Settings {
	// Convert from Hockeypuck settings to plugin settings
	if ph.server != nil && ph.server.settings != nil {
		// Map Hockeypuck settings to plugin settings
		pluginSettings := &config.Settings{
			DataDir: "/var/lib/hockeypuck", // Default, could be configurable
			Plugins: config.PluginConfig{
				Enabled:   true,
				Directory: "./plugins",
				LoadOrder: []string{}, // Will be populated from plugin dependencies
			},
		}

		// Add any additional configuration mappings from Hockeypuck settings
		// This is where you'd map specific Hockeypuck configuration fields
		// to plugin configuration if needed

		return pluginSettings
	}

	// Fallback to defaults
	return &config.Settings{
		DataDir: "/var/lib/hockeypuck",
		Plugins: config.PluginConfig{
			Enabled:   true,
			Directory: "./plugins",
			LoadOrder: []string{},
		},
	}
}

func (ph *ServerPluginHost) Metrics() *metrics.Metrics {
	// Return the plugin system metrics (not Hockeypuck's metrics)
	// The plugin system uses its own metrics implementation
	return metrics.NewMetrics()
}

func (ph *ServerPluginHost) Logger() *log.Logger {
	// Return the standard logrus logger
	return log.StandardLogger()
}

func (ph *ServerPluginHost) RegisterTask(name string, interval time.Duration, task func(context.Context) error) error {
	ctx, cancel := context.WithCancel(context.Background())
	ph.tasks[name] = TaskInfo{
		Name:     name,
		Interval: interval,
		Task:     task,
		Cancel:   cancel,
	}

	// Start the task
	go ph.runTask(ctx, name, interval, task)
	return nil
}

func (ph *ServerPluginHost) runTask(ctx context.Context, name string, interval time.Duration, task func(context.Context) error) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := task(ctx); err != nil {
				log.WithFields(log.Fields{
					"task":  name,
					"error": err,
				}).Error("Task error")
			}
		case <-ctx.Done():
			return
		}
	}
}

// Event system methods
func (ph *ServerPluginHost) PublishEvent(event events.PluginEvent) error {
	if ph.eventBus != nil {
		return ph.eventBus.PublishEvent(event)
	}
	return nil
}

func (ph *ServerPluginHost) SubscribeEvent(eventType string, handler events.PluginEventHandler) error {
	if ph.eventBus != nil {
		return ph.eventBus.SubscribeEvent(eventType, handler)
	}
	return nil
}

func (ph *ServerPluginHost) SubscribeKeyChanges(callback func(hkpstorage.KeyChange) error) error {
	if ph.eventBus != nil {
		return ph.eventBus.SubscribeKeyChanges(callback)
	}
	return nil
}

// Convenience event methods
func (ph *ServerPluginHost) PublishThreatDetected(threat events.ThreatInfo) error {
	if ph.eventBus != nil {
		return ph.eventBus.PublishThreatDetected(threat)
	}
	return nil
}

func (ph *ServerPluginHost) PublishRateLimitViolation(violation events.RateLimitViolation) error {
	if ph.eventBus != nil {
		return ph.eventBus.PublishRateLimitViolation(violation)
	}
	return nil
}

func (ph *ServerPluginHost) PublishZTNAEvent(eventType string, ztnaEvent events.ZTNAEvent) error {
	if ph.eventBus != nil {
		return ph.eventBus.PublishZTNAEvent(eventType, ztnaEvent)
	}
	return nil
}
