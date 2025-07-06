// Package config provides generic configuration structures for the plugin system
// This deliberately avoids copying any Hockeypuck-specific configuration patterns
// to maintain AGPL license compliance
package config

import (
	"time"
)

// Settings represents the minimal plugin system configuration
// This is deliberately generic to avoid AGPL license issues
type Settings struct {
	// Generic server information
	DataDir string

	// Plugin-specific configuration
	Plugins PluginConfig
}

// PluginConfig configures the plugin system only
type PluginConfig struct {
	Enabled   bool                              `toml:"enabled"`
	Directory string                            `toml:"directory"`
	LoadOrder []string                          `toml:"loadOrder"`
	Global    GlobalPluginConfig                `toml:"global"`
	Config    map[string]map[string]interface{} `toml:"config"`
}

// GlobalPluginConfig contains global plugin settings
type GlobalPluginConfig struct {
	EventBufferSize     int    `toml:"eventBufferSize"`
	MaxConcurrentEvents int    `toml:"maxConcurrentEvents"`
	LogLevel            string `toml:"logLevel"`
	MetricsEnabled      bool   `toml:"metricsEnabled"`
	TaskTimeoutStr      string `toml:"taskTimeout"`
}

// Constants for plugin system defaults only
const (
	DefaultPluginDirectory = "/etc/hockeypuck/plugins"
	DefaultDataDir         = "/var/lib/hockeypuck"
)

// DefaultSettings returns default plugin configuration
func DefaultSettings() Settings {
	return Settings{
		DataDir: DefaultDataDir,
		Plugins: PluginConfig{
			Enabled:   false,
			Directory: DefaultPluginDirectory,
			Global: GlobalPluginConfig{
				EventBufferSize:     1000,
				MaxConcurrentEvents: 100,
				LogLevel:            "info",
				MetricsEnabled:      true,
				TaskTimeoutStr:      "30s",
			},
			Config: make(map[string]map[string]interface{}),
		},
	}
}

// GetPluginConfig returns configuration for a specific plugin
func (s *Settings) GetPluginConfig(pluginName string) map[string]interface{} {
	if config, exists := s.Plugins.Config[pluginName]; exists {
		return config
	}
	return make(map[string]interface{})
}

// TaskTimeout returns the task timeout as a duration
func (g *GlobalPluginConfig) TaskTimeout() time.Duration {
	if dur, err := time.ParseDuration(g.TaskTimeoutStr); err == nil {
		return dur
	}
	return 30 * time.Second // fallback
}

// NewFromGeneric creates Settings from a generic configuration map
// This allows Hockeypuck to pass its config without us knowing the structure
func NewFromGeneric(data map[string]interface{}) *Settings {
	settings := DefaultSettings()

	// Extract only the data we need for plugins
	if dataDir, ok := data["dataDir"].(string); ok {
		settings.DataDir = dataDir
	}

	if pluginData, ok := data["plugins"].(map[string]interface{}); ok {
		if enabled, ok := pluginData["enabled"].(bool); ok {
			settings.Plugins.Enabled = enabled
		}
		if directory, ok := pluginData["directory"].(string); ok {
			settings.Plugins.Directory = directory
		}
		if config, ok := pluginData["config"].(map[string]map[string]interface{}); ok {
			settings.Plugins.Config = config
		}
	}

	return &settings
}
