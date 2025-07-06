// Package plugin lifecycle management
package plugin

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

// PluginLifecycle manages plugin initialization and shutdown
type PluginLifecycle struct {
	registry     *PluginRegistry
	dependencies *DependencyGraph
}

// NewPluginLifecycle creates a new plugin lifecycle manager
func NewPluginLifecycle(registry *PluginRegistry) *PluginLifecycle {
	return &PluginLifecycle{
		registry:     registry,
		dependencies: NewDependencyGraph(),
	}
}

// Initialize initializes plugins in dependency order
func (l *PluginLifecycle) Initialize(ctx context.Context, configs map[string]map[string]interface{}) error {
	plugins := l.registry.List()

	// Build dependency graph
	for _, plugin := range plugins {
		l.dependencies.AddNode(plugin.Name())
		for _, dep := range plugin.Dependencies() {
			if dep.Type != DependencyConflict {
				l.dependencies.AddEdge(dep.Name, plugin.Name())
			}
		}
	}

	// Get initialization order
	order, err := l.dependencies.TopologicalSort()
	if err != nil {
		return fmt.Errorf("failed to resolve plugin dependencies: %w", err)
	}

	// Initialize plugins in order
	for _, name := range order {
		plugin, exists := l.registry.Get(name)
		if !exists {
			continue // Skip missing dependencies
		}

		config := configs[name]
		if config == nil {
			config = make(map[string]interface{})
		}

		if err := plugin.Initialize(ctx, l.registry.host, config); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", name, err)
		}
	}

	return nil
}

// Shutdown shuts down plugins in reverse dependency order
func (l *PluginLifecycle) Shutdown(ctx context.Context) error {
	plugins := l.registry.List()

	// Shutdown in reverse order
	for i := len(plugins) - 1; i >= 0; i-- {
		plugin := plugins[i]
		if err := plugin.Shutdown(ctx); err != nil {
			// Log error but continue shutdown
			log.WithFields(log.Fields{
				"plugin": plugin.Name(),
				"error":  err,
			}).Error("Failed to shutdown plugin")
		}
	}

	return nil
}

// DependencyGraph represents a dependency graph for plugins
type DependencyGraph struct {
	nodes map[string]bool
	edges map[string][]string
	mu    sync.RWMutex
}

// NewDependencyGraph creates a new dependency graph
func NewDependencyGraph() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[string]bool),
		edges: make(map[string][]string),
	}
}

// AddNode adds a node to the graph
func (g *DependencyGraph) AddNode(name string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[name] = true
	if g.edges[name] == nil {
		g.edges[name] = make([]string, 0)
	}
}

// AddEdge adds an edge from 'from' to 'to'
func (g *DependencyGraph) AddEdge(from, to string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[from] = append(g.edges[from], to)
}

// TopologicalSort returns a topologically sorted list of nodes
func (g *DependencyGraph) TopologicalSort() ([]string, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	inDegree := make(map[string]int)
	for node := range g.nodes {
		inDegree[node] = 0
	}

	for _, neighbors := range g.edges {
		for _, neighbor := range neighbors {
			inDegree[neighbor]++
		}
	}

	queue := make([]string, 0)
	for node, degree := range inDegree {
		if degree == 0 {
			queue = append(queue, node)
		}
	}

	result := make([]string, 0, len(g.nodes))
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		for _, neighbor := range g.edges[current] {
			inDegree[neighbor]--
			if inDegree[neighbor] == 0 {
				queue = append(queue, neighbor)
			}
		}
	}

	if len(result) != len(g.nodes) {
		return nil, fmt.Errorf("circular dependency detected")
	}

	return result, nil
}