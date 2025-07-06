// Package events provides Hockeypuck-compatible event system
// This bridges between Hockeypuck's KeyChange notifications and our flexible plugin event bus
package events

import (
	"sync"
	"time"

	"github.com/dobrevit/hkp-plugin-core/pkg/hkpstorage"
	log "github.com/sirupsen/logrus"
)

// EventBus provides a unified event system compatible with Hockeypuck patterns
type EventBus struct {
	// Generic event handlers (our system)
	genericHandlers map[string][]PluginEventHandler

	// Storage notification handlers (Hockeypuck compatibility)
	keyChangeHandlers []func(hkpstorage.KeyChange) error

	mu     sync.RWMutex
	logger *log.Logger
}

// NewEventBus creates a new event bus
func NewEventBus(logger *log.Logger) *EventBus {
	return &EventBus{
		genericHandlers:   make(map[string][]PluginEventHandler),
		keyChangeHandlers: make([]func(hkpstorage.KeyChange) error, 0),
		logger:            logger,
	}
}

// PluginEvent represents a generic plugin event
type PluginEvent struct {
	Type      string                 `json:"type"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// PluginEventHandler handles plugin events
type PluginEventHandler func(event PluginEvent) error

// Event type constants aligned with Hockeypuck patterns
const (
	// Storage events (bridge to Hockeypuck KeyChange)
	EventStorageKeyAdded      = "storage.key.added"
	EventStorageKeyRemoved    = "storage.key.removed"
	EventStorageKeyReplaced   = "storage.key.replaced"
	EventStorageKeyNotChanged = "storage.key.not_changed"

	// Security events (plugin ecosystem)
	EventSecurityThreatDetected     = "security.threat.detected"
	EventSecurityAnomalyDetected    = "security.anomaly.detected"
	EventSecurityRateLimitTriggered = "security.ratelimit.triggered"
	EventSecurityRiskAssessment     = "security.risk.assessment"

	// Zero Trust events
	EventZTNAAuthenticationRequired = "ztna.authentication.required"
	EventZTNAAccessGranted          = "ztna.access.granted"
	EventZTNAAccessDenied           = "ztna.access.denied"
	EventZTNARiskScoreUpdated       = "ztna.risk.score.updated"
	EventZTNASessionCreated         = "ztna.session.created"
	EventZTNASessionTerminated      = "ztna.session.terminated"

	// Rate limiting events
	EventRateLimitViolation    = "ratelimit.violation"
	EventRateLimitThresholdHit = "ratelimit.threshold.hit"
	EventRateLimitGeoAnomaly   = "ratelimit.geo.anomaly"
	EventRateLimitMLAnomaly    = "ratelimit.ml.anomaly"

	// Endpoint protection events
	EventEndpointProtectionRequest = "endpoint.protection.request"
	EventEndpointProtectionUpdate  = "endpoint.protection.update"
	EventEndpointAccessDenied      = "endpoint.access.denied"
	EventEndpointAccessGranted     = "endpoint.access.granted"

	// Plugin coordination events
	EventPluginLoaded        = "plugin.loaded"
	EventPluginUnloaded      = "plugin.unloaded"
	EventPluginError         = "plugin.error"
	EventPluginConfigUpdated = "plugin.config.updated"
)

// PublishEvent publishes a generic plugin event
func (eb *EventBus) PublishEvent(event PluginEvent) error {
	eb.mu.RLock()
	handlers := eb.genericHandlers[event.Type]
	eb.mu.RUnlock()

	if len(handlers) == 0 {
		eb.logger.WithFields(log.Fields{
			"event_type": event.Type,
			"source":     event.Source,
		}).Debug("No handlers for event type")
		return nil
	}

	// Execute handlers
	for _, handler := range handlers {
		if err := handler(event); err != nil {
			eb.logger.WithFields(log.Fields{
				"event_type": event.Type,
				"source":     event.Source,
				"error":      err,
			}).Error("Event handler error")
		}
	}

	return nil
}

// SubscribeEvent subscribes to generic plugin events
func (eb *EventBus) SubscribeEvent(eventType string, handler PluginEventHandler) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.genericHandlers[eventType] = append(eb.genericHandlers[eventType], handler)

	eb.logger.WithFields(log.Fields{
		"event_type":    eventType,
		"handler_count": len(eb.genericHandlers[eventType]),
	}).Debug("Event handler subscribed")

	return nil
}

// SubscribeKeyChanges subscribes to Hockeypuck-style key change notifications
func (eb *EventBus) SubscribeKeyChanges(handler func(hkpstorage.KeyChange) error) error {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	eb.keyChangeHandlers = append(eb.keyChangeHandlers, handler)

	eb.logger.WithField("handler_count", len(eb.keyChangeHandlers)).Debug("Key change handler subscribed")

	return nil
}

// NotifyKeyChange notifies all key change handlers (Hockeypuck compatibility)
func (eb *EventBus) NotifyKeyChange(change hkpstorage.KeyChange) error {
	eb.mu.RLock()
	handlers := eb.keyChangeHandlers
	eb.mu.RUnlock()

	// Call Hockeypuck-style handlers
	for _, handler := range handlers {
		if err := handler(change); err != nil {
			eb.logger.WithFields(log.Fields{
				"change": change.String(),
				"error":  err,
			}).Error("Key change handler error")
		}
	}

	// Bridge to generic event system
	eventType := getEventTypeForKeyChange(change)
	if eventType != "" {
		event := PluginEvent{
			Type:      eventType,
			Source:    "storage",
			Timestamp: time.Now(),
			Data:      keyChangeToEventData(change),
		}
		return eb.PublishEvent(event)
	}

	return nil
}

// Convenience methods for common security events

// PublishThreatDetected publishes a threat detection event
func (eb *EventBus) PublishThreatDetected(threatInfo ThreatInfo) error {
	return eb.PublishEvent(PluginEvent{
		Type:      EventSecurityThreatDetected,
		Source:    threatInfo.Source,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"threat_type":        threatInfo.ThreatType,
			"severity":           threatInfo.Severity,
			"client_ip":          threatInfo.ClientIP,
			"endpoint":           threatInfo.Endpoint,
			"description":        threatInfo.Description,
			"confidence":         threatInfo.Confidence,
			"recommended_action": threatInfo.RecommendedAction,
		},
	})
}

// PublishRateLimitViolation publishes a rate limit violation event
func (eb *EventBus) PublishRateLimitViolation(violation RateLimitViolation) error {
	return eb.PublishEvent(PluginEvent{
		Type:      EventRateLimitViolation,
		Source:    violation.Source,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"client_ip":     violation.ClientIP,
			"endpoint":      violation.Endpoint,
			"limit_type":    violation.LimitType,
			"current_count": violation.CurrentCount,
			"limit":         violation.Limit,
			"window":        violation.Window,
			"action":        violation.Action,
		},
	})
}

// PublishZTNAEvent publishes a Zero Trust event
func (eb *EventBus) PublishZTNAEvent(eventType string, ztnaEvent ZTNAEvent) error {
	return eb.PublishEvent(PluginEvent{
		Type:      eventType,
		Source:    "ztna",
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"session_id":  ztnaEvent.SessionID,
			"user_id":     ztnaEvent.UserID,
			"client_ip":   ztnaEvent.ClientIP,
			"trust_level": ztnaEvent.TrustLevel,
			"risk_score":  ztnaEvent.RiskScore,
			"endpoint":    ztnaEvent.Endpoint,
			"decision":    ztnaEvent.Decision,
			"reason":      ztnaEvent.Reason,
		},
	})
}

// Helper functions for KeyChange bridge

func getEventTypeForKeyChange(change hkpstorage.KeyChange) string {
	switch change.(type) {
	case hkpstorage.KeyAdded:
		return EventStorageKeyAdded
	case hkpstorage.KeyRemoved:
		return EventStorageKeyRemoved
	case hkpstorage.KeyReplaced:
		return EventStorageKeyReplaced
	case hkpstorage.KeyNotChanged:
		return EventStorageKeyNotChanged
	default:
		return ""
	}
}

func keyChangeToEventData(change hkpstorage.KeyChange) map[string]interface{} {
	data := map[string]interface{}{
		"insert_digests": change.InsertDigests(),
		"remove_digests": change.RemoveDigests(),
		"description":    change.String(),
	}

	// Add specific fields based on change type
	switch c := change.(type) {
	case hkpstorage.KeyAdded:
		data["key_id"] = c.ID
		data["digest"] = c.Digest
	case hkpstorage.KeyRemoved:
		data["key_id"] = c.ID
		data["digest"] = c.Digest
	case hkpstorage.KeyReplaced:
		data["old_key_id"] = c.OldID
		data["old_digest"] = c.OldDigest
		data["new_key_id"] = c.NewID
		data["new_digest"] = c.NewDigest
	case hkpstorage.KeyNotChanged:
		data["key_id"] = c.ID
		data["digest"] = c.Digest
	}

	return data
}

// Event data structures

// ThreatInfo represents security threat information
type ThreatInfo struct {
	ThreatType        string  `json:"threat_type"`
	Severity          string  `json:"severity"`
	ClientIP          string  `json:"client_ip"`
	Endpoint          string  `json:"endpoint"`
	Description       string  `json:"description"`
	Confidence        float64 `json:"confidence"`
	RecommendedAction string  `json:"recommended_action"`
	Source            string  `json:"source"`
}

// RateLimitViolation represents a rate limiting violation
type RateLimitViolation struct {
	ClientIP     string `json:"client_ip"`
	Endpoint     string `json:"endpoint"`
	LimitType    string `json:"limit_type"`
	CurrentCount int    `json:"current_count"`
	Limit        int    `json:"limit"`
	Window       string `json:"window"`
	Action       string `json:"action"`
	Source       string `json:"source"`
}

// ZTNAEvent represents Zero Trust events
type ZTNAEvent struct {
	SessionID  string  `json:"session_id"`
	UserID     string  `json:"user_id"`
	ClientIP   string  `json:"client_ip"`
	TrustLevel string  `json:"trust_level"`
	RiskScore  float64 `json:"risk_score"`
	Endpoint   string  `json:"endpoint"`
	Decision   string  `json:"decision"`
	Reason     string  `json:"reason"`
}

// EndpointProtectionRequest represents endpoint protection requests
type EndpointProtectionRequest struct {
	Action      string   `json:"action"`       // "protect" or "whitelist"
	Paths       []string `json:"paths"`        // Endpoint paths
	Reason      string   `json:"reason"`       // Reason for request
	RequesterID string   `json:"requester_id"` // Plugin requesting
	Temporary   bool     `json:"temporary"`    // Whether temporary
	Duration    string   `json:"duration"`     // Duration for temporary
	Priority    int      `json:"priority"`     // Priority level
}
