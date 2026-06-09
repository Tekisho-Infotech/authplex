package security

import (
	"context"
	"log/slog"
	"sync"
	"time"

	domainaudit "github.com/authplex/internal/domain/audit"
)

// AlertType classifies the kind of suspicious activity detected.
type AlertType string

const (
	AlertBruteForce   AlertType = "brute_force"    // repeated login failures per IP
	AlertCredStuffing AlertType = "cred_stuffing"  // login failures across many users from one IP
	AlertMFABombing   AlertType = "mfa_bombing"    // repeated MFA failures
	AlertOTPFlooding  AlertType = "otp_flooding"   // repeated OTP failures
	AlertTokenReplay  AlertType = "token_replay"   // refresh token replay detected
)

// Alert is emitted when a suspicious activity threshold is crossed.
type Alert struct {
	Type      AlertType
	TenantID  string
	ActorID   string
	IP        string
	Count     int
	Window    time.Duration
	Details   map[string]any
	Timestamp time.Time
}

// AlertHandler is called when an alert fires. Multiple handlers can be registered.
type AlertHandler func(ctx context.Context, alert Alert)

// AlertObserver is the port implemented by any component that monitors audit events
// for security threats. Using this interface instead of *Alerter breaks the concrete
// dependency between application services and the security package.
type AlertObserver interface {
	Observe(ctx context.Context, event domainaudit.Event)
	ObserveTokenReplay(ctx context.Context, tenantID, clientID, ip string)
}

// threshold defines when an alert fires.
type threshold struct {
	count  int
	window time.Duration
}

// counter tracks event occurrences in a sliding window.
type counter struct {
	mu     sync.Mutex
	events []time.Time
}

func (c *counter) record(now time.Time, window time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-window)
	var valid []time.Time
	for _, t := range c.events {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	valid = append(valid, now)
	c.events = valid
	return len(valid)
}

// Alerter observes audit events and fires alerts when suspicious patterns are detected.
// It uses in-memory sliding windows — no external dependency needed.
type Alerter struct {
	mu         sync.Mutex
	counters   map[string]*counter
	thresholds map[domainaudit.EventType]threshold
	handlers   []AlertHandler
	logger     *slog.Logger
	done       chan struct{}
	// lastFired tracks the most recent alert time per key to prevent repeated
	// goroutine fan-out on every event above threshold.
	firedMu   sync.Mutex
	lastFired map[string]time.Time
}

// NewAlerter creates a new security alerter with sensible default thresholds.
func NewAlerter(logger *slog.Logger) *Alerter {
	a := &Alerter{
		counters:  make(map[string]*counter),
		lastFired: make(map[string]time.Time),
		thresholds: map[domainaudit.EventType]threshold{
			// 5 login failures from the same IP in 10 minutes → brute force
			domainaudit.EventLoginFailure: {count: 5, window: 10 * time.Minute},
			// 5 MFA failures in 5 minutes → MFA bombing
			domainaudit.EventMFAFailed: {count: 5, window: 5 * time.Minute},
			// 5 OTP failures in 5 minutes → OTP flooding
			domainaudit.EventOTPFailed: {count: 5, window: 5 * time.Minute},
		},
		logger: logger,
		done:   make(chan struct{}),
	}
	go a.cleanup()
	return a
}

// WithHandler registers an alert handler (logger, webhook, email, etc.)
func (a *Alerter) WithHandler(h AlertHandler) *Alerter {
	a.handlers = append(a.handlers, h)
	return a
}

// WithThreshold overrides the default threshold for an event type.
func (a *Alerter) WithThreshold(event domainaudit.EventType, count int, window time.Duration) *Alerter {
	a.thresholds[event] = threshold{count: count, window: window}
	return a
}

// Observe is called for every audit event. It tracks failure counts and fires alerts.
func (a *Alerter) Observe(ctx context.Context, event domainaudit.Event) {
	th, ok := a.thresholds[event.Action]
	if !ok {
		return // not a monitored event type
	}

	// Key: event type + IP (catches distributed attacks per-IP)
	key := string(event.Action) + ":" + event.IPAddress
	c := a.getCounter(key)
	n := c.record(event.Timestamp, th.window)

	if n >= th.count && a.shouldFire(key, th.window) {
		alertType := a.alertTypeFor(event.Action)
		alert := Alert{
			Type:      alertType,
			TenantID:  event.TenantID,
			ActorID:   event.ActorID,
			IP:        event.IPAddress,
			Count:     n,
			Window:    th.window,
			Details:   event.Details,
			Timestamp: event.Timestamp,
		}
		a.fire(ctx, alert)
	}

	// Additional: cross-user credential stuffing detection
	// Many distinct users failing from the same IP is more dangerous than one user retrying
	if event.Action == domainaudit.EventLoginFailure && event.ActorID != "" {
		stuffKey := "cred_stuffing:" + event.IPAddress
		cs := a.getCounter(stuffKey)
		// Record unique user — we approximate by counting events; exact user-dedup
		// would require a set, kept simple here to avoid lock contention
		csn := cs.record(event.Timestamp, 15*time.Minute)
		if csn >= 20 && a.shouldFire(stuffKey, 15*time.Minute) {
			a.fire(ctx, Alert{
				Type:      AlertCredStuffing,
				TenantID:  event.TenantID,
				IP:        event.IPAddress,
				Count:     csn,
				Window:    15 * time.Minute,
				Timestamp: event.Timestamp,
			})
		}
	}
}

// ObserveTokenReplay fires an immediate alert — token replay is always critical.
func (a *Alerter) ObserveTokenReplay(ctx context.Context, tenantID, clientID, ip string) {
	a.fire(ctx, Alert{
		Type:      AlertTokenReplay,
		TenantID:  tenantID,
		ActorID:   clientID,
		IP:        ip,
		Count:     1,
		Window:    0,
		Timestamp: time.Now().UTC(),
	})
}

// Stop terminates the background cleanup goroutine.
func (a *Alerter) Stop() {
	close(a.done)
}

// shouldFire returns true if the alert key has not fired within its window,
// and records the current time as the last fired time. This prevents repeated
// handler invocations (and goroutine fan-out) on every event above threshold.
func (a *Alerter) shouldFire(key string, window time.Duration) bool {
	a.firedMu.Lock()
	defer a.firedMu.Unlock()
	if last, ok := a.lastFired[key]; ok && time.Since(last) < window {
		return false
	}
	a.lastFired[key] = time.Now()
	return true
}

func (a *Alerter) getCounter(key string) *counter {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.counters[key]; ok {
		return c
	}
	c := &counter{}
	a.counters[key] = c
	return c
}

func (a *Alerter) fire(ctx context.Context, alert Alert) {
	// Always log at Warn level — monitoring systems (Datadog, CloudWatch, Loki) pick this up
	a.logger.WarnContext(ctx, "security alert",
		"alert_type", alert.Type,
		"tenant_id", alert.TenantID,
		"actor_id", alert.ActorID,
		"ip", alert.IP,
		"count", alert.Count,
		"window_minutes", int(alert.Window.Minutes()),
	)

	for _, h := range a.handlers {
		h(ctx, alert)
	}
}

func (a *Alerter) alertTypeFor(event domainaudit.EventType) AlertType {
	switch event {
	case domainaudit.EventLoginFailure:
		return AlertBruteForce
	case domainaudit.EventMFAFailed:
		return AlertMFABombing
	case domainaudit.EventOTPFailed:
		return AlertOTPFlooding
	default:
		return AlertType(event)
	}
}

// cleanup purges stale counters every 15 minutes to prevent unbounded memory growth.
func (a *Alerter) cleanup() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.purgeStale()
		case <-a.done:
			return
		}
	}
}

func (a *Alerter) purgeStale() {
	a.mu.Lock()
	defer a.mu.Unlock()
	// Remove counters with no events in the last 30 minutes
	cutoff := time.Now().Add(-30 * time.Minute)
	for key, c := range a.counters {
		c.mu.Lock()
		hasRecent := false
		for _, t := range c.events {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		c.mu.Unlock()
		if !hasRecent {
			delete(a.counters, key)
		}
	}
}
