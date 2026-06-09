package security_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/authplex/internal/application/security"
	"github.com/authplex/pkg/sdk/logger"
)

func newTestAlerter() *security.Alerter {
	log := logger.New("local")
	return security.NewAlerter(log)
}

func makeEvent(action domainaudit.EventType, ip, actorID string) domainaudit.Event {
	return domainaudit.Event{
		TenantID:  "tenant-1",
		ActorID:   actorID,
		Action:    action,
		IPAddress: ip,
		Timestamp: time.Now().UTC(),
	}
}

func TestAlerter_BruteForce_FiredAfterThreshold(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	for i := 0; i < 4; i++ {
		a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "1.2.3.4", "user-1"))
	}
	mu.Lock()
	before := len(fired)
	mu.Unlock()
	assert.Equal(t, 0, before, "alert should not fire before threshold")

	// 5th event crosses the threshold
	a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "1.2.3.4", "user-1"))
	mu.Lock()
	after := len(fired)
	mu.Unlock()
	require.Equal(t, 1, after)
	assert.Equal(t, security.AlertBruteForce, fired[0].Type)
	assert.Equal(t, "1.2.3.4", fired[0].IP)
}

func TestAlerter_MFABombing_FiredAfterThreshold(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.Observe(ctx, makeEvent(domainaudit.EventMFAFailed, "5.6.7.8", "user-2"))
	}

	mu.Lock()
	count := len(fired)
	mu.Unlock()
	require.Equal(t, 1, count)
	assert.Equal(t, security.AlertMFABombing, fired[0].Type)
}

func TestAlerter_OTPFlooding_FiredAfterThreshold(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.Observe(ctx, makeEvent(domainaudit.EventOTPFailed, "9.10.11.12", "user-3"))
	}

	mu.Lock()
	count := len(fired)
	mu.Unlock()
	require.Equal(t, 1, count)
	assert.Equal(t, security.AlertOTPFlooding, fired[0].Type)
}

func TestAlerter_DifferentIPs_DoNotShareCounters(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	// 4 from one IP, 4 from another — neither should fire
	for i := 0; i < 4; i++ {
		a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "10.0.0.1", "u"))
		a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "10.0.0.2", "u"))
	}

	mu.Lock()
	count := len(fired)
	mu.Unlock()
	assert.Equal(t, 0, count)
}

func TestAlerter_CredStuffing_FiredAfterThreshold(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	// 20 login failures from same IP, different users → cred stuffing
	for i := 0; i < 20; i++ {
		evt := makeEvent(domainaudit.EventLoginFailure, "203.0.113.1", "user-x")
		a.Observe(ctx, evt)
	}

	mu.Lock()
	alerts := make([]security.Alert, len(fired))
	copy(alerts, fired)
	mu.Unlock()

	// Should have brute force alert AND cred stuffing alert
	var hasCredStuffing bool
	for _, al := range alerts {
		if al.Type == security.AlertCredStuffing {
			hasCredStuffing = true
		}
	}
	assert.True(t, hasCredStuffing, "expected cred stuffing alert after 20 failures from same IP")
}

func TestAlerter_UnmonitoredEvent_DoesNotFire(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	fired := false
	a.WithHandler(func(_ context.Context, _ security.Alert) {
		fired = true
	})

	ctx := context.Background()
	a.Observe(ctx, makeEvent(domainaudit.EventLoginSuccess, "1.2.3.4", "u"))

	assert.False(t, fired, "login success should not fire any alert")
}

func TestAlerter_TokenReplay_ImmediateAlert(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	a.ObserveTokenReplay(context.Background(), "tenant-1", "client-abc", "1.1.1.1")

	mu.Lock()
	count := len(fired)
	alerts := make([]security.Alert, len(fired))
	copy(alerts, fired)
	mu.Unlock()

	require.Equal(t, 1, count)
	assert.Equal(t, security.AlertTokenReplay, alerts[0].Type)
	assert.Equal(t, "client-abc", alerts[0].ActorID)
	assert.Equal(t, "1.1.1.1", alerts[0].IP)
}

func TestAlerter_CustomThreshold(t *testing.T) {
	log := logger.New("local")
	a := security.NewAlerter(log).
		WithThreshold(domainaudit.EventLoginFailure, 2, 10*time.Minute)
	defer a.Stop()

	var mu sync.Mutex
	var fired []security.Alert
	a.WithHandler(func(_ context.Context, alert security.Alert) {
		mu.Lock()
		fired = append(fired, alert)
		mu.Unlock()
	})

	ctx := context.Background()
	a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "2.2.2.2", "u"))
	mu.Lock()
	before := len(fired)
	mu.Unlock()
	assert.Equal(t, 0, before)

	a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "2.2.2.2", "u"))
	mu.Lock()
	after := len(fired)
	mu.Unlock()
	assert.Equal(t, 1, after)
}

func TestAlerter_MultipleHandlers_AllCalled(t *testing.T) {
	a := newTestAlerter()
	defer a.Stop()

	var mu sync.Mutex
	counts := [2]int{}
	a.WithHandler(func(_ context.Context, _ security.Alert) {
		mu.Lock()
		counts[0]++
		mu.Unlock()
	})
	a.WithHandler(func(_ context.Context, _ security.Alert) {
		mu.Lock()
		counts[1]++
		mu.Unlock()
	})

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		a.Observe(ctx, makeEvent(domainaudit.EventLoginFailure, "3.3.3.3", "u"))
	}

	mu.Lock()
	c0, c1 := counts[0], counts[1]
	mu.Unlock()
	assert.Equal(t, 1, c0)
	assert.Equal(t, 1, c1)
}
