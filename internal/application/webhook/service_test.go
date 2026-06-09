package webhook

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	domainwebhook "github.com/authplex/internal/domain/webhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockWebhookRepo struct {
	hooks map[string]domainwebhook.Webhook
}

func newMockWebhookRepo() *mockWebhookRepo {
	return &mockWebhookRepo{hooks: make(map[string]domainwebhook.Webhook)}
}

func (m *mockWebhookRepo) Create(_ context.Context, w domainwebhook.Webhook) error {
	m.hooks[w.ID] = w
	return nil
}

func (m *mockWebhookRepo) GetByID(_ context.Context, id, tenantID string) (domainwebhook.Webhook, error) {
	w, ok := m.hooks[id]
	if !ok || w.TenantID != tenantID {
		return domainwebhook.Webhook{}, errors.New("not found")
	}
	return w, nil
}

func (m *mockWebhookRepo) List(_ context.Context, tenantID string) ([]domainwebhook.Webhook, error) {
	var result []domainwebhook.Webhook
	for _, w := range m.hooks {
		if w.TenantID == tenantID {
			result = append(result, w)
		}
	}
	return result, nil
}

func (m *mockWebhookRepo) Delete(_ context.Context, id, tenantID string) error {
	w, ok := m.hooks[id]
	if !ok || w.TenantID != tenantID {
		return errors.New("not found")
	}
	delete(m.hooks, id)
	return nil
}

func (m *mockWebhookRepo) ListByEvent(_ context.Context, tenantID, eventType string) ([]domainwebhook.Webhook, error) {
	var result []domainwebhook.Webhook
	for _, w := range m.hooks {
		if w.TenantID != tenantID || !w.Enabled {
			continue
		}
		for _, e := range w.Events {
			if e == eventType {
				result = append(result, w)
				break
			}
		}
	}
	return result, nil
}

type errListByEventRepo struct {
	*mockWebhookRepo
}

func (e *errListByEventRepo) ListByEvent(_ context.Context, _, _ string) ([]domainwebhook.Webhook, error) {
	return nil, errors.New("db unavailable")
}

// --- Tests ---

func TestWebhookSvc_Create(t *testing.T) {
	svc := NewService(newMockWebhookRepo(), slog.Default())
	w, err := svc.Create(context.Background(), "t1", "https://example.com/hook", []string{"login_success"})
	require.NoError(t, err)
	assert.NotEmpty(t, w.ID)
	assert.NotEmpty(t, w.Secret)
	assert.Equal(t, "t1", w.TenantID)
	assert.True(t, w.Enabled)
}

func TestWebhookSvc_List(t *testing.T) {
	svc := NewService(newMockWebhookRepo(), slog.Default())

	_, err := svc.Create(context.Background(), "t1", "https://a.com", []string{"login_success"})
	require.NoError(t, err)
	_, err = svc.Create(context.Background(), "t1", "https://b.com", []string{"register"})
	require.NoError(t, err)

	hooks, err := svc.List(context.Background(), "t1")
	require.NoError(t, err)
	assert.Len(t, hooks, 2)
}

func TestWebhookSvc_Delete(t *testing.T) {
	svc := NewService(newMockWebhookRepo(), slog.Default())

	w, err := svc.Create(context.Background(), "t1", "https://c.com", []string{"login_success"})
	require.NoError(t, err)

	err = svc.Delete(context.Background(), w.ID, "t1")
	require.NoError(t, err)

	hooks, err := svc.List(context.Background(), "t1")
	require.NoError(t, err)
	assert.Empty(t, hooks)
}

func TestWebhookSvc_Deliver_Success(t *testing.T) {
	received := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		received <- struct{}{}
	}))
	defer ts.Close()

	svc := NewService(newMockWebhookRepo(), slog.Default())
	hook, err := svc.Create(context.Background(), "t1", ts.URL, []string{"login_success"})
	require.NoError(t, err)
	_ = hook

	svc.Deliver(context.Background(), "t1", "login_success", map[string]any{"user": "u1"})

	select {
	case <-received:
		// delivery succeeded
	case <-time.After(3 * time.Second):
		t.Fatal("webhook delivery not received within timeout")
	}
}

func TestWebhookSvc_Deliver_ListError(t *testing.T) {
	svc := NewService(&errListByEventRepo{newMockWebhookRepo()}, slog.Default())
	// Should not panic — Deliver logs and returns
	svc.Deliver(context.Background(), "t1", "login_success", map[string]any{})
}

func TestWebhookSvc_Deliver_Non2xx(t *testing.T) {
	done := make(chan struct{}, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		done <- struct{}{}
	}))
	defer ts.Close()

	svc := NewService(newMockWebhookRepo(), slog.Default())
	_, err := svc.Create(context.Background(), "t1", ts.URL, []string{"register"})
	require.NoError(t, err)

	svc.Deliver(context.Background(), "t1", "register", map[string]any{"user": "u2"})

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("webhook delivery goroutine did not complete")
	}
}

func TestWebhookSvc_Deliver_BadURL(t *testing.T) {
	repo := newMockWebhookRepo()
	repo.hooks["h1"] = domainwebhook.Webhook{
		ID:       "h1",
		TenantID: "t1",
		URL:      "://bad-url",
		Secret:   "sec",
		Events:   []string{"login_success"},
		Enabled:  true,
	}
	svc := NewService(repo, slog.Default())
	// Should not panic — delivers in goroutine, logs error, returns
	svc.Deliver(context.Background(), "t1", "login_success", map[string]any{})
	time.Sleep(100 * time.Millisecond)
}

func TestSign(t *testing.T) {
	sig1 := sign("secret", []byte("hello"))
	sig2 := sign("secret", []byte("hello"))
	assert.Equal(t, sig1, sig2)
	assert.Contains(t, sig1, "sha256=")

	sig3 := sign("other-secret", []byte("hello"))
	assert.NotEqual(t, sig1, sig3)
}
