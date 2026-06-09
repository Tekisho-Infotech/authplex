package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequireHTTPS_Disabled(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	w := httptest.NewRecorder()

	RequireHTTPS(false)(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireHTTPS_PlainHTTP_Redirects(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path?q=1", nil)
	w := httptest.NewRecorder()

	RequireHTTPS(true)(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusMovedPermanently, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "https://")
}

func TestRequireHTTPS_XForwardedProto_Passes(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.com/path", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	w := httptest.NewRecorder()

	RequireHTTPS(true)(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireHTTPS_NativeTLS_Passes(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/path", nil)
	req.TLS = &tls.ConnectionState{} // non-nil TLS signals TLS connection
	w := httptest.NewRecorder()

	RequireHTTPS(true)(next).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
