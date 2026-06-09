package middleware

import (
	"net/http"
	"strings"
)

// RequireHTTPS rejects plain HTTP requests in production with 301 redirect to HTTPS.
// Enabled only when enforce=true — set this via environment config for production.
// Requests via a reverse proxy that sets X-Forwarded-Proto are handled correctly.
func RequireHTTPS(enforce bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enforce {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Already TLS at the transport layer
			if r.TLS != nil {
				next.ServeHTTP(w, r)
				return
			}
			// Behind a reverse proxy (nginx, Caddy, ALB) that terminates TLS
			proto := r.Header.Get("X-Forwarded-Proto")
			if strings.EqualFold(proto, "https") {
				next.ServeHTTP(w, r)
				return
			}
			// Plain HTTP — redirect permanently to same host over HTTPS.
			// G710: r.Host is the incoming Host header, not user-controlled redirect target.
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently) //nolint:gosec
		})
	}
}
