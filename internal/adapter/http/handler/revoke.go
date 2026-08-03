package handler

import (
	"net/http"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/pkg/sdk/httputil"
)

// RevokeHandler serves the token revocation endpoint (RFC 7009).
type RevokeHandler struct {
	svc *auth.Service
}

// NewRevokeHandler creates a new RevokeHandler.
func NewRevokeHandler(svc *auth.Service) *RevokeHandler {
	return &RevokeHandler{svc: svc}
}

// HandleRevoke serves POST /revoke.
//
// @Summary      Token revocation
// @Description  Revoke an access or refresh token (RFC 7009). Always returns 200 per spec.
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Param        X-Tenant-ID      header    string  false  "Tenant identifier (optional)"
// @Param        token            formData  string  true   "Token to revoke"
// @Param        token_type_hint  formData  string  false  "Token type hint"  Enums(access_token, refresh_token)
// @Param        client_id        formData  string  false  "Client ID"
// @Param        client_secret    formData  string  false  "Client secret"
// @Success      200
// @Router       /revoke [post]
func (h *RevokeHandler) HandleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid form body")) //nolint:errcheck
		return
	}

	req := auth.RevokeRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
		TenantID:      resolveTenantID(r),
	}

	appErr := h.svc.Revoke(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	// RFC 7009: always return 200
	w.WriteHeader(http.StatusOK)
}
