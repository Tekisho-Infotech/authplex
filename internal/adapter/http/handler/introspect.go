package handler

import (
	"net/http"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/pkg/sdk/httputil"
)

// IntrospectHandler serves the token introspection endpoint (RFC 7662).
type IntrospectHandler struct {
	svc *auth.Service
}

// NewIntrospectHandler creates a new IntrospectHandler.
func NewIntrospectHandler(svc *auth.Service) *IntrospectHandler {
	return &IntrospectHandler{svc: svc}
}

// HandleIntrospect serves POST /introspect.
//
// @Summary      Token introspection
// @Description  Determine the active state and metadata of a token (RFC 7662).
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        X-Tenant-ID      header    string  true   "Tenant identifier"
// @Param        token            formData  string  true   "Token to introspect"
// @Param        token_type_hint  formData  string  false  "Token type hint"
// @Param        client_id        formData  string  false  "Client ID"
// @Param        client_secret    formData  string  false  "Client secret"
// @Success      200              {object}  map[string]interface{}
// @Router       /introspect [post]
func (h *IntrospectHandler) HandleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid form body")) //nolint:errcheck
		return
	}

	req := auth.IntrospectRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
		TenantID:      resolveTenantID(r),
		DPoPProof:     r.Header.Get("DPoP"),
		HTTPMethod:    r.Method,
		HTTPURI:       r.URL.String(),
	}

	resp, appErr := h.svc.Introspect(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, resp) //nolint:errcheck
}
