package handler

import (
	"net/http"

	"github.com/authplex/internal/application/jwks"
	"github.com/authplex/internal/domain/shared"
	"github.com/authplex/pkg/sdk/httputil"
)

// JWKSHandler serves the JSON Web Key Set endpoint.
type JWKSHandler struct {
	svc *jwks.Service
}

// NewJWKSHandler creates a new JWKSHandler.
func NewJWKSHandler(svc *jwks.Service) *JWKSHandler {
	return &JWKSHandler{svc: svc}
}

// HandleJWKS serves GET /jwks.
// Uses WriteRaw because the response must match RFC 7517 exactly (no envelope).
//
// @Summary      JSON Web Key Set
// @Description  Returns the tenant's public signing keys (RFC 7517).
// @Tags         oidc
// @Produce      json
// @Param        X-Tenant-ID  header    string  false  "Tenant identifier (defaults to \"default\")"
// @Param        tenant_id    query     string  false  "Tenant identifier (alternative to header)"
// @Success      200          {object}  map[string]interface{}
// @Router       /jwks [get]
func (h *JWKSHandler) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// Tenant ID resolution: context → header → query param → "default"
	tenantID, ok := shared.TenantFromContext(r.Context())
	if !ok {
		tenantID = r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			tenantID = r.URL.Query().Get("tenant_id")
		}
		if tenantID == "" {
			tenantID = "default"
		}
	}

	set, appErr := h.svc.GetJWKS(r.Context(), tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, set) //nolint:errcheck
}
