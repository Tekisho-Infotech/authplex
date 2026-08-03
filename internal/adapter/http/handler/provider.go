package handler

import (
	"net/http"

	providersvc "github.com/authplex/internal/application/provider"
	"github.com/authplex/pkg/sdk/httputil"
)

// ProviderHandler serves the identity provider management API.
type ProviderHandler struct {
	svc *providersvc.Service
}

// NewProviderHandler creates a new ProviderHandler.
func NewProviderHandler(svc *providersvc.Service) *ProviderHandler {
	return &ProviderHandler{svc: svc}
}

// HandleProviders serves /tenants/{tenant_id}/providers (POST, GET).
func (h *ProviderHandler) HandleProviders(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.createProvider(w, r, tenantID)
	case http.MethodGet:
		h.listProviders(w, r, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleProvider serves /tenants/{tenant_id}/providers/{provider_id} (GET, DELETE).
func (h *ProviderHandler) HandleProvider(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	providerID := extractPathSegment(r.URL.Path, "providers", 1)
	if tenantID == "" || providerID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and provider_id are required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getProvider(w, r, tenantID, providerID)
	case http.MethodDelete:
		h.deleteProvider(w, r, tenantID, providerID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// createProvider is the POST /tenants/{tid}/providers operation.
//
// @Summary      Create provider
// @Description  Create a new identity provider configuration for the tenant.
// @Tags         providers
// @Accept       json
// @Produce      json
// @Param        tid   path      string                          true  "Tenant ID"
// @Param        body  body      provider.CreateProviderRequest  true  "Provider configuration"
// @Security     AdminAuth
// @Success      201  {object}  provider.ProviderResponse
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/providers [post]
func (h *ProviderHandler) createProvider(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req providersvc.CreateProviderRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = tenantID
	created, appErr := h.svc.Create(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, created) //nolint:errcheck
}

// listProviders is the GET /tenants/{tid}/providers operation.
//
// @Summary      List providers
// @Description  List all identity providers configured for the tenant.
// @Tags         providers
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Security     AdminAuth
// @Success      200  {array}   provider.ProviderResponse
// @Router       /tenants/{tid}/providers [get]
func (h *ProviderHandler) listProviders(w http.ResponseWriter, r *http.Request, tenantID string) {
	providers, appErr := h.svc.List(r.Context(), tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, providers) //nolint:errcheck
}

// getProvider is the GET /tenants/{tid}/providers/{pid} operation.
//
// @Summary      Get provider
// @Tags         providers
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        pid  path  string  true  "Provider ID"
// @Security     AdminAuth
// @Success      200  {object}  provider.ProviderResponse
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/providers/{pid} [get]
func (h *ProviderHandler) getProvider(w http.ResponseWriter, r *http.Request, tenantID, providerID string) {
	resp, appErr := h.svc.Get(r.Context(), providerID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// deleteProvider is the DELETE /tenants/{tid}/providers/{pid} operation.
//
// @Summary      Delete provider
// @Tags         providers
// @Param        tid  path  string  true  "Tenant ID"
// @Param        pid  path  string  true  "Provider ID"
// @Security     AdminAuth
// @Success      204
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/providers/{pid} [delete]
func (h *ProviderHandler) deleteProvider(w http.ResponseWriter, r *http.Request, tenantID, providerID string) {
	if appErr := h.svc.Delete(r.Context(), providerID, tenantID); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
