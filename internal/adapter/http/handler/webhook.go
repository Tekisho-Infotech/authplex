package handler

import (
	"net/http"

	webhooksvc "github.com/authplex/internal/application/webhook"
	"github.com/authplex/internal/domain/webhook"
	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// WebhookHandler serves the webhook management API.
type WebhookHandler struct {
	svc *webhooksvc.Service
}

// NewWebhookHandler creates a new WebhookHandler.
func NewWebhookHandler(svc *webhooksvc.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

// HandleWebhooks serves /tenants/{tid}/webhooks (POST, GET).
func (h *WebhookHandler) HandleWebhooks(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id is required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.createWebhook(w, r, tenantID)
	case http.MethodGet:
		h.listWebhooks(w, r, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleWebhook serves /tenants/{tid}/webhooks/{wid} (DELETE).
func (h *WebhookHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	webhookID := extractPathSegment(r.URL.Path, "webhooks", 1)
	if tenantID == "" || webhookID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id and webhook_id are required")) //nolint:errcheck
		return
	}

	switch r.Method {
	case http.MethodDelete:
		h.deleteWebhook(w, r, tenantID, webhookID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// createWebhook is the POST /tenants/{tid}/webhooks operation.
//
// @Summary      Create webhook
// @Description  Register a new webhook endpoint that will receive event notifications for the tenant.
// @Tags         webhooks
// @Accept       json
// @Produce      json
// @Param        tid   path      string                   true  "Tenant ID"
// @Param        body  body      map[string]interface{}  true  "Webhook details (url, events[])"
// @Security     AdminAuth
// @Success      201  {object}  webhook.Webhook
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/webhooks [post]
func (h *WebhookHandler) createWebhook(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	if req.URL == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "url is required")) //nolint:errcheck
		return
	}

	wh, err := h.svc.Create(r.Context(), tenantID, req.URL, req.Events)
	if err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, wh) //nolint:errcheck
}

// listWebhooks is the GET /tenants/{tid}/webhooks operation.
//
// @Summary      List webhooks
// @Tags         webhooks
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Security     AdminAuth
// @Success      200  {object}  map[string]interface{}
// @Router       /tenants/{tid}/webhooks [get]
func (h *WebhookHandler) listWebhooks(w http.ResponseWriter, r *http.Request, tenantID string) {
	hooks, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	if hooks == nil {
		hooks = []webhook.Webhook{}
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"webhooks": hooks,
		"count":    len(hooks),
	})
}

// deleteWebhook is the DELETE /tenants/{tid}/webhooks/{wid} operation.
//
// @Summary      Delete webhook
// @Tags         webhooks
// @Param        tid  path  string  true  "Tenant ID"
// @Param        wid  path  string  true  "Webhook ID"
// @Security     AdminAuth
// @Success      204
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/webhooks/{wid} [delete]
func (h *WebhookHandler) deleteWebhook(w http.ResponseWriter, r *http.Request, tenantID, webhookID string) {
	if err := h.svc.Delete(r.Context(), webhookID, tenantID); err != nil {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrInternal, err.Error())) //nolint:errcheck
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
