package handler

import (
	"net/http"
	"strconv"
	"strings"

	clientsvc "github.com/authplex/internal/application/client"
	"github.com/authplex/pkg/sdk/httputil"
)

// ClientHandler serves the client management API.
type ClientHandler struct {
	svc *clientsvc.Service
}

// NewClientHandler creates a new ClientHandler.
func NewClientHandler(svc *clientsvc.Service) *ClientHandler {
	return &ClientHandler{svc: svc}
}

// HandleClients serves /tenants/{tenant_id}/clients (POST, GET).
func (h *ClientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.createClient(w, r, tenantID)
	case http.MethodGet:
		h.listClients(w, r, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// createClient is the POST /tenants/{tid}/clients operation.
//
// @Summary      Create client
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        tid   path      string                        true  "Tenant ID"
// @Param        body  body      client.CreateClientRequest    true  "Client definition"
// @Security     AdminAuth
// @Success      201  {object}  client.ClientResponse
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/clients [post]
func (h *ClientHandler) createClient(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req clientsvc.CreateClientRequest
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

// listClients is the GET /tenants/{tid}/clients operation.
//
// @Summary      List clients
// @Tags         clients
// @Produce      json
// @Param        tid     path      string  true   "Tenant ID"
// @Param        offset  query     int     false  "Pagination offset"
// @Param        limit   query     int     false  "Page size (default 20)"
// @Security     AdminAuth
// @Success      200  {array}   client.ClientResponse
// @Router       /tenants/{tid}/clients [get]
func (h *ClientHandler) listClients(w http.ResponseWriter, r *http.Request, tenantID string) {
	offset, _ := strconv.Atoi(httputil.QueryParam(r, "offset", "0"))
	limit, _ := strconv.Atoi(httputil.QueryParam(r, "limit", "20"))
	clients, total, appErr := h.svc.List(r.Context(), tenantID, offset, limit)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"clients": clients, "total": total, "offset": offset, "limit": limit,
	})
}

// HandleClient serves /tenants/{tenant_id}/clients/{client_id} (GET, PUT, DELETE).
func (h *ClientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	clientID := extractPathSegment(r.URL.Path, "clients", 1)
	if tenantID == "" || clientID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and client_id are required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getClient(w, r, clientID, tenantID)
	case http.MethodPut:
		h.updateClient(w, r, clientID, tenantID)
	case http.MethodDelete:
		h.deleteClient(w, r, clientID, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// getClient is the GET /tenants/{tid}/clients/{cid} operation.
//
// @Summary      Get client
// @Tags         clients
// @Produce      json
// @Param        tid  path      string  true  "Tenant ID"
// @Param        cid  path      string  true  "Client ID"
// @Security     AdminAuth
// @Success      200  {object}  client.ClientResponse
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/clients/{cid} [get]
func (h *ClientHandler) getClient(w http.ResponseWriter, r *http.Request, clientID, tenantID string) {
	resp, appErr := h.svc.Get(r.Context(), clientID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// updateClient is the PUT /tenants/{tid}/clients/{cid} operation.
//
// @Summary      Update client
// @Tags         clients
// @Accept       json
// @Produce      json
// @Param        tid   path      string                        true  "Tenant ID"
// @Param        cid   path      string                        true  "Client ID"
// @Param        body  body      client.UpdateClientRequest    true  "Fields to update"
// @Security     AdminAuth
// @Success      200  {object}  client.ClientResponse
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/clients/{cid} [put]
func (h *ClientHandler) updateClient(w http.ResponseWriter, r *http.Request, clientID, tenantID string) {
	var req clientsvc.UpdateClientRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = tenantID
	resp, appErr := h.svc.Update(r.Context(), clientID, req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// deleteClient is the DELETE /tenants/{tid}/clients/{cid} operation.
//
// @Summary      Delete client
// @Tags         clients
// @Param        tid  path  string  true  "Tenant ID"
// @Param        cid  path  string  true  "Client ID"
// @Security     AdminAuth
// @Success      204
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/clients/{cid} [delete]
func (h *ClientHandler) deleteClient(w http.ResponseWriter, r *http.Request, clientID, tenantID string) {
	if appErr := h.svc.Delete(r.Context(), clientID, tenantID); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// HandleAPIKey serves POST /tenants/{tenant_id}/clients/{client_id}/api-key.
// Generates a new non-expiring API key for the client. Returns the raw key once.
//
// @Summary      Generate API key
// @Description  Generate a non-expiring API key for a client. The raw key is returned once and cannot be retrieved again.
// @Tags         clients
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        cid  path  string  true  "Client ID"
// @Security     AdminAuth
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/clients/{cid}/api-key [post]
func (h *ClientHandler) HandleAPIKey(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	clientID := extractPathSegment(r.URL.Path, "clients", 1)
	if tenantID == "" || clientID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and client_id are required")) //nolint:errcheck
		return
	}

	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	rawKey, appErr := h.svc.GenerateAPIKey(r.Context(), clientID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"api_key": rawKey,
	})
}

// extractPathSegment extracts the segment after the given key in a URL path.
// e.g., extractPathSegment("/tenants/t1/clients/c1", "tenants", 1) returns "t1"
func extractPathSegment(path, key string, offset int) string {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for i, part := range parts {
		if part == key && i+offset < len(parts) {
			return parts[i+offset]
		}
	}
	return ""
}
