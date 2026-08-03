package handler

import (
	"net/http"

	rbacsvc "github.com/authplex/internal/application/rbac"
	"github.com/authplex/pkg/sdk/httputil"
)

// RBACHandler serves role and assignment management endpoints.
type RBACHandler struct {
	svc *rbacsvc.Service
}

// NewRBACHandler creates a new RBACHandler.
func NewRBACHandler(svc *rbacsvc.Service) *RBACHandler {
	return &RBACHandler{svc: svc}
}

// HandleRoles serves /tenants/{tid}/roles (POST, GET).
func (h *RBACHandler) HandleRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.createRole(w, r, tenantID)
	case http.MethodGet:
		h.listRoles(w, r, tenantID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleRole serves /tenants/{tid}/roles/{rid} (GET, PUT, DELETE).
func (h *RBACHandler) HandleRole(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	roleID := extractPathSegment(r.URL.Path, "roles", 1)
	if tenantID == "" || roleID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and role_id required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getRole(w, r, tenantID, roleID)
	case http.MethodPut:
		h.updateRole(w, r, tenantID, roleID)
	case http.MethodDelete:
		h.deleteRole(w, r, tenantID, roleID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleUserRoles serves /tenants/{tid}/users/{uid}/roles (POST, GET).
func (h *RBACHandler) HandleUserRoles(w http.ResponseWriter, r *http.Request) {
	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)
	if tenantID == "" || userID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id and user_id required")) //nolint:errcheck
		return
	}
	switch r.Method {
	case http.MethodPost:
		h.assignRole(w, r, tenantID, userID)
	case http.MethodGet:
		h.listUserRoles(w, r, tenantID, userID)
	default:
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
	}
}

// HandleUserPermissions serves GET /tenants/{tid}/users/{uid}/permissions.
//
// @Summary      Get user permissions
// @Description  Return the full list of permission strings for a user, computed from their assigned roles.
// @Tags         roles
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        uid  path  string  true  "User ID"
// @Security     AdminAuth
// @Success      200  {object}  map[string][]string
// @Router       /tenants/{tid}/users/{uid}/permissions [get]
func (h *RBACHandler) HandleUserPermissions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)

	perms, appErr := h.svc.GetUserPermissions(r.Context(), userID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string][]string{"permissions": perms}) //nolint:errcheck
}

// createRole is the POST /tenants/{tid}/roles operation.
//
// @Summary      Create role
// @Description  Create a new custom role for the tenant.
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        tid   path      string                  true  "Tenant ID"
// @Param        body  body      rbac.CreateRoleRequest  true  "Role definition"
// @Security     AdminAuth
// @Success      201  {object}  rbac.Role
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/roles [post]
func (h *RBACHandler) createRole(w http.ResponseWriter, r *http.Request, tenantID string) {
	var req rbacsvc.CreateRoleRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = tenantID
	resp, appErr := h.svc.CreateRole(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck
}

// listRoles is the GET /tenants/{tid}/roles operation.
//
// @Summary      List roles
// @Tags         roles
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Security     AdminAuth
// @Success      200  {array}   rbac.Role
// @Router       /tenants/{tid}/roles [get]
func (h *RBACHandler) listRoles(w http.ResponseWriter, r *http.Request, tenantID string) {
	roles, appErr := h.svc.ListRoles(r.Context(), tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, roles) //nolint:errcheck
}

// getRole is the GET /tenants/{tid}/roles/{rid} operation.
//
// @Summary      Get role
// @Tags         roles
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        rid  path  string  true  "Role ID"
// @Security     AdminAuth
// @Success      200  {object}  rbac.Role
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/roles/{rid} [get]
func (h *RBACHandler) getRole(w http.ResponseWriter, r *http.Request, tenantID, roleID string) {
	resp, appErr := h.svc.GetRole(r.Context(), roleID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// updateRole is the PUT /tenants/{tid}/roles/{rid} operation.
//
// @Summary      Update role
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        tid   path      string                  true  "Tenant ID"
// @Param        rid   path      string                  true  "Role ID"
// @Param        body  body      rbac.UpdateRoleRequest  true  "Updated role definition"
// @Security     AdminAuth
// @Success      200  {object}  rbac.Role
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/roles/{rid} [put]
func (h *RBACHandler) updateRole(w http.ResponseWriter, r *http.Request, tenantID, roleID string) {
	var req rbacsvc.UpdateRoleRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = tenantID
	resp, appErr := h.svc.UpdateRole(r.Context(), roleID, req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// deleteRole is the DELETE /tenants/{tid}/roles/{rid} operation.
//
// @Summary      Delete role
// @Tags         roles
// @Param        tid  path  string  true  "Tenant ID"
// @Param        rid  path  string  true  "Role ID"
// @Security     AdminAuth
// @Success      204
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/roles/{rid} [delete]
func (h *RBACHandler) deleteRole(w http.ResponseWriter, r *http.Request, tenantID, roleID string) {
	if appErr := h.svc.DeleteRole(r.Context(), roleID, tenantID); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// assignRole is the POST /tenants/{tid}/users/{uid}/roles operation.
//
// @Summary      Assign role to user
// @Tags         roles
// @Accept       json
// @Produce      json
// @Param        tid   path      string                   true  "Tenant ID"
// @Param        uid   path      string                   true  "User ID"
// @Param        body  body      rbac.AssignRoleRequest   true  "Role assignment"
// @Security     AdminAuth
// @Success      201  {object}  map[string]string
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/users/{uid}/roles [post]
func (h *RBACHandler) assignRole(w http.ResponseWriter, r *http.Request, tenantID, userID string) {
	var req rbacsvc.AssignRoleRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	if appErr := h.svc.AssignRole(r.Context(), userID, req.RoleID, tenantID); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusCreated, map[string]string{"status": "assigned"}) //nolint:errcheck
}

// listUserRoles is the GET /tenants/{tid}/users/{uid}/roles operation.
//
// @Summary      List user roles
// @Tags         roles
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        uid  path  string  true  "User ID"
// @Security     AdminAuth
// @Success      200  {array}   rbac.Role
// @Router       /tenants/{tid}/users/{uid}/roles [get]
func (h *RBACHandler) listUserRoles(w http.ResponseWriter, r *http.Request, tenantID, userID string) {
	roles, appErr := h.svc.GetUserRoles(r.Context(), userID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	httputil.WriteJSON(w, http.StatusOK, roles) //nolint:errcheck
}
