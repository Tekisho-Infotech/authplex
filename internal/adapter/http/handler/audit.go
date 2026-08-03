package handler

import (
	"net/http"
	"strconv"

	auditsvc "github.com/authplex/internal/application/audit"
	domainaudit "github.com/authplex/internal/domain/audit"
	"github.com/authplex/pkg/sdk/httputil"
)

// AuditHandler serves audit log query endpoints.
type AuditHandler struct {
	svc *auditsvc.Service
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(svc *auditsvc.Service) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// HandleAuditLogs serves GET /tenants/{tid}/audit.
//
// @Summary      Query audit logs
// @Description  Return paginated audit events for the tenant. All parameters are optional filters.
// @Tags         audit
// @Produce      json
// @Param        tid            path   string  true   "Tenant ID"
// @Param        actor_id       query  string  false  "Filter by actor (user) ID"
// @Param        action         query  string  false  "Filter by event type (e.g. user.login)"
// @Param        resource_type  query  string  false  "Filter by resource type (e.g. client)"
// @Param        resource_id    query  string  false  "Filter by resource ID"
// @Param        limit          query  int     false  "Max results (default 50)"
// @Param        offset         query  int     false  "Pagination offset (default 0)"
// @Security     AdminAuth
// @Success      200  {object}  map[string]interface{}
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/audit [get]
func (h *AuditHandler) HandleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, httputil.MethodNotAllowed("tenant_id is required")) //nolint:errcheck
		return
	}

	limit, _ := strconv.Atoi(httputil.QueryParam(r, "limit", "50"))
	offset, _ := strconv.Atoi(httputil.QueryParam(r, "offset", "0"))

	filter := domainaudit.QueryFilter{
		TenantID:     tenantID,
		ActorID:      httputil.QueryParam(r, "actor_id", ""),
		Action:       domainaudit.EventType(httputil.QueryParam(r, "action", "")),
		ResourceType: httputil.QueryParam(r, "resource_type", ""),
		ResourceID:   httputil.QueryParam(r, "resource_id", ""),
		Limit:        limit,
		Offset:       offset,
	}

	events, appErr := h.svc.Query(r.Context(), filter)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"events": events,
		"count":  len(events),
		"offset": offset,
		"limit":  limit,
	})
}
