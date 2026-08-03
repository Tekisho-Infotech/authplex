package handler

import (
	"net/http"

	"github.com/authplex/internal/application/auth"
	"github.com/authplex/pkg/sdk/httputil"
)

// DeviceHandler serves the device authorization endpoint (RFC 8628).
type DeviceHandler struct {
	svc *auth.Service
}

// NewDeviceHandler creates a new DeviceHandler.
func NewDeviceHandler(svc *auth.Service) *DeviceHandler {
	return &DeviceHandler{svc: svc}
}

// HandleDeviceAuthorize serves POST /device/authorize.
//
// @Summary      Device authorization
// @Description  Initiate the OAuth 2.0 Device Authorization Grant (RFC 8628). Poll /token with grant_type=urn:ietf:params:oauth:grant-type:device_code.
// @Tags         oidc
// @Accept       application/x-www-form-urlencoded
// @Produce      json
// @Param        X-Tenant-ID  header    string  true   "Tenant identifier"
// @Param        client_id    formData  string  true   "Client ID"
// @Param        scope        formData  string  false  "Requested scopes"
// @Success      200          {object}  map[string]interface{}
// @Failure      400          {object}  httputil.Error
// @Router       /device/authorize [post]
func (h *DeviceHandler) HandleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	if err := r.ParseForm(); err != nil {
		httputil.WriteError(w, httputil.MethodNotAllowed("invalid form body")) //nolint:errcheck
		return
	}

	req := auth.DeviceAuthRequest{
		ClientID: r.FormValue("client_id"),
		Scope:    r.FormValue("scope"),
		TenantID: resolveTenantID(r),
	}

	resp, appErr := h.svc.InitiateDeviceAuth(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, resp) //nolint:errcheck
}
