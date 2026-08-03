package handler

import (
	"net/http"
	"strconv"
	"strings"

	usersvc "github.com/authplex/internal/application/user"
	"github.com/authplex/internal/domain/shared"
	sdkerrors "github.com/authplex/pkg/sdk/errors"
	"github.com/authplex/pkg/sdk/httputil"
)

// UserHandler serves user authentication endpoints.
type UserHandler struct {
	svc *usersvc.Service
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(svc *usersvc.Service) *UserHandler {
	return &UserHandler{svc: svc}
}

// HandleRegister serves POST /register.
//
// @Summary      Register user
// @Description  Create a new user account within the resolved tenant.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header    string                true   "Tenant identifier"
// @Param        body         body      user.RegisterRequest  true   "Registration details"
// @Success      201          {object}  user.RegisterResponse
// @Failure      400          {object}  httputil.Error
// @Failure      409          {object}  httputil.Error
// @Router       /register [post]
func (h *UserHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.RegisterRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.Register(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusCreated, resp) //nolint:errcheck
}

// HandleLogin serves POST /login.
//
// @Summary      Login
// @Description  Authenticate with email and password. Returns a session token.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header    string              true   "Tenant identifier"
// @Param        body         body      user.LoginRequest   true   "Login credentials"
// @Success      200          {object}  user.LoginResponse
// @Failure      401          {object}  httputil.Error
// @Failure      429          {object}  httputil.Error
// @Router       /login [post]
func (h *UserHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.LoginRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.Login(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleLogout serves POST /logout.
//
// @Summary      Logout
// @Description  Invalidate the current session token.
// @Tags         auth
// @Produce      json
// @Param        X-Tenant-ID  header    string  true  "Tenant identifier"
// @Security     SessionAuth
// @Success      200
// @Failure      401  {object}  httputil.Error
// @Router       /logout [post]
func (h *UserHandler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	sessionToken := extractSessionToken(r)
	appErr := h.svc.Logout(r.Context(), usersvc.LogoutRequest{SessionToken: sessionToken})
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"}) //nolint:errcheck
}

// HandleUserInfo serves GET /userinfo (OIDC UserInfo endpoint).
//
// @Summary      UserInfo
// @Description  Returns claims about the authenticated user (OIDC Core §5.3). Pass the session token as a Bearer token.
// @Tags         auth
// @Produce      json
// @Param        X-Tenant-ID  header    string  true  "Tenant identifier"
// @Security     SessionAuth
// @Success      200          {object}  user.UserInfoResponse
// @Failure      401          {object}  httputil.Error
// @Router       /userinfo [get]
func (h *UserHandler) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	// Resolve user from session
	sessionToken := extractSessionToken(r)
	if sessionToken == "" {
		httputil.WriteRaw(w, http.StatusUnauthorized, map[string]string{"error": "login_required"}) //nolint:errcheck
		return
	}

	session, appErr := h.svc.ResolveSession(r.Context(), sessionToken)
	if appErr != nil {
		httputil.WriteRaw(w, http.StatusUnauthorized, map[string]string{"error": "login_required"}) //nolint:errcheck
		return
	}

	tenantID, _ := shared.TenantFromContext(r.Context())
	if tenantID == "" {
		tenantID = session.TenantID
	}

	info, appErr := h.svc.GetUserInfo(r.Context(), session.UserID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteRaw(w, http.StatusOK, info) //nolint:errcheck
}

// HandleRequestOTP serves POST /otp/request.
//
// @Summary      Request OTP
// @Description  Send a one-time password to the user's email or phone.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header    string                    true  "Tenant identifier"
// @Param        body         body      user.RequestOTPRequest    true  "OTP request"
// @Success      200          {object}  user.RequestOTPResponse
// @Failure      400          {object}  httputil.Error
// @Router       /otp/request [post]
func (h *UserHandler) HandleRequestOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.RequestOTPRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.RequestOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleVerifyOTP serves POST /otp/verify.
//
// @Summary      Verify OTP
// @Description  Verify the one-time password sent by /otp/request.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header    string                  true  "Tenant identifier"
// @Param        body         body      user.VerifyOTPRequest   true  "OTP verification"
// @Success      200
// @Failure      400  {object}  httputil.Error
// @Failure      429  {object}  httputil.Error
// @Router       /otp/verify [post]
func (h *UserHandler) HandleVerifyOTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.VerifyOTPRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.VerifyOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleResetPassword serves POST /password/reset.
//
// @Summary      Reset password
// @Description  Reset a user's password using an OTP code. Call /otp/request with purpose=reset first.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        X-Tenant-ID  header    string                      true  "Tenant identifier"
// @Param        body         body      user.ResetPasswordRequest   true  "Password reset request"
// @Success      200
// @Failure      400  {object}  httputil.Error
// @Router       /password/reset [post]
func (h *UserHandler) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req usersvc.ResetPasswordRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.ResetPassword(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"}) //nolint:errcheck
}

// HandleListUsers serves GET /tenants/{tid}/users.
//
// @Summary      List users
// @Tags         users
// @Produce      json
// @Param        tid     path      string  true   "Tenant ID"
// @Param        offset  query     int     false  "Pagination offset"
// @Param        limit   query     int     false  "Page size (default 20)"
// @Security     AdminAuth
// @Success      200  {array}   user.UserSummary
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/users [get]
func (h *UserHandler) HandleListUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	if tenantID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id is required")) //nolint:errcheck
		return
	}

	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 20
	}

	users, total, appErr := h.svc.ListUsers(r.Context(), tenantID, offset, limit)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{ //nolint:errcheck
		"users":  users,
		"count":  total,
		"offset": offset,
		"limit":  limit,
	}) //nolint:errcheck
}

// HandleUpdateUser serves PUT /tenants/{tid}/users/{uid}.
//
// @Summary      Update user
// @Description  Update a user's profile fields (name, phone, enabled status).
// @Tags         users
// @Accept       json
// @Produce      json
// @Param        tid   path      string                    true  "Tenant ID"
// @Param        uid   path      string                    true  "User ID"
// @Param        body  body      user.UpdateUserRequest    true  "Fields to update"
// @Security     AdminAuth
// @Success      200  {object}  user.UserSummary
// @Failure      400  {object}  httputil.Error
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/users/{uid} [put]
func (h *UserHandler) HandleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)

	if tenantID == "" || userID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id and user_id are required")) //nolint:errcheck
		return
	}

	var req usersvc.UpdateUserRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.UserID = userID
	req.TenantID = tenantID

	updated, appErr := h.svc.UpdateUser(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, updated) //nolint:errcheck
}

// HandlePurgeUser serves DELETE /tenants/{tid}/users/{uid}/purge (GDPR Art. 17 — right to erasure).
//
// @Summary      Purge user (GDPR)
// @Description  Permanently delete all personal data for a user. Irreversible (GDPR Art. 17).
// @Tags         users
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        uid  path  string  true  "User ID"
// @Security     AdminAuth
// @Success      200
// @Failure      400  {object}  httputil.Error
// @Router       /tenants/{tid}/users/{uid}/purge [delete]
func (h *UserHandler) HandlePurgeUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)

	if tenantID == "" || userID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id and user_id are required")) //nolint:errcheck
		return
	}

	if appErr := h.svc.PurgeUser(r.Context(), userID, tenantID); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "purged"}) //nolint:errcheck
}

// HandleExportUser serves GET /tenants/{tid}/users/{uid}/export (GDPR Art. 15/20 — right to access/portability).
//
// @Summary      Export user data (GDPR)
// @Description  Download all personal data held for a user as JSON (GDPR Art. 15/20).
// @Tags         users
// @Produce      json
// @Param        tid  path  string  true  "Tenant ID"
// @Param        uid  path  string  true  "User ID"
// @Security     AdminAuth
// @Success      200  {object}  user.UserExportResponse
// @Failure      400  {object}  httputil.Error
// @Failure      404  {object}  httputil.Error
// @Router       /tenants/{tid}/users/{uid}/export [get]
func (h *UserHandler) HandleExportUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	tenantID := extractPathSegment(r.URL.Path, "tenants", 1)
	userID := extractPathSegment(r.URL.Path, "users", 1)

	if tenantID == "" || userID == "" {
		httputil.WriteError(w, sdkerrors.New(sdkerrors.ErrBadRequest, "tenant_id and user_id are required")) //nolint:errcheck
		return
	}

	data, appErr := h.svc.ExportUserData(r.Context(), userID, tenantID)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Disposition", "attachment; filename=\"user-export.json\"")
	httputil.WriteJSON(w, http.StatusOK, data) //nolint:errcheck
}

// extractSessionToken gets the session token from Authorization header or X-Session-Token.
func extractSessionToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-Session-Token")
}
