package handler

import (
	"net/http"

	mfasvc "github.com/authplex/internal/application/mfa"
	"github.com/authplex/pkg/sdk/httputil"
)

// MFAHandler serves MFA endpoints.
type MFAHandler struct {
	svc *mfasvc.Service
}

// NewMFAHandler creates a new MFAHandler.
func NewMFAHandler(svc *mfasvc.Service) *MFAHandler {
	return &MFAHandler{svc: svc}
}

// HandleEnroll serves POST /mfa/totp/enroll.
//
// @Summary      Enroll TOTP
// @Description  Begin TOTP MFA enrollment. Returns a secret and QR code to scan with an authenticator app. Confirm enrollment with /mfa/totp/confirm.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfa.EnrollRequest  true  "Enroll request"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/totp/enroll [post]
func (h *MFAHandler) HandleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.EnrollRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.EnrollTOTP(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, resp) //nolint:errcheck
}

// HandleConfirm serves POST /mfa/totp/confirm.
//
// @Summary      Confirm TOTP enrollment
// @Description  Verify the first TOTP code from the authenticator app to activate enrollment.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfa.VerifyRequest  true  "Confirm request"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/totp/confirm [post]
func (h *MFAHandler) HandleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.VerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.ConfirmTOTP(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "confirmed"}) //nolint:errcheck
}

// HandleVerify serves POST /mfa/verify — completes an MFA challenge.
//
// @Summary      Verify MFA challenge
// @Description  Complete an MFA challenge (TOTP or WebAuthn) during authorization. Returns an authorization code on success.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfa.MFAVerifyRequest  true  "MFA verify request"
// @Success      200   {object}  map[string]string
// @Failure      401   {object}  httputil.Error
// @Failure      429   {object}  httputil.Error
// @Router       /mfa/verify [post]
func (h *MFAHandler) HandleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.MFAVerifyRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	resp, appErr := h.svc.VerifyMFA(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{ //nolint:errcheck
		"code":  resp.Code,
		"state": resp.State,
	})
}

// HandleWebAuthnRegisterBegin serves POST /mfa/webauthn/register/begin.
//
// @Summary      Begin WebAuthn registration
// @Description  Start WebAuthn authenticator registration. Returns PublicKeyCredentialCreationOptions (W3C WebAuthn spec).
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfa.WebAuthnRegisterRequest  true  "Register request"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/webauthn/register/begin [post]
func (h *MFAHandler) HandleWebAuthnRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnRegisterRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.BeginWebAuthnRegistration(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp) //nolint:errcheck
}

// HandleWebAuthnRegisterFinish serves POST /mfa/webauthn/register/finish.
//
// @Summary      Finish WebAuthn registration
// @Description  Complete WebAuthn authenticator registration by posting the credential response.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      map[string]interface{}  true  "Credential response from authenticator ({subject, response})"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/webauthn/register/finish [post]
func (h *MFAHandler) HandleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnRegisterFinishRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	if appErr := h.svc.FinishWebAuthnRegistration(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "registered"}) //nolint:errcheck
}

// HandleWebAuthnLoginBegin serves POST /mfa/webauthn/login/begin.
//
// @Summary      Begin WebAuthn login
// @Description  Start WebAuthn authentication. Returns PublicKeyCredentialRequestOptions (W3C WebAuthn spec).
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      mfa.WebAuthnLoginRequest  true  "Login request"
// @Success      200   {object}  map[string]interface{}
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/webauthn/login/begin [post]
func (h *MFAHandler) HandleWebAuthnLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnLoginRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}
	req.TenantID = resolveTenantID(r)

	resp, appErr := h.svc.BeginWebAuthnLogin(r.Context(), req)
	if appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp) //nolint:errcheck
}

// HandleWebAuthnLoginFinish serves POST /mfa/webauthn/login/finish.
//
// @Summary      Finish WebAuthn login
// @Description  Complete WebAuthn authentication by posting the credential assertion.
// @Tags         mfa
// @Accept       json
// @Produce      json
// @Param        body  body      map[string]interface{}  true  "Credential assertion from authenticator ({challenge_id, response})"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  httputil.Error
// @Router       /mfa/webauthn/login/finish [post]
func (h *MFAHandler) HandleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httputil.WriteError(w, httputil.MethodNotAllowed(r.Method)) //nolint:errcheck
		return
	}

	var req mfasvc.WebAuthnLoginFinishRequest
	if appErr := httputil.DecodeJSON(r, &req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	if appErr := h.svc.FinishWebAuthnLogin(r.Context(), req); appErr != nil {
		httputil.WriteError(w, appErr) //nolint:errcheck
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]string{"status": "verified"}) //nolint:errcheck
}
