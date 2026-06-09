package auth

// AuthorizeRequest contains the parameters for the authorization endpoint.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Subject             string // provided by upstream auth (headless)
	TenantID            string // resolved by middleware
	Nonce               string
}

// AuthorizeResponse contains the authorization code and state.
type AuthorizeResponse struct {
	Code        string
	State       string
	RedirectURI string
}

// TokenRequest contains the parameters for the token endpoint.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	TenantID     string
	// Refresh token grant
	RefreshToken string
	// Device code grant
	DeviceCode string
	// Password grant
	Username string
	Password string
	Scope    string
}

// RevokeRequest contains the parameters for token revocation (RFC 7009).
type RevokeRequest struct {
	Token         string
	TokenTypeHint string // "access_token" or "refresh_token"
	ClientID      string
	ClientSecret  string
	TenantID      string
}

// IntrospectRequest contains the parameters for token introspection (RFC 7662).
type IntrospectRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
	TenantID      string
	DPoPProof     string // RFC 9449: DPoP proof JWT from the DPoP header
	HTTPMethod    string // RFC 9449: HTTP method of the introspection request (for htm check)
	HTTPURI       string // RFC 9449: HTTP URI of the introspection request (for htu check)
}

// IntrospectResponse is the RFC 7662 introspection response.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Subject   string `json:"sub,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	JWTID     string `json:"jti,omitempty"`
}

// DeviceAuthRequest contains the parameters for device authorization (RFC 8628).
type DeviceAuthRequest struct {
	ClientID string
	Scope    string
	TenantID string
}

// DeviceAuthResponse is the device authorization response.
type DeviceAuthResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// AuthorizeDeviceRequest is used to authorize a pending device code.
type AuthorizeDeviceRequest struct {
	UserCode string
	Subject  string
	TenantID string
}
