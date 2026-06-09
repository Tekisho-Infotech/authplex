package token

// CNFClaim is the confirmation claim (RFC 7800) used for DPoP token binding (RFC 9449).
// JKT is the JWK Thumbprint of the client's public key.
type CNFClaim struct {
	JKT string `json:"jkt,omitempty"`
}

// Claims represents the JWT claims payload (RFC 7519 + OIDC Core 1.0).
type Claims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	JWTID     string   `json:"jti"`
	Nonce     string   `json:"nonce,omitempty"`

	// Profile claims (for id_token)
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`

	// RBAC claims
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`

	// Tenant ID for signature verification during introspection
	TenantID string `json:"tid,omitempty"`

	// Token versioning for instant revocation
	TokenVersion int `json:"tv,omitempty"`

	// Allowed API endpoints for agent tokens
	Endpoints []string `json:"endpoints,omitempty"`

	// DPoP token binding (RFC 9449) — populated when token was issued with a DPoP key
	CNF *CNFClaim `json:"cnf,omitempty"`
}

// TokenResponse is the OAuth 2.0 token response (RFC 6749 Section 5.1).
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}
