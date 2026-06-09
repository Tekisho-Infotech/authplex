package token

// Signer creates signed JWT strings from claims.
type Signer interface {
	Sign(claims Claims, kid string, privateKeyPEM []byte, algorithm string) (string, error)
	// SignRaw signs an arbitrary JSON-marshalable payload as a JWT.
	// Use this when the payload type differs from Claims (e.g., admin tokens with extra fields).
	SignRaw(payload any, kid string, privateKeyPEM []byte, algorithm string) (string, error)
}
