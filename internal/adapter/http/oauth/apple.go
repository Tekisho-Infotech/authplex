package oauth

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"
)

// GenerateAppleClientSecret creates a JWT client_secret for Apple Sign In.
// Apple requires the client_secret to be a JWT signed with the app's ES256 private key.
//
// Parameters:
//   - teamID: Apple Developer Team ID (10 chars)
//   - clientID: The Services ID or Bundle ID
//   - keyID: The Key ID from the Apple Developer portal
//   - privateKeyPEM: The .p8 private key file contents (PKCS#8 PEM)
//
// Returns a signed JWT valid for 180 days.
func GenerateAppleClientSecret(teamID, clientID, keyID string, privateKeyPEM []byte) (string, error) {
	if teamID == "" || clientID == "" || keyID == "" {
		return "", fmt.Errorf("teamID, clientID, and keyID are required")
	}

	// Parse the EC private key from PEM
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block from private key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not an EC key")
	}

	now := time.Now().UTC()

	// Build JWT header
	header := map[string]string{
		"alg": "ES256",
		"kid": keyID,
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Build JWT payload
	payload := map[string]any{
		"iss": teamID,
		"sub": clientID,
		"aud": "https://appleid.apple.com",
		"iat": now.Unix(),
		"exp": now.Add(180 * 24 * time.Hour).Unix(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Sign with ES256
	signingInput := headerB64 + "." + payloadB64
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, ecKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign Apple client secret: %w", err)
	}

	// Encode r and s as fixed-size 32-byte big-endian arrays (P-256)
	keySize := 32
	rBytes := padToSize(r.Bytes(), keySize)
	sBytes := padToSize(s.Bytes(), keySize)
	sig := append(rBytes, sBytes...) //nolint:gocritic
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// padToSize left-pads a byte slice with zeros to the given size.
func padToSize(b []byte, size int) []byte {
	if len(b) >= size {
		return b[:size]
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
