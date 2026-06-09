package mfa

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP RFC 6238 requires HMAC-SHA1
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	totpDigits = 6
	totpPeriod = 30 // seconds
	totpWindow = 1  // accept codes from [-1, 0, +1] time steps
)

// GenerateTOTP generates a TOTP code for the given secret and time (RFC 6238).
func GenerateTOTP(secret []byte, t time.Time) string {
	counter := uint64(t.Unix()) / totpPeriod //nolint:gosec
	return generateHOTP(secret, counter)
}

// VerifyTOTP validates a TOTP code against the secret, accepting a time window.
func VerifyTOTP(secret []byte, code string, t time.Time) bool {
	counter := uint64(t.Unix()) / totpPeriod //nolint:gosec

	for i := -totpWindow; i <= totpWindow; i++ {
		c := counter + uint64(i)
		if generateHOTP(secret, c) == code {
			return true
		}
	}
	return false
}

// generateHOTP implements HOTP (RFC 4226) — the base algorithm for TOTP.
func generateHOTP(secret []byte, counter uint64) string {
	// Step 1: Generate HMAC-SHA1
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)

	mac := hmac.New(sha1.New, secret)
	mac.Write(buf)
	h := mac.Sum(nil)

	// Step 2: Dynamic truncation
	offset := h[19] & 0x0F
	binCode := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7FFFFFFF

	// Step 3: Compute TOTP value
	otp := binCode % uint32(math.Pow10(totpDigits))

	return fmt.Sprintf("%06d", otp)
}

// BuildOTPAuthURI creates the otpauth:// URI for QR code generation.
func BuildOTPAuthURI(issuer, account, encodedSecret string) string {
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=%d&period=%d",
		issuer, account, encodedSecret, issuer, totpDigits, totpPeriod)
}
