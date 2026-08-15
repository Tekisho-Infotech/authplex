package config

import (
	"os"
	"testing"

	"github.com/authplex/pkg/sdk/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	result := Load()

	assert.True(t, result.IsOk())
	cfg := result.Value()
	assert.Equal(t, "local", string(cfg.Environment))
	assert.Equal(t, 8080, cfg.HTTPPort)
	assert.Equal(t, TenantModeHeader, cfg.TenantMode)
	assert.Equal(t, "postgres", string(cfg.DatabaseDriver))
}

func TestConfig_Validate_InvalidPort(t *testing.T) {
	cfg := &Config{
		HTTPPort:       0,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "HTTP port")
}

func TestConfig_Validate_PortTooHigh(t *testing.T) {
	cfg := &Config{
		HTTPPort:       70000,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "HTTP port")
}

func TestConfig_Validate_InvalidTenantMode(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     "invalid",
		DatabaseDriver: "postgres",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "tenant mode")
}

func TestConfig_Validate_InvalidDriver(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "mysql",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "database driver")
}

func TestConfig_Validate_ValidHeader(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
		Environment:    logger.Local,
	}

	err := cfg.validate()
	assert.Nil(t, err)
}

func TestConfig_Validate_ValidDomain(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeDomain,
		DatabaseDriver: "sqlserver",
		Environment:    logger.Local,
	}

	err := cfg.validate()
	assert.Nil(t, err)
}

func TestConfig_Validate_ProductionRequiresAdminKey(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
		Environment:    logger.Production,
		AdminAPIKey:    "",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "AUTHPLEX_ADMIN_API_KEY")
}

func TestConfig_Validate_StagingRequiresAdminKey(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
		Environment:    logger.Staging,
		AdminAPIKey:    "",
	}

	err := cfg.validate()
	assert.NotNil(t, err)
	assert.Contains(t, err.Message, "AUTHPLEX_ADMIN_API_KEY")
}

func TestConfig_Validate_ProductionWithAdminKey(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
		Environment:    logger.Production,
		AdminAPIKey:    "my-prod-key",
	}

	err := cfg.validate()
	assert.Nil(t, err)
}

func TestConfig_Validate_LocalAllowsEmptyAdminKey(t *testing.T) {
	cfg := &Config{
		HTTPPort:       8080,
		TenantMode:     TenantModeHeader,
		DatabaseDriver: "postgres",
		Environment:    logger.Local,
		AdminAPIKey:    "",
	}

	err := cfg.validate()
	assert.Nil(t, err)
}

// ---------------------------------------------------------------------------
// Redis URL default — regression tests for the localhost:6379 bug
// ---------------------------------------------------------------------------

// TestLoad_RedisURL_EmptyByDefault verifies that omitting AUTHPLEX_REDIS_URL
// results in an empty string, not "redis://localhost:6379". An empty value
// causes main.go to skip the Redis connection attempt entirely and fall back
// to the Postgres-only repo setup.
func TestLoad_RedisURL_EmptyByDefault(t *testing.T) {
	t.Setenv("AUTHPLEX_REDIS_URL", "") // ensure env var is absent / blank

	result := Load()
	require.True(t, result.IsOk())
	assert.Empty(t, result.Value().RedisURL,
		"RedisURL must be empty when AUTHPLEX_REDIS_URL is not set; "+
			"a non-empty default causes spurious connections to localhost:6379 in production")
}

// TestLoad_RedisURL_FromEnv verifies that setting AUTHPLEX_REDIS_URL is
// picked up correctly so the Redis path in main.go activates.
func TestLoad_RedisURL_FromEnv(t *testing.T) {
	const redisURL = "redis://cache.internal:6379/0"
	t.Setenv("AUTHPLEX_REDIS_URL", redisURL)

	result := Load()
	require.True(t, result.IsOk())
	assert.Equal(t, redisURL, result.Value().RedisURL)
}

// TestLoad_RedisURL_NotDefaultToLocalhost is a belt-and-suspenders check:
// load config with all env vars cleared and confirm the value is not the
// old localhost default that caused the production incident.
func TestLoad_RedisURL_NotDefaultToLocalhost(t *testing.T) {
	os.Unsetenv("AUTHPLEX_REDIS_URL") //nolint:errcheck

	result := Load()
	require.True(t, result.IsOk())
	assert.NotEqual(t, "redis://localhost:6379", result.Value().RedisURL,
		"RedisURL must never default to localhost:6379")
}
