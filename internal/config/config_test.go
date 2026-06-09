package config

import (
	"testing"

	"github.com/authplex/pkg/sdk/logger"
	"github.com/stretchr/testify/assert"
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
