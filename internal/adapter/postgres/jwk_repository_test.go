//go:build functional

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/authplex/internal/domain/jwk"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupPostgres(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port())
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Ping())

	// Run migration
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS jwk_pairs (
		id          TEXT PRIMARY KEY,
		tenant_id   TEXT NOT NULL,
		key_type    TEXT NOT NULL,
		algorithm   TEXT NOT NULL,
		key_use     TEXT NOT NULL DEFAULT 'sig',
		private_key BYTEA NOT NULL,
		public_key  BYTEA NOT NULL,
		active      BOOLEAN NOT NULL DEFAULT true,
		created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
		expires_at  TIMESTAMPTZ
	)`)
	require.NoError(t, err)

	cleanup := func() {
		db.Close()
		container.Terminate(ctx) //nolint:errcheck
	}

	return db, cleanup
}

func TestJWKRepository_StoreAndGetActive(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp, err := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, err)

	require.NoError(t, repo.Store(ctx, kp))

	active, err := repo.GetActive(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Equal(t, "kid-1", active.ID)
	assert.Equal(t, "tenant-1", active.TenantID)
	assert.Equal(t, jwk.RSA, active.KeyType)
	assert.True(t, active.Active)
}

func TestJWKRepository_GetActive_NotFound(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	_, err := repo.GetActive(ctx, "nonexistent")
	require.Error(t, err)
}

func TestJWKRepository_GetAllPublic(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp1, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv1"), []byte("pub1"))
	kp2, _ := jwk.NewKeyPair("kid-2", "tenant-1", jwk.EC, "ES256", []byte("priv2"), []byte("pub2"))
	require.NoError(t, repo.Store(ctx, kp1))
	require.NoError(t, repo.Store(ctx, kp2))

	pairs, err := repo.GetAllPublic(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, pairs, 2)
}

func TestJWKRepository_Deactivate(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, repo.Store(ctx, kp))

	require.NoError(t, repo.Deactivate(ctx, "kid-1"))

	_, err := repo.GetActive(ctx, "tenant-1")
	require.Error(t, err)
}

func TestJWKRepository_Deactivate_NotFound(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	err := repo.Deactivate(ctx, "nonexistent")
	require.Error(t, err)
}

// setupPostgresRLS creates jwk_pairs with the same row-level security policy as
// migrations 001 and 015, owned by a NON-superuser role, and returns a connection
// as that role. This mirrors managed Postgres (Render), where RLS is genuinely
// enforced — a superuser connection bypasses RLS entirely and hides the problem.
func setupPostgresRLS(t *testing.T) (*sql.DB, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:16-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	admin, err := sql.Open("pgx", fmt.Sprintf("postgres://test:test@%s:%s/testdb?sslmode=disable", host, port.Port()))
	require.NoError(t, err)
	require.NoError(t, admin.Ping())

	_, err = admin.Exec(`
		CREATE ROLE app_user LOGIN PASSWORD 'app_pass' NOSUPERUSER;
		CREATE TABLE jwk_pairs (
			id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id   UUID NOT NULL,
			key_type    VARCHAR(10) NOT NULL,
			algorithm   VARCHAR(10) NOT NULL,
			key_use     VARCHAR(3) NOT NULL DEFAULT 'sig',
			private_key BYTEA NOT NULL,
			public_key  BYTEA NOT NULL,
			active      BOOLEAN NOT NULL DEFAULT true,
			created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
			expires_at  TIMESTAMPTZ
		);
		ALTER TABLE jwk_pairs OWNER TO app_user;
		ALTER TABLE jwk_pairs ENABLE ROW LEVEL SECURITY;
		ALTER TABLE jwk_pairs FORCE ROW LEVEL SECURITY;
		CREATE POLICY tenant_isolation_jwk_pairs ON jwk_pairs
			USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
			WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
	`)
	require.NoError(t, err)
	require.NoError(t, admin.Close())

	db, err := sql.Open("pgx", fmt.Sprintf("postgres://app_user:app_pass@%s:%s/testdb?sslmode=disable", host, port.Port()))
	require.NoError(t, err)
	require.NoError(t, db.Ping())

	cleanup := func() {
		db.Close()
		container.Terminate(ctx) //nolint:errcheck
	}

	return db, cleanup
}

// TestJWKRepository_Store_UnderRLS proves that Store establishes the tenant
// context before inserting. Without it the RLS WITH CHECK policy rejects the row,
// leaving the tenant with no signing key and /token returning "no signing key available".
func TestJWKRepository_Store_UnderRLS(t *testing.T) {
	db, cleanup := setupPostgresRLS(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	const tenantID = "4aa2670c-2a50-5851-a4e4-f4931e6f49e5"

	// Guard: confirm RLS really is enforced for this role, so the assertion below
	// cannot pass vacuously.
	_, rawErr := db.ExecContext(ctx,
		`INSERT INTO jwk_pairs (id, tenant_id, key_type, algorithm, key_use, private_key, public_key, active, created_at)
		 VALUES ($1, $2, 'RSA', 'RS256', 'sig', $3, $4, true, now())`,
		uuid.New().String(), tenantID, []byte("priv"), []byte("pub"))
	require.Error(t, rawErr, "RLS must reject a write made without app.tenant_id")

	kid := uuid.New().String()
	kp, err := jwk.NewKeyPair(kid, tenantID, jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, err)

	require.NoError(t, repo.Store(ctx, kp), "Store must set tenant context so the RLS policy passes")

	active, err := repo.GetActive(ctx, tenantID)
	require.NoError(t, err)
	assert.Equal(t, kid, active.ID)
	assert.Equal(t, tenantID, active.TenantID)
}

// TestJWKRepository_GetAllPublic_UnderRLS proves the /jwks read path sets the tenant
// context. Without it the tenant_isolation USING clause filters every row out and the
// endpoint returns {"keys":[]} even though the signing key exists and can sign JWTs.
func TestJWKRepository_GetAllPublic_UnderRLS(t *testing.T) {
	db, cleanup := setupPostgresRLS(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	const tenantID = "4aa2670c-2a50-5851-a4e4-f4931e6f49e5"

	kid := uuid.New().String()
	kp, err := jwk.NewKeyPair(kid, tenantID, jwk.RSA, "RS256", []byte("priv"), []byte("pub"))
	require.NoError(t, err)
	require.NoError(t, repo.Store(ctx, kp))

	pairs, err := repo.GetAllPublic(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, pairs, 1, "GetAllPublic must set tenant context so RLS does not hide the key")

	// The JWKS "kid" is projected from this ID, and the JWT header carries the same
	// value via signer.Sign(claims, kp.ID, ...) — they must agree.
	assert.Equal(t, kid, pairs[0].ID)
	assert.Equal(t, tenantID, pairs[0].TenantID)
	assert.True(t, pairs[0].Active)
	assert.Equal(t, []byte("pub"), pairs[0].PublicKey)
}

// TestJWKRepository_GetAllPublic_UnderRLS_TenantIsolation confirms the tenant context
// scopes the read rather than disabling the policy — one tenant never sees another's key.
func TestJWKRepository_GetAllPublic_UnderRLS_TenantIsolation(t *testing.T) {
	db, cleanup := setupPostgresRLS(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	const tenantA = "4aa2670c-2a50-5851-a4e4-f4931e6f49e5"
	const tenantB = "6b13f81e-1c4d-4a2b-9f3e-2d5c8a7b4e10"

	kidA := uuid.New().String()
	kpA, err := jwk.NewKeyPair(kidA, tenantA, jwk.RSA, "RS256", []byte("privA"), []byte("pubA"))
	require.NoError(t, err)
	require.NoError(t, repo.Store(ctx, kpA))

	kpB, err := jwk.NewKeyPair(uuid.New().String(), tenantB, jwk.RSA, "RS256", []byte("privB"), []byte("pubB"))
	require.NoError(t, err)
	require.NoError(t, repo.Store(ctx, kpB))

	pairs, err := repo.GetAllPublic(ctx, tenantA)
	require.NoError(t, err)
	require.Len(t, pairs, 1)
	assert.Equal(t, kidA, pairs[0].ID)
}

func TestJWKRepository_TenantIsolation(t *testing.T) {
	db, cleanup := setupPostgres(t)
	defer cleanup()

	repo := NewJWKRepository(db)
	ctx := context.Background()

	kp1, _ := jwk.NewKeyPair("kid-1", "tenant-1", jwk.RSA, "RS256", []byte("priv1"), []byte("pub1"))
	kp2, _ := jwk.NewKeyPair("kid-2", "tenant-2", jwk.RSA, "RS256", []byte("priv2"), []byte("pub2"))
	require.NoError(t, repo.Store(ctx, kp1))
	require.NoError(t, repo.Store(ctx, kp2))

	pairs, err := repo.GetAllPublic(ctx, "tenant-1")
	require.NoError(t, err)
	assert.Len(t, pairs, 1)
	assert.Equal(t, "kid-1", pairs[0].ID)
}
