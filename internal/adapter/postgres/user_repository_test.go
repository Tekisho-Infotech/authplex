//go:build functional

package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/authplex/internal/domain/user"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupUsersDB spins up a Postgres container, creates the users table with RLS
// enforced for all roles (including superuser), and returns a ready *sql.DB.
func setupUsersDB(t *testing.T) (*sql.DB, func()) {
	t.Helper()

	db, cleanup := setupPostgres(t)

	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id             UUID PRIMARY KEY,
			tenant_id      UUID NOT NULL,
			email          VARCHAR(254) NOT NULL,
			phone          VARCHAR(30)  NOT NULL DEFAULT '',
			password_hash  BYTEA        NOT NULL DEFAULT '',
			name           VARCHAR(200) NOT NULL DEFAULT '',
			email_verified BOOLEAN      NOT NULL DEFAULT false,
			phone_verified BOOLEAN      NOT NULL DEFAULT false,
			enabled        BOOLEAN      NOT NULL DEFAULT true,
			token_version  INTEGER      NOT NULL DEFAULT 1,
			created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
			updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
			deleted_at     TIMESTAMPTZ,
			UNIQUE(tenant_id, email)
		);

		ALTER TABLE users ENABLE ROW LEVEL SECURITY;

		-- FORCE applies the policy even to the superuser role used by tests,
		-- which is the same condition the production app role operates under.
		ALTER TABLE users FORCE ROW LEVEL SECURITY;

		-- current_setting with missing_ok=true returns NULL when app.tenant_id
		-- is not set; NULL = tenant_id is never true, so the row is blocked.
		CREATE POLICY users_tenant_rls ON users
			USING     (tenant_id::text = current_setting('app.tenant_id', true))
			WITH CHECK(tenant_id::text = current_setting('app.tenant_id', true));
	`)
	require.NoError(t, err)

	return db, cleanup
}

// newTestUser builds a minimal valid user with a deterministic ID.
func newTestUser(id, tenantID, email string) user.User {
	u, err := user.NewUser(id, tenantID, email, "Test User")
	if err != nil {
		panic(err)
	}
	u.PasswordHash = []byte("hashed-password")
	return u
}

// ---------------------------------------------------------------------------
// RLS enforcement proof
// ---------------------------------------------------------------------------

// TestUserRepository_RLSEnforced verifies that a raw INSERT without setting
// app.tenant_id is rejected by the RLS policy. This confirms the policy is
// active so that subsequent tests are meaningful.
func TestUserRepository_RLSEnforced(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	id := uuid.New().String()
	tenantID := uuid.New().String()

	_, err := db.ExecContext(context.Background(), `
		INSERT INTO users (id, tenant_id, email, password_hash, name)
		VALUES ($1, $2, 'rls-test@example.com', 'hash', 'Test')`,
		id, tenantID,
	)
	require.Error(t, err, "INSERT without app.tenant_id should be blocked by RLS")
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

func TestUserRepository_Create_SetsRLSContext(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "alice@example.com")

	// WithTenantTx inside Create sets app.tenant_id — policy must permit this.
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByID(ctx, u.ID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, tenantID, got.TenantID)
	assert.Equal(t, "alice@example.com", got.Email)
	assert.True(t, got.Enabled)
}

func TestUserRepository_Create_DuplicateEmail_ReturnsError(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u1 := newTestUser(uuid.New().String(), tenantID, "dup@example.com")
	u2 := newTestUser(uuid.New().String(), tenantID, "dup@example.com")

	require.NoError(t, repo.Create(ctx, u1))
	require.Error(t, repo.Create(ctx, u2), "duplicate email within tenant should fail")
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

func TestUserRepository_GetByEmail(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "bob@example.com")
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByEmail(ctx, "bob@example.com", tenantID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
}

func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	_, err := repo.GetByEmail(context.Background(), "nobody@example.com", uuid.New().String())
	require.Error(t, err)
}

func TestUserRepository_GetByPhone(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "carol@example.com")
	u.Phone = "+15550001234"
	require.NoError(t, repo.Create(ctx, u))

	got, err := repo.GetByPhone(ctx, "+15550001234", tenantID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func TestUserRepository_Update_SetsRLSContext(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "dave@example.com")
	require.NoError(t, repo.Create(ctx, u))

	u.Name = "Dave Updated"
	u.EmailVerified = true
	// WithTenantTx inside Update sets app.tenant_id — must not be blocked.
	require.NoError(t, repo.Update(ctx, u))

	got, err := repo.GetByID(ctx, u.ID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, "Dave Updated", got.Name)
	assert.True(t, got.EmailVerified)
}

// ---------------------------------------------------------------------------
// Delete (soft)
// ---------------------------------------------------------------------------

func TestUserRepository_Delete_SetsRLSContext(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "eve@example.com")
	require.NoError(t, repo.Create(ctx, u))

	// WithTenantTx inside Delete sets app.tenant_id — must not be blocked.
	require.NoError(t, repo.Delete(ctx, u.ID, tenantID))

	// Soft-deleted user is no longer visible via GetByEmail.
	_, err := repo.GetByEmail(ctx, "eve@example.com", tenantID)
	require.Error(t, err, "soft-deleted user should not be found")
}

func TestUserRepository_Delete_NotFound(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	err := repo.Delete(context.Background(), uuid.New().String(), uuid.New().String())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// HardDelete
// ---------------------------------------------------------------------------

func TestUserRepository_HardDelete_SetsRLSContext(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "frank@example.com")
	require.NoError(t, repo.Create(ctx, u))

	// WithTenantTx inside HardDelete sets app.tenant_id — must not be blocked.
	require.NoError(t, repo.HardDelete(ctx, u.ID, tenantID))

	_, err := repo.GetByID(ctx, u.ID, tenantID)
	require.Error(t, err, "hard-deleted user should not be found")
}

func TestUserRepository_HardDelete_NotFound(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	err := repo.HardDelete(context.Background(), uuid.New().String(), uuid.New().String())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// IncrementTokenVersion
// ---------------------------------------------------------------------------

func TestUserRepository_IncrementTokenVersion_SetsRLSContext(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u := newTestUser(uuid.New().String(), tenantID, "grace@example.com")
	require.NoError(t, repo.Create(ctx, u))

	// WithTenantTx inside IncrementTokenVersion sets app.tenant_id — must not be blocked.
	require.NoError(t, repo.IncrementTokenVersion(ctx, u.ID, tenantID))

	got, err := repo.GetByID(ctx, u.ID, tenantID)
	require.NoError(t, err)
	assert.Equal(t, 2, got.TokenVersion, "token_version should have incremented from 1 to 2")
}

func TestUserRepository_IncrementTokenVersion_NotFound(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	err := repo.IncrementTokenVersion(context.Background(), uuid.New().String(), uuid.New().String())
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// ListByTenant
// ---------------------------------------------------------------------------

func TestUserRepository_ListByTenant(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	for _, email := range []string{"h@example.com", "i@example.com", "j@example.com"} {
		u := newTestUser(uuid.New().String(), tenantID, email)
		require.NoError(t, repo.Create(ctx, u))
	}

	users, total, err := repo.ListByTenant(ctx, tenantID, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, users, 3)
}

func TestUserRepository_ListByTenant_ExcludesSoftDeleted(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	u1 := newTestUser(uuid.New().String(), tenantID, "keep@example.com")
	u2 := newTestUser(uuid.New().String(), tenantID, "gone@example.com")
	require.NoError(t, repo.Create(ctx, u1))
	require.NoError(t, repo.Create(ctx, u2))
	require.NoError(t, repo.Delete(ctx, u2.ID, tenantID))

	users, total, err := repo.ListByTenant(ctx, tenantID, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, users, 1)
	assert.Equal(t, u1.ID, users[0].ID)
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation
// ---------------------------------------------------------------------------

func TestUserRepository_TenantIsolation(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantA := uuid.New().String()
	tenantB := uuid.New().String()

	uA := newTestUser(uuid.New().String(), tenantA, "user@example.com")
	uB := newTestUser(uuid.New().String(), tenantB, "user@example.com") // same email, different tenant
	require.NoError(t, repo.Create(ctx, uA))
	require.NoError(t, repo.Create(ctx, uB))

	// Tenant A can find its user.
	gotA, err := repo.GetByID(ctx, uA.ID, tenantA)
	require.NoError(t, err)
	assert.Equal(t, tenantA, gotA.TenantID)

	// Tenant A cannot find tenant B's user.
	_, err = repo.GetByID(ctx, uB.ID, tenantA)
	require.Error(t, err, "tenant A should not be able to read tenant B's user")

	// Each tenant only sees its own users in ListByTenant.
	usersA, totalA, err := repo.ListByTenant(ctx, tenantA, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, totalA)
	assert.Equal(t, uA.ID, usersA[0].ID)

	usersB, totalB, err := repo.ListByTenant(ctx, tenantB, 0, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, totalB)
	assert.Equal(t, uB.ID, usersB[0].ID)
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

func TestUserRepository_ListByTenant_Pagination(t *testing.T) {
	db, cleanup := setupUsersDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	tenantID := uuid.New().String()
	emails := []string{"p1@example.com", "p2@example.com", "p3@example.com", "p4@example.com", "p5@example.com"}
	for _, email := range emails {
		u := newTestUser(uuid.New().String(), tenantID, email)
		// Stagger created_at so ORDER BY is deterministic.
		u.CreatedAt = time.Now().UTC()
		require.NoError(t, repo.Create(ctx, u))
	}

	page1, total, err := repo.ListByTenant(ctx, tenantID, 0, 3)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, page1, 3)

	page2, _, err := repo.ListByTenant(ctx, tenantID, 3, 3)
	require.NoError(t, err)
	assert.Len(t, page2, 2)
}
