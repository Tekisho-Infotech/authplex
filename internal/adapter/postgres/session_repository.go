package postgres

import (
	"context"
	"database/sql"

	"github.com/authplex/internal/domain/user"
	apperrors "github.com/authplex/pkg/sdk/errors"
)

// SessionRepository implements user.SessionRepository using PostgreSQL.
type SessionRepository struct {
	db *sql.DB
}

// NewSessionRepository creates a new Postgres-backed session repository.
func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

var _ user.SessionRepository = (*SessionRepository)(nil)

func (r *SessionRepository) Create(ctx context.Context, s user.Session) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, tenant_id, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		s.ID, s.UserID, s.TenantID, s.ExpiresAt, s.CreatedAt,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to create session", err)
	}
	return nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id string) (user.Session, error) {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	var s user.Session
	err := r.db.QueryRowContext(ctx,
		`SELECT id, user_id, tenant_id, expires_at, created_at
		 FROM sessions WHERE id = $1 AND expires_at > NOW()`,
		id,
	).Scan(&s.ID, &s.UserID, &s.TenantID, &s.ExpiresAt, &s.CreatedAt)
	if err == sql.ErrNoRows {
		return user.Session{}, apperrors.New(apperrors.ErrNotFound, "session not found")
	}
	if err != nil {
		return user.Session{}, apperrors.Wrap(apperrors.ErrInternal, "failed to get session", err)
	}
	return s, nil
}

func (r *SessionRepository) Delete(ctx context.Context, id string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	_, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete session", err)
	}
	return nil
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID, tenantID string) error {
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	_, err := r.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID,
	)
	if err != nil {
		return apperrors.Wrap(apperrors.ErrInternal, "failed to delete sessions for user", err)
	}
	return nil
}

// DeleteExpired removes a batch of expired sessions. Batched to avoid long-held row locks at volume.
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	const batchSize = 1000
	ctx, cancel := WithQueryTimeout(ctx)
	defer cancel()
	result, err := r.db.ExecContext(ctx,
		`DELETE FROM sessions WHERE id IN (
		     SELECT id FROM sessions WHERE expires_at < NOW() LIMIT $1
		 )`,
		batchSize,
	)
	if err != nil {
		return 0, apperrors.Wrap(apperrors.ErrInternal, "failed to delete expired sessions", err)
	}
	n, err := result.RowsAffected()
	if err != nil {
		return 0, apperrors.Wrap(apperrors.ErrInternal, "failed to read rows affected", err)
	}
	return n, nil
}
