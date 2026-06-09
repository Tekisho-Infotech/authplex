-- Sessions are looked up by their opaque token ID (the token itself is the access control).
-- FORCE ROW LEVEL SECURITY prevents the service user from reading sessions at all unless
-- app.tenant_id is SET LOCAL in every transaction — but GetByID and Delete don't carry
-- tenant context. Disabling RLS here; the application enforces tenant scope via explicit
-- WHERE tenant_id = $N in DeleteByUserID and through FK constraints.
ALTER TABLE sessions DISABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation_sessions ON sessions;
