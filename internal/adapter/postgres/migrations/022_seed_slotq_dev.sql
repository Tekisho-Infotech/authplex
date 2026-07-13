-- 022_seed_slotq_dev.sql
-- Seeds the SlotQ development tenant, OIDC client, and default user so that
-- new dev environments work without any manual setup.
--
-- Tenant UUID is a deterministic uuid5("slotq") so it matches OIDC_TENANT_ID
-- in SlotQ's .env and AUTHPLEX_DEFAULT_TENANT_ID in docker-compose.
--
-- Hashes computed with bcrypt cost 12 (matches AuthPlex BcryptHasher):
--   password  = "Admin@1234"
--   secret    = "WaQZLOBbEW-9RlS0RPCc7hUO0Jfd0x-CORCmbZbnUOU"
--
-- RLS requires app.tenant_id to be set before inserting into tenant-scoped tables.

SET app.tenant_id = '4aa2670c-2a50-5851-a4e4-f4931e6f49e5';

-- Tenant (no RLS on this table)
INSERT INTO tenants (id, domain, issuer, algorithm, active_key_id, token_version, settings)
VALUES (
    '4aa2670c-2a50-5851-a4e4-f4931e6f49e5',
    'slotq.local',
    'http://localhost:8080',
    'RS256',
    NULL,
    1,
    '{}'
)
ON CONFLICT (id) DO NOTHING;

-- OIDC client (confidential, used by core-api BFF)
INSERT INTO clients (
    client_id,
    tenant_id,
    client_name,
    client_type,
    secret_hash,
    redirect_uris,
    allowed_scopes,
    allowed_grant_types,
    token_version
)
VALUES (
    '5BOOTLIGWdWN9Y1OYrjk7A',
    '4aa2670c-2a50-5851-a4e4-f4931e6f49e5',
    'slotq-web',
    'confidential',
    '$2a$12$0yOGUvUpOX1pxj2JUubK..rXJ3Ms0eyhKmQnxE1b8uDyik5e.eOBq'::bytea,
    ARRAY['http://localhost:5173/auth/callback'],
    ARRAY['openid', 'profile', 'email'],
    ARRAY['authorization_code', 'refresh_token'],
    1
)
ON CONFLICT (client_id) DO NOTHING;

-- Default dev user
INSERT INTO users (
    tenant_id,
    email,
    password_hash,
    name,
    email_verified,
    enabled,
    token_version
)
VALUES (
    '4aa2670c-2a50-5851-a4e4-f4931e6f49e5',
    'ananta.sai@tekisho.ai',
    '$2a$12$cVhP.w6.giDBTcoWV7w9B.yL6CjBJ2Y1OIQR82As0vrr6CaJt2UMq'::bytea,
    'Sai',
    true,
    true,
    1
)
ON CONFLICT (tenant_id, email) DO NOTHING;
