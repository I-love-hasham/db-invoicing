-- Main application database. All statements are idempotent.

CREATE TABLE IF NOT EXISTS users (
    id                  INTEGER PRIMARY KEY,
    username            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash       TEXT NOT NULL,
    totp_secret_enc     TEXT,            -- Fernet-encrypted, never stored in plain text
    totp_enabled        INTEGER NOT NULL DEFAULT 0,
    totp_last_step      INTEGER NOT NULL DEFAULT 0,  -- blocks reuse of a TOTP code
    failed_count        INTEGER NOT NULL DEFAULT 0,
    locked_until        REAL,
    created_at          TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    TEXT
);

-- Server-side sessions. The cookie holds a random token; only its SHA-256 is stored.
CREATE TABLE IF NOT EXISTS sessions (
    token_hash        TEXT PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    stage             TEXT NOT NULL CHECK (stage IN ('enroll', 'password', 'full')),
    created_at        REAL NOT NULL,
    last_seen         REAL NOT NULL,
    reauth_at         REAL,
    ip                TEXT,
    user_agent        TEXT,
    csrf_token        TEXT NOT NULL,
    pending_totp_enc  TEXT
);

CREATE TABLE IF NOT EXISTS login_failures (
    id  INTEGER PRIMARY KEY,
    ip  TEXT NOT NULL,
    ts  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_failures_ip_ts ON login_failures (ip, ts);

CREATE TABLE IF NOT EXISTS known_devices (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip          TEXT NOT NULL,
    ua_hash     TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (user_id, ip, ua_hash)
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id               INTEGER PRIMARY KEY,
    ts               TEXT NOT NULL,
    kind             TEXT NOT NULL,
    message          TEXT NOT NULL,
    acknowledged_at  TEXT,
    acknowledged_by  TEXT,
    emailed_at       TEXT   -- filled once Microsoft Graph sending is built
);

-- Small key/value store. 'audit_checkpoint' = highest audit entry ever written
-- (count|hash|mac), so deleting the audit DB or restoring an older copy is detected.
CREATE TABLE IF NOT EXISTS app_state (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- ---------------------------------------------------------------- clients, products, rates
-- Money is stored as whole cents (7718 = $77.18) so totals never have rounding errors.
-- Nothing here is ever hard-deleted: clients and products are archived instead.

CREATE TABLE IF NOT EXISTS clients (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    address             TEXT NOT NULL DEFAULT '',
    email               TEXT NOT NULL DEFAULT '',
    payment_terms_days  INTEGER NOT NULL DEFAULT 15 CHECK (payment_terms_days BETWEEN 0 AND 120),
    notes               TEXT NOT NULL DEFAULT '',
    archived_at         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description         TEXT NOT NULL DEFAULT '',          -- shown on the invoice line, e.g. "IT services"
    unit                TEXT NOT NULL DEFAULT 'hour' CHECK (unit IN ('hour', 'each')),
    default_rate_cents  INTEGER CHECK (default_rate_cents IS NULL OR default_rate_cents BETWEEN 0 AND 10000000),
    archived_at         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- A client's own rate for a product (overrides the product's default rate).
CREATE TABLE IF NOT EXISTS client_rates (
    client_id   INTEGER NOT NULL REFERENCES clients(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    rate_cents  INTEGER NOT NULL CHECK (rate_cents BETWEEN 0 AND 10000000),
    updated_at  TEXT NOT NULL,
    PRIMARY KEY (client_id, product_id)
);
