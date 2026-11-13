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
