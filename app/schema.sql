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
    emailed_at       TEXT,  -- when the alert email went out ('skipped' if too old when email was set up)
    email_attempts   INTEGER NOT NULL DEFAULT 0
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

-- ---------------------------------------------------------------- time entries
-- duration_seconds is NULL only while a timer is running. Entries are never
-- hard-deleted (deleted_at), and once on an invoice (invoice_id) they are locked.
CREATE TABLE IF NOT EXISTS time_entries (
    id                INTEGER PRIMARY KEY,
    client_id         INTEGER NOT NULL REFERENCES clients(id),
    product_id        INTEGER NOT NULL REFERENCES products(id),
    work_date         TEXT NOT NULL,                       -- YYYY-MM-DD, local time
    started_at        TEXT,                                -- UTC, timer entries only
    ended_at          TEXT,
    duration_seconds  INTEGER CHECK (duration_seconds IS NULL OR duration_seconds BETWEEN 0 AND 86400),
    notes             TEXT NOT NULL DEFAULT '',
    source            TEXT NOT NULL CHECK (source IN ('timer', 'manual')),
    invoice_id        INTEGER,
    deleted_at        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_time_client_date ON time_entries (client_id, work_date);
-- At most one running timer, enforced by the database itself.
CREATE UNIQUE INDEX IF NOT EXISTS idx_one_running_timer ON time_entries (source)
    WHERE source = 'timer' AND duration_seconds IS NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------- invoices
-- An invoice is a snapshot: client and business details are copied in when it's
-- created, so editing a client later never changes an invoice already sent.
-- Invoices are never deleted; "delete" = void (record kept, time released).
CREATE TABLE IF NOT EXISTS invoices (
    id                 INTEGER PRIMARY KEY,
    number             INTEGER NOT NULL UNIQUE,
    client_id          INTEGER NOT NULL REFERENCES clients(id),
    status             TEXT NOT NULL DEFAULT 'unpaid' CHECK (status IN ('unpaid', 'paid', 'void')),
    invoice_date       TEXT NOT NULL,
    due_date           TEXT NOT NULL,
    period_from        TEXT NOT NULL,
    period_to          TEXT NOT NULL,
    subtotal_cents     INTEGER NOT NULL,
    total_cents        INTEGER NOT NULL,
    notes              TEXT NOT NULL DEFAULT '',
    client_snapshot    TEXT NOT NULL,     -- JSON: name, address, email, terms
    business_snapshot  TEXT NOT NULL,     -- JSON: name, address, phone, email, footer
    pdf_path           TEXT,              -- relative to DATA_DIR
    pdf_sha256         TEXT,
    void_reason        TEXT,
    voided_at          TEXT,
    paid_at            TEXT,              -- date the payment arrived (YYYY-MM-DD)
    paid_method        TEXT,              -- check / zelle / transfer / other (never account numbers)
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices (client_id, invoice_date);

CREATE TABLE IF NOT EXISTS invoice_lines (
    id            INTEGER PRIMARY KEY,
    invoice_id    INTEGER NOT NULL REFERENCES invoices(id),
    sort          INTEGER NOT NULL,
    product_id    INTEGER NOT NULL REFERENCES products(id),
    description   TEXT NOT NULL,
    seconds       INTEGER NOT NULL,
    hours         TEXT NOT NULL,          -- what the invoice shows, e.g. "43.32"
    rate_cents    INTEGER NOT NULL,
    amount_cents  INTEGER NOT NULL
);

-- Business details printed on invoices (one row per setting).
CREATE TABLE IF NOT EXISTS app_settings (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);

-- ---------------------------------------------------------------- follow-ups
-- Reminder drafts at 7 and 14 days past due. Sent only when David clicks Send.
CREATE TABLE IF NOT EXISTS follow_ups (
    id          INTEGER PRIMARY KEY,
    invoice_id  INTEGER NOT NULL REFERENCES invoices(id),
    stage       INTEGER NOT NULL CHECK (stage IN (7, 14)),
    drafted_at  TEXT NOT NULL,
    sent_at     TEXT,
    UNIQUE (invoice_id, stage)
);

-- ---------------------------------------------------------------- email (Microsoft Graph)
-- One row per send attempt. send_token is unique per Send click, so a double
-- click can never send the same email twice. Message text is never stored here.
CREATE TABLE IF NOT EXISTS email_log (
    id            INTEGER PRIMARY KEY,
    kind          TEXT NOT NULL CHECK (kind IN ('invoice', 'follow_up', 'test', 'alert')),
    invoice_id    INTEGER REFERENCES invoices(id),
    follow_up_id  INTEGER REFERENCES follow_ups(id),
    to_addr       TEXT NOT NULL,
    cc_addr       TEXT NOT NULL DEFAULT '',
    bcc_addr      TEXT NOT NULL DEFAULT '',
    subject       TEXT NOT NULL,
    send_token    TEXT NOT NULL UNIQUE,
    status        TEXT NOT NULL CHECK (status IN ('sending', 'sent', 'failed')),
    error         TEXT,
    created_at    TEXT NOT NULL,
    sent_at       TEXT
);
CREATE INDEX IF NOT EXISTS idx_email_log_invoice ON email_log (invoice_id);
