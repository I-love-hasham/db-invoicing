-- Audit database (separate file). Append-only and hash-chained.

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    username    TEXT,
    ip          TEXT,
    user_agent  TEXT,
    category    TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT,
    outcome     TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '{}',
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts);
CREATE INDEX IF NOT EXISTS idx_audit_cat_action ON audit_log (category, action);

-- The database itself refuses edits and deletes.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit log is append-only');
END;

-- Signed pointer to the newest entry, so cutting entries off the end is detected.
CREATE TABLE IF NOT EXISTS audit_head (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    entry_count  INTEGER NOT NULL,
    last_hash    TEXT NOT NULL,
    mac          TEXT NOT NULL
);
