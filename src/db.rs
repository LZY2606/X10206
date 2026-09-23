//! SQLite persistence for the recovery pod.

use rusqlite::Connection;

pub const SCHEMA_VERSION: i64 = 1;

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    init_schema(&conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> rusqlite::Result<Connection> {
    let mut conn = Connection::open_in_memory()?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    init_schema(&conn)?;
    Ok(conn)
}

fn init_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    object_id      TEXT PRIMARY KEY,
    codec_version  TEXT NOT NULL,
    k              INTEGER NOT NULL,
    n              INTEGER NOT NULL,
    shard_size     INTEGER NOT NULL,
    object_size    INTEGER,
    object_digest  TEXT,
    stripe_count   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS stripes (
    object_id   TEXT NOT NULL REFERENCES objects(object_id),
    stripe      INTEGER NOT NULL,
    state       TEXT NOT NULL DEFAULT 'pending',
    chosen_output INTEGER,
    object_verified INTEGER NOT NULL DEFAULT 0,
    committed_at TEXT,
    PRIMARY KEY (object_id, stripe)
);

CREATE TABLE IF NOT EXISTS shard_anchors (
    object_id  TEXT NOT NULL REFERENCES objects(object_id),
    stripe     INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    digest     TEXT,
    PRIMARY KEY (object_id, stripe, shard_index)
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    stripe          INTEGER NOT NULL,
    shard_index     INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    source          TEXT NOT NULL,
    received_digest TEXT,
    computed_digest TEXT NOT NULL,
    blob_path       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_cand_loc ON candidates(object_id, stripe);

CREATE TABLE IF NOT EXISTS excluded (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id     TEXT NOT NULL,
    stripe        INTEGER NOT NULL,
    candidate_id  INTEGER NOT NULL,
    shard_index   INTEGER NOT NULL,
    generation    INTEGER NOT NULL,
    source        TEXT NOT NULL,
    reason        TEXT NOT NULL,
    run_id        INTEGER
);

CREATE TABLE IF NOT EXISTS failed_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    stripe      INTEGER NOT NULL,
    run_id      INTEGER,
    coherent_generation INTEGER,
    reason      TEXT NOT NULL,
    members_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outputs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    stripe      INTEGER NOT NULL,
    option_index INTEGER NOT NULL,
    shard_index INTEGER NOT NULL,
    digest      TEXT NOT NULL,
    blob_path   TEXT NOT NULL,
    coherent_generation INTEGER,
    anchor_verified INTEGER NOT NULL,
    members_json TEXT NOT NULL,
    supporting_sets INTEGER NOT NULL DEFAULT 1,
    committed   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(object_id, stripe, option_index, shard_index)
);

CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id   TEXT NOT NULL,
    started_at  TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    budget      INTEGER NOT NULL,
    reused_committed INTEGER NOT NULL DEFAULT 0,
    newly_committed  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS isolated_sources (
    object_id TEXT NOT NULL REFERENCES objects(object_id),
    source    TEXT NOT NULL,
    isolated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (object_id, source)
);

CREATE TABLE IF NOT EXISTS exports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id  TEXT NOT NULL,
    dir        TEXT NOT NULL,
    manifest_path TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#,
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO schema_meta(key, value) VALUES ('version', ?1)",
        [SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}
