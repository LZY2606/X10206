//! SQLite schema and small query helpers.

use rusqlite::Connection;

pub const SCHEMA_VERSION: u32 = 1;

pub const SCHEMA: &str = r#"
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    object_id       TEXT PRIMARY KEY,
    object_digest   TEXT,
    object_len      INTEGER NOT NULL DEFAULT 0,
    max_generation  INTEGER NOT NULL DEFAULT 0,
    imported_at     TEXT NOT NULL DEFAULT (datetime('now')),
    state           TEXT NOT NULL DEFAULT 'pending',
    -- pending|recovering|recovered|exported
    export_run_id   TEXT
);

CREATE TABLE IF NOT EXISTS manifests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    generation      INTEGER NOT NULL,
    data_shards     INTEGER NOT NULL,
    parity_shards   INTEGER NOT NULL,
    shard_len       INTEGER NOT NULL,
    object_digest   TEXT NOT NULL,
    object_len      INTEGER NOT NULL,
    raw_json        TEXT NOT NULL,
    received_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(object_id, generation)
);

CREATE TABLE IF NOT EXISTS sources (
    source_id       TEXT PRIMARY KEY,
    label           TEXT NOT NULL,
    isolated        INTEGER NOT NULL DEFAULT 0,
    received_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS candidates (
    candidate_id    TEXT PRIMARY KEY,
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    stripe_idx      INTEGER NOT NULL,
    shard_index     INTEGER NOT NULL,
    generation      INTEGER,
    source_id       TEXT NOT NULL REFERENCES sources(source_id),
    bytes_path      TEXT NOT NULL,
    len             INTEGER NOT NULL,
    received_digest TEXT,
    computed_digest TEXT NOT NULL,
    manifest_generation INTEGER,  -- generation whose manifest digest matched
    gen_match       INTEGER NOT NULL DEFAULT 0,
    digest_match    INTEGER NOT NULL DEFAULT 0,
    length_status   TEXT NOT NULL, -- ok|mismatch|no_manifest
    sidecar_status  TEXT NOT NULL, -- absent|ok|mismatch
    active          INTEGER NOT NULL DEFAULT 1,
    duplicate_of    TEXT REFERENCES candidates(candidate_id),
    received_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_candidates_lookup
    ON candidates(object_id, stripe_idx, shard_index);

CREATE TABLE IF NOT EXISTS stripes (
    object_id       TEXT NOT NULL REFERENCES objects(object_id),
    stripe_idx      INTEGER NOT NULL,
    generation      INTEGER NOT NULL,
    k               INTEGER NOT NULL,
    m               INTEGER NOT NULL,
    n               INTEGER NOT NULL,
    shard_len       INTEGER NOT NULL,
    state           TEXT NOT NULL DEFAULT 'pending',
    -- pending|infeasible|multiple|ready|committed
    chosen_solution_id INTEGER REFERENCES solutions(id),
    solution_count  INTEGER NOT NULL DEFAULT 0,
    feasible        INTEGER NOT NULL DEFAULT 0,
    analyzed_at     TEXT,
    committed_at    TEXT,
    result_path     TEXT,
    result_digest   TEXT,
    object_digest_match INTEGER,
    result_json     TEXT,
    PRIMARY KEY (object_id, stripe_idx)
);

CREATE TABLE IF NOT EXISTS solutions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id           TEXT NOT NULL,
    stripe_idx          INTEGER NOT NULL,
    generation          INTEGER NOT NULL,
    rank_no             INTEGER NOT NULL,
    participant_indexes TEXT NOT NULL, -- json [usize]
    present_indexes     TEXT NOT NULL, -- json [usize]
    rebuilt_indexes     TEXT NOT NULL, -- json [usize]
    solution_digest     TEXT NOT NULL,
    is_duplicate        INTEGER NOT NULL DEFAULT 0,
    signature           TEXT NOT NULL,
    FOREIGN KEY (object_id, stripe_idx) REFERENCES stripes(object_id, stripe_idx),
    UNIQUE(object_id, stripe_idx, signature)
);

CREATE TABLE IF NOT EXISTS rebuilt_shards (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    solution_id         INTEGER NOT NULL REFERENCES solutions(id),
    shard_index         INTEGER NOT NULL,
    source              TEXT NOT NULL, -- present|rebuilt
    candidate_id        TEXT REFERENCES candidates(candidate_id),
    bytes_path          TEXT,
    digest              TEXT NOT NULL,
    UNIQUE(solution_id, shard_index)
);

CREATE TABLE IF NOT EXISTS exclusions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL,
    stripe_idx      INTEGER NOT NULL,
    solution_id     INTEGER REFERENCES solutions(id),
    candidate_id    TEXT REFERENCES candidates(candidate_id),
    shard_index     INTEGER,
    generation      INTEGER,
    source_id       TEXT,
    kind            TEXT NOT NULL,
    detail          TEXT NOT NULL,
    observed        TEXT,
    expected        TEXT
);

CREATE INDEX IF NOT EXISTS idx_exclusions_lookup
    ON exclusions(object_id, stripe_idx);

CREATE TABLE IF NOT EXISTS jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL,
    kind            TEXT NOT NULL, -- recover|recompute
    state           TEXT NOT NULL, -- running|committed|interrupted|failed
    isolated_sources TEXT NOT NULL DEFAULT '[]', -- json
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    error           TEXT,
    progress_done   INTEGER NOT NULL DEFAULT 0,
    progress_total  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS recovery_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    object_id       TEXT NOT NULL,
    stripe_idx      INTEGER,
    job_id          INTEGER REFERENCES jobs(id),
    level           TEXT NOT NULL, -- info|warn|error
    event           TEXT NOT NULL,
    detail          TEXT,
    at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exports (
    run_id          TEXT PRIMARY KEY,
    dir             TEXT NOT NULL,
    manifest_path   TEXT NOT NULL,
    state           TEXT NOT NULL, -- staged|committed
    objects_json    TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

pub fn open(path: &str) -> rusqlite::Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    Ok(conn)
}

pub fn init(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(SCHEMA)?;
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        rusqlite::params![SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

/// Re-own a `?1`-style params list; small ergonomic wrapper.
#[macro_export]
macro_rules! params {
    ($($arg:expr),* $(,)?) => { rusqlite::params![$($arg),*] };
}
