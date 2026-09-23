//! SQLite 持久层 + 字节仓库目录管理。
//! 提交按 stripe 在单个事务内完成；重启时只复用数据库中已登记且摘要完整的输出。

use crate::model::*;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub struct Store {
    pub conn: Mutex<Connection>,
    pub data_dir: PathBuf,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=FULL;

CREATE TABLE IF NOT EXISTS sources(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  received_at TEXT NOT NULL,
  ingest_seq INTEGER NOT NULL,
  isolated INTEGER NOT NULL DEFAULT 0,
  UNIQUE(name, ingest_seq)
);

CREATE TABLE IF NOT EXISTS objects(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL UNIQUE,
  current_generation INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_versions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  k INTEGER NOT NULL,
  m INTEGER NOT NULL,
  shard_len INTEGER NOT NULL,
  stripe_count INTEGER NOT NULL,
  object_digest TEXT NOT NULL,
  UNIQUE(object_id, generation)
);

CREATE TABLE IF NOT EXISTS shard_expectations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stripe_idx INTEGER NOT NULL,
  shard_idx INTEGER NOT NULL,
  expected_digest TEXT NOT NULL,
  UNIQUE(object_id, generation, stripe_idx, shard_idx)
);

CREATE TABLE IF NOT EXISTS fragments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  stripe_idx INTEGER NOT NULL,
  shard_idx INTEGER NOT NULL,
  source_id INTEGER NOT NULL REFERENCES sources(id),
  length INTEGER NOT NULL,
  claimed_digest TEXT NOT NULL,
  actual_digest TEXT NOT NULL,
  byte_path TEXT NOT NULL,
  receive_order INTEGER NOT NULL,
  UNIQUE(object_id, generation, stripe_idx, shard_idx, actual_digest, source_id)
);

CREATE TABLE IF NOT EXISTS stripes(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  stripe_idx INTEGER NOT NULL,
  status TEXT NOT NULL,
  candidate_count INTEGER NOT NULL DEFAULT 0,
  preferred_candidate_id TEXT,
  committed_generation INTEGER,
  UNIQUE(object_id, stripe_idx)
);

CREATE TABLE IF NOT EXISTS reconstructions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  stripe_idx INTEGER NOT NULL,
  candidate_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  members_json TEXT NOT NULL,
  missing_json TEXT NOT NULL,
  rebuilt_json TEXT NOT NULL,
  rebuilt_digests_json TEXT NOT NULL,
  object_digest TEXT NOT NULL,
  object_digest_ok INTEGER NOT NULL,
  preferred INTEGER NOT NULL,
  differences_json TEXT NOT NULL,
  excluded_json TEXT NOT NULL,
  UNIQUE(object_id, stripe_idx, candidate_id)
);

CREATE TABLE IF NOT EXISTS committed_shards(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  object_id TEXT NOT NULL,
  stripe_idx INTEGER NOT NULL,
  shard_idx INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  digest TEXT NOT NULL,
  byte_path TEXT NOT NULL,
  UNIQUE(object_id, stripe_idx, shard_idx)
);

CREATE TABLE IF NOT EXISTS recovery_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  status TEXT NOT NULL,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  total_stripes INTEGER NOT NULL,
  committed_stripes INTEGER NOT NULL DEFAULT 0,
  failed_stripe INTEGER,
  error TEXT
);

CREATE TABLE IF NOT EXISTS exports(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  dir TEXT NOT NULL,
  created_at TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  object_count INTEGER NOT NULL
);
"#;

impl Store {
    pub fn open(data_dir: &str) -> rusqlite::Result<Self> {
        let dir = PathBuf::from(data_dir);
        std::fs::create_dir_all(dir.join("incoming")).ok();
        std::fs::create_dir_all(dir.join("fragments")).ok();
        std::fs::create_dir_all(dir.join("tmp")).ok();
        std::fs::create_dir_all(dir.join("committed")).ok();
        std::fs::create_dir_all(dir.join("exports")).ok();
        let db_path = dir.join("pod.db");
        let conn = Connection::open(db_path)?;
        conn.execute_batch(SCHEMA)?;
        let store = Store {
            conn: Mutex::new(conn),
            data_dir: dir,
        };
        store.cleanup_temp()?;
        store.cleanup_orphan_committed()?;
        Ok(store)
    }

    pub fn fragments_dir(&self) -> PathBuf {
        self.data_dir.join("fragments")
    }
    pub fn tmp_dir(&self) -> PathBuf {
        self.data_dir.join("tmp")
    }
    pub fn committed_dir(&self) -> PathBuf {
        self.data_dir.join("committed")
    }
    pub fn exports_dir(&self) -> PathBuf {
        self.data_dir.join("exports")
    }

    /// 删除临时目录中所有块：临时块永远不得被最终读取。
    pub fn cleanup_temp(&self) -> rusqlite::Result<()> {
        if let Ok(rd) = std::fs::read_dir(self.tmp_dir()) {
            for e in rd.flatten() {
                std::fs::remove_file(e.path()).ok();
            }
        }
        Ok(())
    }

    /// 删除已提交目录里未在数据库登记（中断时写入）的块。
    pub fn cleanup_orphan_committed(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        let mut registered = std::collections::HashSet::new();
        {
            let mut stmt = conn.prepare("SELECT byte_path FROM committed_shards")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            for p in rows.flatten() {
                registered.insert(p);
            }
        }
        let base = self.committed_dir();
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                let path = e.path();
                if !path.is_file() {
                    continue;
                }
                let rel = path.strip_prefix(&self.data_dir).unwrap_or(&path);
                if !registered.contains(rel.to_str().unwrap_or("")) {
                    std::fs::remove_file(&path).ok();
                }
            }
        }
        Ok(())
    }
}

impl Store {
    // ---------- sources ----------

    pub fn next_ingest_seq(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT COALESCE(MAX(ingest_seq),0)+1 FROM sources", [], |r| {
            r.get(0)
        })
    }

    pub fn insert_source(&self, name: &str, received_at: &str, seq: i64) -> rusqlite::Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO sources(name, received_at, ingest_seq) VALUES(?1,?2,?3)",
            params![name, received_at, seq],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn set_source_isolated(&self, name: &str, isolated: bool) -> rusqlite::Result<usize> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sources SET isolated=?1 WHERE name=?2",
            params![isolated as i64, name],
        )
    }

    pub fn sources(&self) -> rusqlite::Result<Vec<SourceRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,name,received_at,isolated,ingest_seq FROM sources ORDER BY ingest_seq,id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                name: r.get(1)?,
                received_at: r.get(2)?,
                isolated: r.get::<_, i64>(3)? != 0,
                ingest_seq: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    // ---------- manifest ----------

    pub fn upsert_object(&self, object_id: &str, current_gen: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(object_id,current_generation) VALUES(?1,?2)
             ON CONFLICT(object_id) DO UPDATE SET
               current_generation=MAX(current_generation, excluded.current_generation)",
            params![object_id, current_gen],
        )?;
        Ok(())
    }
}

impl Store {
    pub fn upsert_manifest_version(&self, v: &ManifestVersion, object_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO manifest_versions(object_id,generation,k,m,shard_len,stripe_count,object_digest)
             VALUES(?1,?2,?3,?4,?5,?6,?7)
             ON CONFLICT(object_id,generation) DO UPDATE SET
               k=excluded.k,m=excluded.m,shard_len=excluded.shard_len,
               stripe_count=excluded.stripe_count,object_digest=excluded.object_digest",
            params![object_id, v.generation as i64, v.k, v.m, v.shard_len, v.stripe_count, v.object_digest],
        )?;
        Ok(())
    }

    pub fn upsert_expectation(
        &self,
        object_id: &str,
        generation: i64,
        stripe: i64,
        shard: i64,
        digest: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shard_expectations(object_id,generation,stripe_idx,shard_idx,expected_digest)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(object_id,generation,stripe_idx,shard_idx)
             DO UPDATE SET expected_digest=excluded.expected_digest",
            params![object_id, generation, stripe, shard, digest],
        )?;
        Ok(())
    }

    pub fn insert_fragment(
        &self,
        object_id: &str,
        generation: i64,
        stripe: i64,
        shard: i64,
        source_id: i64,
        length: i64,
        claimed: &str,
        actual: &str,
        byte_rel_path: &str,
        receive_order: i64,
    ) -> rusqlite::Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        // 同来源、同摘要的重复提交幂等忽略；不同内容候选全部保留。
        let exists: Option<i64> = conn
            .query_row(
                "SELECT id FROM fragments WHERE object_id=?1 AND generation=?2 AND stripe_idx=?3
                 AND shard_idx=?4 AND source_id=?5 AND actual_digest=?6",
                params![object_id, generation, stripe, shard, source_id, actual],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(id) = exists {
            return Ok(id);
        }
        conn.execute(
            "INSERT INTO fragments(object_id,generation,stripe_idx,shard_idx,source_id,length,
                 claimed_digest,actual_digest,byte_path,receive_order)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                object_id,
                generation,
                stripe,
                shard,
                source_id,
                length,
                claimed,
                actual,
                byte_rel_path,
                receive_order
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn ensure_stripe(&self, object_id: &str, stripe: i64, total: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        for s in 0..total {
            conn.execute(
                "INSERT INTO stripes(object_id,stripe_idx,status) VALUES(?1,?2,'pending')
                 ON CONFLICT(object_id,stripe_idx) DO NOTHING",
                params![object_id, s],
            )?;
        }
        let _ = stripe;
        Ok(())
    }

    pub fn object_ids(&self) -> rusqlite::Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT object_id FROM objects ORDER BY object_id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect()
    }

    pub fn current_generation(&self, object_id: &str) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT current_generation FROM objects WHERE object_id=?1", params![object_id], |r| {
            r.get(0)
        })
    }

    pub fn manifest_version(&self, object_id: &str, gen: i64) -> rusqlite::Result<ManifestVersion> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT generation,k,m,shard_len,stripe_count,object_digest
             FROM manifest_versions WHERE object_id=?1 AND generation=?2",
            params![object_id, gen],
            |r| {
                Ok(ManifestVersion {
                    generation: r.get::<_, i64>(0)? as u64,
                    k: r.get(1)?,
                    m: r.get(2)?,
                    shard_len: r.get(3)?,
                    stripe_count: r.get(4)?,
                    object_digest: r.get(5)?,
                    shard_digests: Vec::new(),
                })
            },
        )
    }

    pub fn expected_digest(&self, object_id: &str, gen: i64, stripe: i64, shard: i64) -> rusqlite::Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT expected_digest FROM shard_expectations
             WHERE object_id=?1 AND generation=?2 AND stripe_idx=?3 AND shard_idx=?4",
            params![object_id, gen, stripe, shard],
            |r| r.get::<_, String>(0),
        )
        .optional()
    }
}

impl Store {
    pub fn fragments_for(&self, object_id: &str, stripe: i64) -> rusqlite::Result<Vec<FragmentRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT f.id,f.object_id,f.stripe_idx,f.shard_idx,f.generation,f.source_id,s.name,
                    f.length,f.claimed_digest,f.actual_digest,
                    (SELECT e.expected_digest FROM shard_expectations e
                      WHERE e.object_id=f.object_id AND e.generation=f.generation
                        AND e.stripe_idx=f.stripe_idx AND e.shard_idx=f.shard_idx),
                    f.byte_path,f.receive_order,s.isolated
             FROM fragments f JOIN sources s ON s.id=f.source_id
             WHERE f.object_id=?1 AND f.stripe_idx=?2
             ORDER BY f.shard_idx, f.generation, f.receive_order, f.id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe], |r| {
            Ok(FragmentRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                stripe_idx: r.get(2)?,
                shard_idx: r.get(3)?,
                generation: r.get(4)?,
                source_id: r.get(5)?,
                source_name: r.get(6)?,
                length: r.get(7)?,
                claimed_digest: r.get(8)?,
                actual_digest: r.get(9)?,
                expected_digest: r.get(10)?,
                byte_path: r.get(11)?,
                receive_order: r.get(12)?,
                isolated: r.get::<_, i64>(13)? != 0,
                excluded: false,
                evidence: None,
            })
        })?;
        rows.collect()
    }

    pub fn all_fragments(&self, object_id: &str) -> rusqlite::Result<Vec<FragmentRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT f.id,f.object_id,f.stripe_idx,f.shard_idx,f.generation,f.source_id,s.name,
                    f.length,f.claimed_digest,f.actual_digest,
                    (SELECT e.expected_digest FROM shard_expectations e
                      WHERE e.object_id=f.object_id AND e.generation=f.generation
                        AND e.stripe_idx=f.stripe_idx AND e.shard_idx=f.shard_idx),
                    f.byte_path,f.receive_order,s.isolated
             FROM fragments f JOIN sources s ON s.id=f.source_id
             WHERE f.object_id=?1
             ORDER BY f.stripe_idx,f.shard_idx,f.generation,f.receive_order,f.id",
        )?;
        let rows = stmt.query_map(params![object_id], |r| {
            Ok(FragmentRow {
                id: r.get(0)?,
                object_id: r.get(1)?,
                stripe_idx: r.get(2)?,
                shard_idx: r.get(3)?,
                generation: r.get(4)?,
                source_id: r.get(5)?,
                source_name: r.get(6)?,
                length: r.get(7)?,
                claimed_digest: r.get(8)?,
                actual_digest: r.get(9)?,
                expected_digest: r.get(10)?,
                byte_path: r.get(11)?,
                receive_order: r.get(12)?,
                isolated: r.get::<_, i64>(13)? != 0,
                excluded: false,
                evidence: None,
            })
        })?;
        rows.collect()
    }

    pub fn read_fragment_bytes(&self, rel: &str) -> std::io::Result<Vec<u8>> {
        std::fs::read(self.data_dir.join(rel))
    }

    pub fn committed_shards(&self, object_id: &str, stripe: i64) -> rusqlite::Result<Vec<(i64, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT shard_idx,digest,byte_path FROM committed_shards
             WHERE object_id=?1 AND stripe_idx=?2 ORDER BY shard_idx",
        )?;
        let rows = stmt.query_map(params![object_id, stripe], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?))
        })?;
        rows.collect()
    }

    pub fn committed_generation(&self, object_id: &str, stripe: i64) -> rusqlite::Result<Option<i64>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT committed_generation FROM stripes WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe],
            |r| r.get(0),
        )
        .optional()
    }

    pub fn is_stripe_committed(&self, object_id: &str, stripe: i64) -> rusqlite::Result<bool> {
        let conn = self.conn.lock().unwrap();
        let s: String = conn.query_row(
            "SELECT status FROM stripes WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe],
            |r| r.get(0),
        )?;
        Ok(s == "committed")
    }
}

impl Store {
    /// 用一次枚举结果替换某个 stripe 的全部候选（非提交态）。
    pub fn replace_reconstructions(
        &self,
        object_id: &str,
        stripe: i64,
        status: StripeStatus,
        cands: &[crate::recovery::Candidate],
    ) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM reconstructions WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe],
        )?;
        let mut preferred: Option<String> = None;
        for c in cands {
            if c.preferred {
                preferred = Some(c.candidate_id.clone());
            }
            tx.execute(
                "INSERT INTO reconstructions(object_id,stripe_idx,candidate_id,generation,
                    members_json,missing_json,rebuilt_json,rebuilt_digests_json,
                    object_digest,object_digest_ok,preferred,differences_json,excluded_json)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
                params![
                    object_id,
                    stripe,
                    c.candidate_id,
                    c.generation,
                    serde_json::to_string(&c.members).unwrap(),
                    serde_json::to_string(&c.missing_shards).unwrap(),
                    serde_json::to_string(
                        &c.rebuilt_data.iter().map(|(k, v)| (k.to_string(), hex::encode(v))).collect::<std::collections::BTreeMap<_,_>>()
                    ).unwrap(),
                    serde_json::to_string(&c.rebuilt_digests).unwrap(),
                    c.object_digest,
                    c.object_digest_ok as i64,
                    c.preferred as i64,
                    serde_json::to_string(&c.differences).unwrap(),
                    serde_json::to_string(&c.excluded).unwrap(),
                ],
            )?;
        }
        tx.execute(
            "UPDATE stripes SET status=?1,candidate_count=?2,preferred_candidate_id=?3
             WHERE object_id=?4 AND stripe_idx=?5",
            params![
                serde_json::to_string(&status).unwrap().trim_matches('"'),
                cands.len() as i64,
                preferred,
                object_id,
                stripe
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn mark_needs_recompute(&self, object_id: &str, stripe: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE stripes SET status='needs_recompute' WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe],
        )?;
        Ok(())
    }

    /// 提交 stripe：文件已先原子改名到位并核对摘要；此处仅做元数据事务登记。
    pub fn commit_stripe_metadata(
        &self,
        object_id: &str,
        stripe: i64,
        generation: i64,
        candidate_id: &str,
        shards: &[(i64, String, String)],
    ) -> rusqlite::Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        for (shard_idx, digest, rel) in shards {
            tx.execute(
                "INSERT INTO committed_shards(object_id,stripe_idx,shard_idx,generation,digest,byte_path)
                 VALUES(?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(object_id,stripe_idx,shard_idx) DO UPDATE SET
                   generation=excluded.generation,digest=excluded.digest,byte_path=excluded.byte_path",
                params![object_id, stripe, shard_idx, generation, digest, rel],
            )?;
        }
        tx.execute(
            "UPDATE stripes SET status='committed',committed_generation=?1,preferred_candidate_id=?2
             WHERE object_id=?3 AND stripe_idx=?4",
            params![generation, candidate_id, object_id, stripe],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn stripe_row(&self, object_id: &str, stripe: i64) -> rusqlite::Result<(String, i64, Option<String>, Option<i64>)> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT status,candidate_count,preferred_candidate_id,committed_generation
             FROM stripes WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
    }

    pub fn candidate_json(&self, object_id: &str, stripe: i64) -> rusqlite::Result<Vec<crate::recovery::StoredCandidate>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT candidate_id,generation,members_json,missing_json,rebuilt_json,
                    rebuilt_digests_json,object_digest,object_digest_ok,preferred,
                    differences_json,excluded_json
             FROM reconstructions WHERE object_id=?1 AND stripe_idx=?2
             ORDER BY preferred DESC, generation DESC, candidate_id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe], |r| {
            Ok(crate::recovery::StoredCandidate {
                candidate_id: r.get(0)?,
                generation: r.get(1)?,
                members_json: r.get(2)?,
                missing_json: r.get(3)?,
                rebuilt_json: r.get(4)?,
                rebuilt_digests_json: r.get(5)?,
                object_digest: r.get(6)?,
                object_digest_ok: r.get::<_, i64>(7)? != 0,
                preferred: r.get::<_, i64>(8)? != 0,
                _shard_digests_ok: (),
                differences_json: r.get(9)?,
                excluded_json: r.get(10)?,
            })
        })?;
        rows.collect()
    }

    // ---------- runs ----------

    pub fn start_run(&self, total: i64, started_at: &str) -> rusqlite::Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recovery_runs(status,started_at,total_stripes) VALUES('running',?1,?2)",
            params![started_at, total],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn update_run_progress(&self, run_id: i64, committed: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE recovery_runs SET committed_stripes=?1 WHERE id=?2",
            params![committed, run_id],
        )?;
        Ok(())
    }

    pub fn finish_run(&self, run_id: i64, status: RunStatus, finished_at: &str, failed_stripe: Option<i64>, error: Option<&str>) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE recovery_runs SET status=?1,finished_at=?2,failed_stripe=?3,error=?4 WHERE id=?5",
            params![serde_json::to_string(&status).unwrap().trim_matches('"'), finished_at, failed_stripe, error, run_id],
        )?;
        Ok(())
    }

    pub fn list_runs(&self) -> rusqlite::Result<Vec<RunDto>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id,status,started_at,finished_at,total_stripes,committed_stripes,failed_stripe,error
             FROM recovery_runs ORDER BY id DESC LIMIT 20",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(RunDto {
                id: r.get(0)?,
                status: r.get(1)?,
                started_at: r.get(2)?,
                finished_at: r.get(3)?,
                total_stripes: r.get(4)?,
                committed_stripes: r.get(5)?,
                failed_stripe: r.get(6)?,
                error: r.get(7)?,
            })
        })?;
        rows.collect()
    }

    pub fn last_run(&self) -> rusqlite::Result<Option<RunDto>> {
        Ok(self.list_runs()?.into_iter().next())
    }

    pub fn record_export(&self, dir: &str, created_at: &str, manifest_path: &str, count: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO exports(dir,created_at,manifest_path,object_count) VALUES(?1,?2,?3,?4)",
            params![dir, created_at, manifest_path, count],
        )?;
        Ok(())
    }

    pub fn rel_path(&self, p: &Path) -> String {
        p.strip_prefix(&self.data_dir).unwrap_or(p).to_string_lossy().to_string()
    }
}
