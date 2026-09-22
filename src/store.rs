use crate::model::*;
use crate::util::sha256_hex;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub struct Store {
    pub conn: Connection,
}

fn now() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}

impl Store {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> rusqlite::Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS objects(
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                enc_version INTEGER NOT NULL,
                k INTEGER NOT NULL,
                m INTEGER NOT NULL,
                shard_size INTEGER NOT NULL,
                object_len INTEGER NOT NULL,
                stripe_count INTEGER NOT NULL,
                manifest_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fragments(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                object_id TEXT NOT NULL,
                stripe_idx INTEGER NOT NULL,
                shard_idx INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                source TEXT NOT NULL,
                declared_digest TEXT NOT NULL,
                computed_digest TEXT NOT NULL,
                bytes BLOB NOT NULL,
                received_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_frag ON fragments(object_id, stripe_idx);
            CREATE TABLE IF NOT EXISTS sources(
                object_id TEXT NOT NULL,
                source TEXT NOT NULL,
                quarantined INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(object_id, source)
            );
            CREATE TABLE IF NOT EXISTS committed_stripes(
                object_id TEXT NOT NULL,
                stripe_idx INTEGER NOT NULL,
                generation INTEGER NOT NULL,
                solution_digest TEXT NOT NULL,
                PRIMARY KEY(object_id, stripe_idx)
            );
            CREATE TABLE IF NOT EXISTS committed_shards(
                object_id TEXT NOT NULL,
                stripe_idx INTEGER NOT NULL,
                shard_idx INTEGER NOT NULL,
                digest TEXT NOT NULL,
                bytes BLOB NOT NULL,
                PRIMARY KEY(object_id, stripe_idx, shard_idx)
            );
            CREATE TABLE IF NOT EXISTS reports(
                object_id TEXT NOT NULL,
                stripe_idx INTEGER NOT NULL,
                json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(object_id, stripe_idx)
            );
            ",
        )
    }

    /// 计算 manifest 一致性警告并推导 stripe 数。
    pub fn analyze(create: &CreateObject) -> (usize, Vec<String>) {
        let p = &create.params;
        let capacity_per_stripe = (p.k * p.shard_size) as u64;
        let computed = if capacity_per_stripe == 0 {
            0
        } else {
            create.object_len.div_ceil(capacity_per_stripe) as usize
        };
        let stripe_count = computed.max(create.manifest.stripes.len());
        let mut warnings = Vec::new();
        if create.object_len == 0 {
            warnings.push("manifest 声明对象长度为 0".to_string());
        }
        if computed != create.manifest.stripes.len() {
            warnings.push(format!(
                "manifest 与实际长度不符：声明长度 {} 字节需 {} 个 stripe，manifest 列出 {} 个",
                create.object_len,
                computed,
                create.manifest.stripes.len()
            ));
        }
        if create.object_len > capacity_per_stripe * create.manifest.stripes.len() as u64
            && !create.manifest.stripes.is_empty()
        {
            warnings.push("声明对象长度超出 manifest stripe 覆盖范围".to_string());
        }
        (stripe_count, warnings)
    }

    pub fn create_object(&self, create: &CreateObject) -> rusqlite::Result<()> {
        let (stripe_count, warnings) = Self::analyze(create);
        self.conn.execute(
            "INSERT INTO objects(id,name,enc_version,k,m,shard_size,object_len,stripe_count,manifest_json,warnings_json,created_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                create.id,
                create.name,
                create.params.version,
                create.params.k as i64,
                create.params.m as i64,
                create.params.shard_size as i64,
                create.object_len as i64,
                stripe_count as i64,
                serde_json::to_string(&create.manifest).unwrap(),
                serde_json::to_string(&warnings).unwrap(),
                now(),
            ],
        )?;
        Ok(())
    }

    fn object_from_row(row: &rusqlite::Row) -> rusqlite::Result<ObjectRow> {
        let manifest_json: String = row.get(8)?;
        let warnings_json: String = row.get(9)?;
        Ok(ObjectRow {
            id: row.get(0)?,
            name: row.get(1)?,
            params: EncodingParams {
                version: row.get::<_, i64>(2)? as u32,
                k: row.get::<_, i64>(3)? as usize,
                m: row.get::<_, i64>(4)? as usize,
                shard_size: row.get::<_, i64>(5)? as usize,
            },
            object_len: row.get::<_, i64>(6)? as u64,
            stripe_count: row.get::<_, i64>(7)? as usize,
            manifest: serde_json::from_str(&manifest_json).unwrap_or_default(),
            warnings: serde_json::from_str(&warnings_json).unwrap_or_default(),
        })
    }

    pub fn get_object(&self, id: &str) -> rusqlite::Result<Option<ObjectRow>> {
        self.conn
            .query_row(
                "SELECT id,name,enc_version,k,m,shard_size,object_len,stripe_count,manifest_json,warnings_json FROM objects WHERE id=?1",
                params![id],
                Self::object_from_row,
            )
            .optional()
    }

    pub fn list_objects(&self) -> rusqlite::Result<Vec<ObjectRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,name,enc_version,k,m,shard_size,object_len,stripe_count,manifest_json,warnings_json FROM objects ORDER BY id",
        )?;
        let rows = stmt.query_map([], Self::object_from_row)?;
        rows.collect()
    }

    /// 保存碎片原始字节与接收来源，接收时即重算摘要。
    pub fn add_fragment(
        &self,
        object_id: &str,
        stripe_idx: u32,
        shard_idx: u32,
        generation: u64,
        source: &str,
        declared_digest: &str,
        bytes: &[u8],
    ) -> rusqlite::Result<i64> {
        let computed = sha256_hex(bytes);
        self.conn.execute(
            "INSERT INTO fragments(object_id,stripe_idx,shard_idx,generation,source,declared_digest,computed_digest,bytes,received_at)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                object_id,
                stripe_idx,
                shard_idx,
                generation as i64,
                source,
                declared_digest,
                computed,
                bytes,
                now(),
            ],
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO sources(object_id, source, quarantined) VALUES(?1,?2,0)",
            params![object_id, source],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn fragment_from_row(row: &rusqlite::Row) -> rusqlite::Result<Fragment> {
        Ok(Fragment {
            id: row.get(0)?,
            object_id: row.get(1)?,
            stripe_idx: row.get::<_, i64>(2)? as u32,
            shard_idx: row.get::<_, i64>(3)? as u32,
            generation: row.get::<_, i64>(4)? as u64,
            source: row.get(5)?,
            declared_digest: row.get(6)?,
            computed_digest: row.get(7)?,
            bytes: row.get(8)?,
        })
    }

    /// 确定性排序：shard_idx, source, digest。
    pub fn fragments_for_stripe(&self, object_id: &str, stripe_idx: u32) -> rusqlite::Result<Vec<Fragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,object_id,stripe_idx,shard_idx,generation,source,declared_digest,computed_digest,bytes
             FROM fragments WHERE object_id=?1 AND stripe_idx=?2
             ORDER BY shard_idx, source, computed_digest, id",
        )?;
        let rows = stmt.query_map(params![object_id, stripe_idx], Self::fragment_from_row)?;
        rows.collect()
    }

    pub fn fragments_for_object(&self, object_id: &str) -> rusqlite::Result<Vec<Fragment>> {
        let mut stmt = self.conn.prepare(
            "SELECT id,object_id,stripe_idx,shard_idx,generation,source,declared_digest,computed_digest,bytes
             FROM fragments WHERE object_id=?1
             ORDER BY stripe_idx, shard_idx, source, computed_digest, id",
        )?;
        let rows = stmt.query_map(params![object_id], Self::fragment_from_row)?;
        rows.collect()
    }

    pub fn list_sources(&self, object_id: &str) -> rusqlite::Result<Vec<(String, bool)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT source, quarantined FROM sources WHERE object_id=?1 ORDER BY source")?;
        let rows = stmt.query_map(params![object_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? != 0))
        })?;
        rows.collect()
    }

    pub fn quarantined_sources(&self, object_id: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT source FROM sources WHERE object_id=?1 AND quarantined=1 ORDER BY source")?;
        let rows = stmt.query_map(params![object_id], |row| row.get(0))?;
        rows.collect()
    }

    pub fn set_quarantine(&self, object_id: &str, source: &str, quarantined: bool) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO sources(object_id, source, quarantined) VALUES(?1,?2,?3)
             ON CONFLICT(object_id, source) DO UPDATE SET quarantined=?3",
            params![object_id, source, quarantined as i64],
        )?;
        Ok(())
    }

    /// 单事务提交一个 stripe 的重建结果。
    pub fn commit_stripe(
        &self,
        object_id: &str,
        stripe_idx: u32,
        generation: u64,
        solution_digest: &str,
        shards: &[(u32, Vec<u8>, String)],
    ) -> rusqlite::Result<()> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            self.conn.execute(
                "DELETE FROM committed_shards WHERE object_id=?1 AND stripe_idx=?2",
                params![object_id, stripe_idx],
            )?;
            self.conn.execute(
                "INSERT INTO committed_stripes(object_id, stripe_idx, generation, solution_digest)
                 VALUES(?1,?2,?3,?4)
                 ON CONFLICT(object_id, stripe_idx) DO UPDATE SET generation=?3, solution_digest=?4",
                params![object_id, stripe_idx, generation as i64, solution_digest],
            )?;
            for (idx, bytes, digest) in shards {
                self.conn.execute(
                    "INSERT INTO committed_shards(object_id, stripe_idx, shard_idx, digest, bytes) VALUES(?1,?2,?3,?4,?5)",
                    params![object_id, stripe_idx, idx, digest, bytes],
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => self.conn.execute_batch("COMMIT"),
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    pub fn delete_committed(&self, object_id: &str, stripe_idx: u32) -> rusqlite::Result<()> {
        self.conn.execute(
            "DELETE FROM committed_shards WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe_idx],
        )?;
        self.conn.execute(
            "DELETE FROM committed_stripes WHERE object_id=?1 AND stripe_idx=?2",
            params![object_id, stripe_idx],
        )?;
        Ok(())
    }

    pub fn committed_stripe(&self, object_id: &str, stripe_idx: u32) -> rusqlite::Result<Option<(u64, String)>> {
        self.conn
            .query_row(
                "SELECT generation, solution_digest FROM committed_stripes WHERE object_id=?1 AND stripe_idx=?2",
                params![object_id, stripe_idx],
                |row| Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?)),
            )
            .optional()
    }

    pub fn committed_shards(&self, object_id: &str, stripe_idx: u32) -> rusqlite::Result<Vec<(u32, String, Vec<u8>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT shard_idx, digest, bytes FROM committed_shards WHERE object_id=?1 AND stripe_idx=?2 ORDER BY shard_idx",
        )?;
        let rows = stmt.query_map(params![object_id, stripe_idx], |row| {
            Ok((row.get::<_, i64>(0)? as u32, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?))
        })?;
        rows.collect()
    }

    /// 只有摘要完整校验通过的已提交 stripe 才可复用。
    pub fn verify_committed(&self, object_id: &str, stripe_idx: u32, expected_shards: usize) -> rusqlite::Result<bool> {
        if self.committed_stripe(object_id, stripe_idx)?.is_none() {
            return Ok(false);
        }
        let shards = self.committed_shards(object_id, stripe_idx)?;
        if shards.len() != expected_shards {
            return Ok(false);
        }
        Ok(shards.iter().all(|(_, digest, bytes)| sha256_hex(bytes) == *digest))
    }

    pub fn committed_count(&self, object_id: &str) -> rusqlite::Result<usize> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM committed_stripes WHERE object_id=?1",
            params![object_id],
            |row| row.get::<_, i64>(0).map(|v| v as usize),
        )
    }

    pub fn save_report(&self, object_id: &str, report: &StripeReport) -> rusqlite::Result<()> {
        self.conn.execute(
            "INSERT INTO reports(object_id, stripe_idx, json, created_at) VALUES(?1,?2,?3,?4)
             ON CONFLICT(object_id, stripe_idx) DO UPDATE SET json=?3, created_at=?4",
            params![
                object_id,
                report.stripe_idx,
                serde_json::to_string(report).unwrap(),
                now(),
            ],
        )?;
        Ok(())
    }

    pub fn reports(&self, object_id: &str) -> rusqlite::Result<Vec<StripeReport>> {
        let mut stmt = self
            .conn
            .prepare("SELECT json FROM reports WHERE object_id=?1 ORDER BY stripe_idx")?;
        let rows = stmt.query_map(params![object_id], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            if let Ok(report) = serde_json::from_str(&row?) {
                out.push(report);
            }
        }
        Ok(out)
    }
}
