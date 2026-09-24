//! SQLite 持久层：来源、shard 原始字节、manifest 摘要、已提交 stripe、临时块与报告。

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type Res<T> = Result<T, String>;

fn map_err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[derive(Clone)]
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

#[derive(Clone, Debug)]
pub struct SourceRow {
    pub id: i64,
    pub name: String,
    pub quarantined: bool,
}

#[derive(Clone, Debug)]
pub struct ObjectRow {
    pub id: String,
    pub param_version: i64,
    pub shard_size: usize,
    pub stripe_count: usize,
}

#[derive(Clone, Debug)]
pub struct ParamsRow {
    pub version: i64,
    pub k: usize,
    pub m: usize,
    pub field_bits: u8,
    pub field_poly: u16,
    pub stripe_size: usize,
    pub digest_alg: String,
}

#[derive(Clone, Debug)]
pub struct ShardRow {
    pub id: i64,
    pub object_id: String,
    pub shard_index: i64,
    pub generation: i64,
    pub source_id: i64,
    pub source_name: String,
    pub source_quarantined: bool,
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct CommittedRow {
    pub shard_index: usize,
    pub bytes: Vec<u8>,
    pub digest: String,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Res<Store> {
        let conn = Connection::open(path).map_err(map_err)?;
        let store = Store { conn: Arc::new(Mutex::new(conn)) };
        store.init()?;
        Ok(store)
    }

    pub fn open_memory() -> Res<Store> {
        let conn = Connection::open_in_memory().map_err(map_err)?;
        let store = Store { conn: Arc::new(Mutex::new(conn)) };
        store.init()?;
        Ok(store)
    }

    fn init(&self) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS params(
               version INTEGER PRIMARY KEY, k INTEGER, m INTEGER,
               field_bits INTEGER, field_poly INTEGER, stripe_size INTEGER, digest_alg TEXT);
             CREATE TABLE IF NOT EXISTS sources(
               id INTEGER PRIMARY KEY, name TEXT UNIQUE, quarantined INTEGER DEFAULT 0);
             CREATE TABLE IF NOT EXISTS objects(
               id TEXT PRIMARY KEY, param_version INTEGER, shard_size INTEGER, stripe_count INTEGER);
             CREATE TABLE IF NOT EXISTS manifest_digests(
               object_id TEXT, stripe INTEGER, shard_index INTEGER, digest TEXT,
               PRIMARY KEY(object_id, stripe, shard_index));
             CREATE TABLE IF NOT EXISTS shards(
               id INTEGER PRIMARY KEY, object_id TEXT, shard_index INTEGER, generation INTEGER,
               source_id INTEGER, path TEXT, bytes BLOB);
             CREATE TABLE IF NOT EXISTS committed(
               object_id TEXT, stripe INTEGER, shard_index INTEGER,
               bytes BLOB, digest TEXT, run_id TEXT,
               PRIMARY KEY(object_id, stripe, shard_index));
             CREATE TABLE IF NOT EXISTS stripe_temp(
               object_id TEXT, stripe INTEGER, shard_index INTEGER, bytes BLOB, digest TEXT);
             CREATE TABLE IF NOT EXISTS stripe_reports(
               object_id TEXT, stripe INTEGER, run_id TEXT, report TEXT,
               PRIMARY KEY(object_id, stripe));",
        )
        .map_err(map_err)
    }

    pub fn reset(&self) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "DELETE FROM stripe_temp; DELETE FROM committed; DELETE FROM stripe_reports;
             DELETE FROM shards; DELETE FROM manifest_digests; DELETE FROM objects;
             DELETE FROM sources; DELETE FROM params;",
        )
        .map_err(map_err)
    }

    pub fn put_params(&self, p: &ParamsRow) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO params(version,k,m,field_bits,field_poly,stripe_size,digest_alg)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![p.version, p.k as i64, p.m as i64, p.field_bits as i64,
                    p.field_poly as i64, p.stripe_size as i64, p.digest_alg],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn get_params(&self, version: i64) -> Res<ParamsRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT version,k,m,field_bits,field_poly,stripe_size,digest_alg FROM params WHERE version=?1",
            params![version],
            |r| {
                Ok(ParamsRow {
                    version: r.get(0)?,
                    k: r.get::<_, i64>(1)? as usize,
                    m: r.get::<_, i64>(2)? as usize,
                    field_bits: r.get::<_, i64>(3)? as u8,
                    field_poly: r.get::<_, i64>(4)? as u16,
                    stripe_size: r.get::<_, i64>(5)? as usize,
                    digest_alg: r.get(6)?,
                })
            },
        )
        .map_err(|_| format!("编码参数版本 {version} 不存在"))
    }

    pub fn add_source(&self, name: &str) -> Res<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute("INSERT OR IGNORE INTO sources(name) VALUES(?1)", params![name])
            .map_err(map_err)?;
        conn.query_row("SELECT id FROM sources WHERE name=?1", params![name], |r| r.get(0))
            .map_err(map_err)
    }

    pub fn list_sources(&self) -> Res<Vec<SourceRow>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT id,name,quarantined FROM sources ORDER BY id")
            .map_err(map_err)?;
        let rows = st
            .query_map([], |r| {
                Ok(SourceRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    quarantined: r.get::<_, i64>(2)? != 0,
                })
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    pub fn set_quarantined(&self, id: i64, q: bool) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE sources SET quarantined=?2 WHERE id=?1",
            params![id, if q { 1 } else { 0 }],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn put_object(&self, o: &ObjectRow) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO objects(id,param_version,shard_size,stripe_count) VALUES(?1,?2,?3,?4)",
            params![o.id, o.param_version, o.shard_size as i64, o.stripe_count as i64],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn get_object(&self, id: &str) -> Res<ObjectRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,param_version,shard_size,stripe_count FROM objects WHERE id=?1",
            params![id],
            |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    param_version: r.get(1)?,
                    shard_size: r.get::<_, i64>(2)? as usize,
                    stripe_count: r.get::<_, i64>(3)? as usize,
                })
            },
        )
        .map_err(|_| format!("对象 {id} 不存在"))
    }

    pub fn list_objects(&self) -> Res<Vec<ObjectRow>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT id,param_version,shard_size,stripe_count FROM objects ORDER BY id")
            .map_err(map_err)?;
        let rows = st
            .query_map([], |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    param_version: r.get(1)?,
                    shard_size: r.get::<_, i64>(2)? as usize,
                    stripe_count: r.get::<_, i64>(3)? as usize,
                })
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    pub fn put_manifest_digest(&self, object: &str, stripe: usize, shard_index: usize, digest: &str) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO manifest_digests(object_id,stripe,shard_index,digest) VALUES(?1,?2,?3,?4)",
            params![object, stripe as i64, shard_index as i64, digest],
        )
        .map_err(map_err)?;
        Ok(())
    }

    /// 返回某 stripe 的 manifest 摘要表：shard_index -> digest（按索引升序，确定）。
    pub fn manifest_digests(&self, object: &str, stripe: usize) -> Res<Vec<(usize, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare(
                "SELECT shard_index,digest FROM manifest_digests
                 WHERE object_id=?1 AND stripe=?2 ORDER BY shard_index",
            )
            .map_err(map_err)?;
        let rows = st
            .query_map(params![object, stripe as i64], |r| {
                Ok((r.get::<_, i64>(0)? as usize, r.get::<_, String>(1)?))
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    pub fn add_shard(&self, object: &str, shard_index: i64, generation: i64, source_id: i64, path: &str, bytes: &[u8]) -> Res<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shards(object_id,shard_index,generation,source_id,path,bytes) VALUES(?1,?2,?3,?4,?5,?6)",
            params![object, shard_index, generation, source_id, path, bytes],
        )
        .map_err(map_err)?;
        Ok(conn.last_insert_rowid())
    }

    pub fn delete_shard(&self, id: i64) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM shards WHERE id=?1", params![id]).map_err(map_err)?;
        Ok(())
    }

    pub fn shards_for_object(&self, object: &str) -> Res<Vec<ShardRow>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare(
                "SELECT s.id,s.object_id,s.shard_index,s.generation,s.source_id,
                        src.name,src.quarantined,s.path,s.bytes
                 FROM shards s JOIN sources src ON src.id=s.source_id
                 WHERE s.object_id=?1
                 ORDER BY s.shard_index, s.generation DESC, s.source_id, s.id",
            )
            .map_err(map_err)?;
        let rows = st
            .query_map(params![object], |r| {
                Ok(ShardRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    shard_index: r.get(2)?,
                    generation: r.get(3)?,
                    source_id: r.get(4)?,
                    source_name: r.get(5)?,
                    source_quarantined: r.get::<_, i64>(6)? != 0,
                    path: r.get(7)?,
                    bytes: r.get(8)?,
                })
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    /// 提交一个 stripe：先写临时块，校验后在单事务内切换为已提交并清理临时块。
    pub fn commit_stripe(&self, object: &str, stripe: usize, run_id: &str, shards: &[(usize, Vec<u8>, String)]) -> Res<()> {
        let mut conn = self.conn.lock().unwrap();
        // 临时区：进程中断时这些行永远不会被最终读取。
        conn.execute("DELETE FROM stripe_temp WHERE object_id=?1 AND stripe=?2", params![object, stripe as i64])
            .map_err(map_err)?;
        for (idx, bytes, digest) in shards {
            conn.execute(
                "INSERT INTO stripe_temp(object_id,stripe,shard_index,bytes,digest) VALUES(?1,?2,?3,?4,?5)",
                params![object, stripe as i64, *idx as i64, bytes, digest],
            )
            .map_err(map_err)?;
        }
        let tx = conn.transaction().map_err(map_err)?;
        tx.execute(
            "DELETE FROM committed WHERE object_id=?1 AND stripe=?2",
            params![object, stripe as i64],
        )
        .map_err(map_err)?;
        {
            let mut st = tx
                .prepare(
                    "INSERT INTO committed(object_id,stripe,shard_index,bytes,digest,run_id)
                     SELECT object_id,stripe,shard_index,bytes,digest,?3 FROM stripe_temp
                     WHERE object_id=?1 AND stripe=?2",
                )
                .map_err(map_err)?;
            st.execute(params![object, stripe as i64, run_id]).map_err(map_err)?;
        }
        tx.execute("DELETE FROM stripe_temp WHERE object_id=?1 AND stripe=?2", params![object, stripe as i64])
            .map_err(map_err)?;
        tx.commit().map_err(map_err)?;
        Ok(())
    }

    pub fn committed_for_stripe(&self, object: &str, stripe: usize) -> Res<Vec<CommittedRow>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare(
                "SELECT shard_index,bytes,digest FROM committed
                 WHERE object_id=?1 AND stripe=?2 ORDER BY shard_index",
            )
            .map_err(map_err)?;
        let rows = st
            .query_map(params![object, stripe as i64], |r| {
                Ok(CommittedRow {
                    shard_index: r.get::<_, i64>(0)? as usize,
                    bytes: r.get(1)?,
                    digest: r.get(2)?,
                })
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }

    pub fn delete_committed(&self, object: &str, stripe: usize) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM committed WHERE object_id=?1 AND stripe=?2",
            params![object, stripe as i64],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn committed_count(&self, object: &str) -> Res<usize> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(DISTINCT stripe) FROM committed WHERE object_id=?1",
            params![object],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as usize)
        .map_err(map_err)
    }

    /// 测试/恢复检查用：向临时区注入数据，验证临时块永不进入最终读取。
    pub fn insert_temp(&self, object: &str, stripe: usize, shard_index: usize, bytes: &[u8], digest: &str) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO stripe_temp(object_id,stripe,shard_index,bytes,digest) VALUES(?1,?2,?3,?4,?5)",
            params![object, stripe as i64, shard_index as i64, bytes, digest],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn temp_count(&self, object: &str) -> Res<usize> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT COUNT(*) FROM stripe_temp WHERE object_id=?1",
            params![object],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v as usize)
        .map_err(map_err)
    }

    pub fn save_report(&self, object: &str, stripe: usize, run_id: &str, report_json: &str) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO stripe_reports(object_id,stripe,run_id,report) VALUES(?1,?2,?3,?4)",
            params![object, stripe as i64, run_id, report_json],
        )
        .map_err(map_err)?;
        Ok(())
    }

    pub fn get_report(&self, object: &str, stripe: usize) -> Res<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT report FROM stripe_reports WHERE object_id=?1 AND stripe=?2",
            params![object, stripe as i64],
            |r| r.get(0),
        )
        .optional()
        .map_err(map_err)
    }

    pub fn get_reports(&self, object: &str) -> Res<Vec<(usize, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT stripe,report FROM stripe_reports WHERE object_id=?1 ORDER BY stripe")
            .map_err(map_err)?;
        let rows = st
            .query_map(params![object], |r| {
                Ok((r.get::<_, i64>(0)? as usize, r.get::<_, String>(1)?))
            })
            .map_err(map_err)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(map_err)
    }
}
