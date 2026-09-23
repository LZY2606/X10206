//! SQLite 持久化：对象、manifest 摘要、收到的碎片、已提交 stripe、隔离名单。
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub type Res<T> = Result<T, String>;

fn es<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestShard {
    pub stripe: u32,
    pub index: u32,
    pub kind: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    pub k: usize,
    pub m: usize,
    pub shard_len: usize,
    pub stripes: u32,
    pub ec_version: u32,
    pub shards: Vec<ManifestShard>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObjectRow {
    pub id: i64,
    pub name: String,
    pub k: usize,
    pub m: usize,
    pub shard_len: usize,
    pub stripes: u32,
    pub ec_version: u32,
}

#[derive(Clone, Debug)]
pub struct ShardRow {
    pub index: u32,
    pub generation: u64,
    pub source: String,
    pub digest: String,
    pub bytes: Vec<u8>,
}

pub struct Store {
    pub conn: Mutex<Connection>,
    pub base: PathBuf,
}

impl Store {
    pub fn open(base: &Path) -> Res<Store> {
        std::fs::create_dir_all(base.join("tmp")).map_err(es)?;
        let conn = Connection::open(base.join("recovery.db")).map_err(es)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS objects(
                id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                k INTEGER NOT NULL, m INTEGER NOT NULL, shard_len INTEGER NOT NULL,
                stripes INTEGER NOT NULL, ec_version INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS manifest(
                object_id INTEGER NOT NULL, stripe INTEGER NOT NULL, idx INTEGER NOT NULL,
                kind TEXT NOT NULL, digest TEXT NOT NULL,
                PRIMARY KEY(object_id, stripe, idx));
             CREATE TABLE IF NOT EXISTS shards(
                id INTEGER PRIMARY KEY, object_id INTEGER NOT NULL, stripe INTEGER NOT NULL,
                idx INTEGER NOT NULL, generation INTEGER NOT NULL, source TEXT NOT NULL,
                digest TEXT NOT NULL, bytes BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS committed(
                object_id INTEGER NOT NULL, stripe INTEGER NOT NULL, digest TEXT NOT NULL,
                bytes BLOB NOT NULL, sources TEXT NOT NULL,
                PRIMARY KEY(object_id, stripe));
             CREATE TABLE IF NOT EXISTS quarantine(source TEXT PRIMARY KEY);",
        )
        .map_err(es)?;
        Ok(Store {
            conn: Mutex::new(conn),
            base: base.to_path_buf(),
        })
    }

    /// 启动时清理临时块：临时块绝不参与最终读取。
    pub fn cleanup_temp(&self) -> Res<()> {
        let tmp = self.base.join("tmp");
        if tmp.is_dir() {
            for entry in std::fs::read_dir(&tmp).map_err(es)? {
                let p = entry.map_err(es)?.path();
                if p.is_file() {
                    std::fs::remove_file(&p).map_err(es)?;
                }
            }
        }
        Ok(())
    }

    pub fn create_object(&self, m: &Manifest) -> Res<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO objects(name,k,m,shard_len,stripes,ec_version) VALUES(?1,?2,?3,?4,?5,?6)",
            params![m.name, m.k as i64, m.m as i64, m.shard_len as i64, m.stripes as i64, m.ec_version as i64],
        )
        .map_err(|e| format!("创建对象失败（名称可能重复）: {}", e))?;
        let id = conn.last_insert_rowid();
        for s in &m.shards {
            conn.execute(
                "INSERT INTO manifest(object_id,stripe,idx,kind,digest) VALUES(?1,?2,?3,?4,?5)",
                params![id, s.stripe as i64, s.index as i64, s.kind, s.sha256],
            )
            .map_err(es)?;
        }
        Ok(id)
    }

    pub fn object(&self, id: i64) -> Res<ObjectRow> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id,name,k,m,shard_len,stripes,ec_version FROM objects WHERE id=?1",
            params![id],
            |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    k: r.get::<_, i64>(2)? as usize,
                    m: r.get::<_, i64>(3)? as usize,
                    shard_len: r.get::<_, i64>(4)? as usize,
                    stripes: r.get::<_, i64>(5)? as u32,
                    ec_version: r.get::<_, i64>(6)? as u32,
                })
            },
        )
        .map_err(|e| format!("对象不存在: {}", e))
    }

    pub fn list_objects(&self) -> Res<Vec<ObjectRow>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT id,name,k,m,shard_len,stripes,ec_version FROM objects ORDER BY id")
            .map_err(es)?;
        let rows = st
            .query_map([], |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    k: r.get::<_, i64>(2)? as usize,
                    m: r.get::<_, i64>(3)? as usize,
                    shard_len: r.get::<_, i64>(4)? as usize,
                    stripes: r.get::<_, i64>(5)? as u32,
                    ec_version: r.get::<_, i64>(6)? as u32,
                })
            })
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn add_shard(
        &self,
        object_id: i64,
        stripe: u32,
        index: u32,
        generation: u64,
        source: &str,
        digest: &str,
        bytes: &[u8],
    ) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO shards(object_id,stripe,idx,generation,source,digest,bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![object_id, stripe as i64, index as i64, generation as i64, source, digest, bytes],
        )
        .map_err(es)?;
        Ok(())
    }

    pub fn shards_for(&self, object_id: i64, stripe: u32, exclude_quarantined: bool) -> Res<Vec<ShardRow>> {
        let conn = self.conn.lock().unwrap();
        let sql = if exclude_quarantined {
            "SELECT idx,generation,source,digest,bytes FROM shards
             WHERE object_id=?1 AND stripe=?2
             AND source NOT IN (SELECT source FROM quarantine)
             ORDER BY idx,generation,source"
        } else {
            "SELECT idx,generation,source,digest,bytes FROM shards
             WHERE object_id=?1 AND stripe=?2 ORDER BY idx,generation,source"
        };
        let mut st = conn.prepare(sql).map_err(es)?;
        let rows = st
            .query_map(params![object_id, stripe as i64], |r| {
                Ok(ShardRow {
                    index: r.get::<_, i64>(0)? as u32,
                    generation: r.get::<_, i64>(1)? as u64,
                    source: r.get(2)?,
                    digest: r.get(3)?,
                    bytes: r.get(4)?,
                })
            })
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn manifest_digests(&self, object_id: i64, stripe: u32) -> Res<BTreeMap<u32, String>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT idx,digest FROM manifest WHERE object_id=?1 AND stripe=?2 ORDER BY idx")
            .map_err(es)?;
        let rows = st
            .query_map(params![object_id, stripe as i64], |r| {
                Ok((r.get::<_, i64>(0)? as u32, r.get::<_, String>(1)?))
            })
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn manifest_all(&self, object_id: i64) -> Res<Vec<(u32, u32, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT stripe,idx,kind,digest FROM manifest WHERE object_id=?1 ORDER BY stripe,idx")
            .map_err(es)?;
        let rows = st
            .query_map(params![object_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn sources(&self, object_id: i64) -> Res<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT DISTINCT source FROM shards WHERE object_id=?1 ORDER BY source")
            .map_err(es)?;
        let rows = st
            .query_map(params![object_id], |r| r.get::<_, String>(0))
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn quarantined(&self) -> Res<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT source FROM quarantine ORDER BY source")
            .map_err(es)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn set_quarantine(&self, source: &str, on: bool) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        if on {
            conn.execute("INSERT OR IGNORE INTO quarantine(source) VALUES(?1)", params![source])
                .map_err(es)?;
        } else {
            conn.execute("DELETE FROM quarantine WHERE source=?1", params![source])
                .map_err(es)?;
        }
        Ok(())
    }

    /// 隔离来源后，删除使用过该来源的已提交 stripe，返回受影响的 (object_id, stripe)。
    pub fn drop_committed_with_source(&self, source: &str) -> Res<Vec<(i64, u32)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT object_id,stripe,sources FROM committed")
            .map_err(es)?;
        let rows: Vec<(i64, u32, String)> = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, i64>(1)? as u32,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(es)?
            .filter_map(|r| r.ok())
            .collect();
        let mut affected = Vec::new();
        for (oid, stripe, sources) in rows {
            if sources.split(',').any(|s| s == source) {
                conn.execute(
                    "DELETE FROM committed WHERE object_id=?1 AND stripe=?2",
                    params![oid, stripe as i64],
                )
                .map_err(es)?;
                affected.push((oid, stripe));
            }
        }
        Ok(affected)
    }

    pub fn committed(&self, object_id: i64, stripe: u32) -> Res<Option<(String, Vec<u8>, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT digest,bytes,sources FROM committed WHERE object_id=?1 AND stripe=?2")
            .map_err(es)?;
        let mut rows = st
            .query_map(params![object_id, stripe as i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, String>(2)?))
            })
            .map_err(es)?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    pub fn commit_stripe(&self, object_id: i64, stripe: u32, digest: &str, bytes: &[u8], sources: &str) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO committed(object_id,stripe,digest,bytes,sources) VALUES(?1,?2,?3,?4,?5)",
            params![object_id, stripe as i64, digest, bytes, sources],
        )
        .map_err(es)?;
        Ok(())
    }

    pub fn delete_committed(&self, object_id: i64, stripe: u32) -> Res<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM committed WHERE object_id=?1 AND stripe=?2",
            params![object_id, stripe as i64],
        )
        .map_err(es)?;
        Ok(())
    }

    pub fn committed_stripes(&self, object_id: i64) -> Res<Vec<(u32, String, Vec<u8>)>> {
        let conn = self.conn.lock().unwrap();
        let mut st = conn
            .prepare("SELECT stripe,digest,bytes FROM committed WHERE object_id=?1 ORDER BY stripe")
            .map_err(es)?;
        let rows = st
            .query_map(params![object_id], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u32,
                    r.get::<_, String>(1)?,
                    r.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(es)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}
