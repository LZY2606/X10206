//! SQLite + 本地目录的存储层。
//!
//! 目录布局（均在项目目录 `data/` 下）：
//! - `bay.db`：元数据库；
//! - `inbox/<batch_id>/manifest.json` 与 shard 原始字节：导入物原样保留，永不改动；
//! - `stripes/<object_id>/stripe-<i>/committed/`：已提交块 + provenance；
//! - `stripes/<object_id>/stripe-<i>/tmp-*`：重建临时区，启动时清理，永不被最终读取；
//! - `exports/<export_id>/`：新目录导出 + `MANIFEST.commit.json` 原子切换。

use rusqlite::{params, Connection, OptionalExtension};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::coding::CodingParams;
use crate::manifest::SCHEMA_VERSION;
use crate::model::{sha256_hex, EvidenceKind, FaultGate};

pub struct Store {
    pub root: PathBuf,
    pub db: Connection,
    pub fault: Arc<FaultGate>,
}

pub struct ObjectRow {
    pub id: i64,
    pub object_id: String,
    pub field_bits: i64,
    pub k: i64,
    pub m: i64,
    pub shard_size: i64,
    pub stripes: i64,
    pub object_digest: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReplicaRow {
    pub id: i64,
    pub object_pk: i64,
    pub stripe_idx: i64,
    pub slot: i64,
    pub generation: i64,
    pub source: String,
    pub digest_expected: Option<String>,
    pub digest_actual: String,
    pub byte_len: i64,
    pub inbox_path: String,
    pub received_seq: i64,
}

const SCHEMA: &str = r#"
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS objects (
  id INTEGER PRIMARY KEY,
  object_id TEXT NOT NULL UNIQUE,
  field_bits INTEGER NOT NULL,
  k INTEGER NOT NULL,
  m INTEGER NOT NULL,
  shard_size INTEGER NOT NULL,
  stripes INTEGER NOT NULL,
  object_digest TEXT
);
CREATE TABLE IF NOT EXISTS replicas (
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  stripe_idx INTEGER NOT NULL,
  slot INTEGER NOT NULL,
  generation INTEGER NOT NULL,
  source TEXT NOT NULL,
  digest_expected TEXT,
  digest_actual TEXT NOT NULL,
  byte_len INTEGER NOT NULL,
  inbox_path TEXT NOT NULL,
  received_seq INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  stripe_idx INTEGER NOT NULL,
  slot INTEGER,
  replica_id INTEGER,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  phase TEXT NOT NULL DEFAULT 'import'
);
CREATE TABLE IF NOT EXISTS stripe_solutions (
  id INTEGER PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  stripe_idx INTEGER NOT NULL,
  rank INTEGER NOT NULL,
  replica_ids TEXT NOT NULL,
  generation INTEGER NOT NULL,
  data_digests TEXT NOT NULL,
  output_digest TEXT NOT NULL,
  tainted INTEGER NOT NULL,
  matches_object_digest INTEGER,
  committed INTEGER NOT NULL DEFAULT 0,
  UNIQUE(object_pk, stripe_idx, output_digest)
);
CREATE TABLE IF NOT EXISTS stripe_commits (
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  stripe_idx INTEGER NOT NULL,
  solution_id INTEGER NOT NULL REFERENCES stripe_solutions(id),
  committed_at TEXT NOT NULL,
  run_id TEXT NOT NULL,
  PRIMARY KEY (object_pk, stripe_idx)
);
CREATE TABLE IF NOT EXISTS quarantined_sources (
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  source TEXT NOT NULL,
  PRIMARY KEY (object_pk, source)
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY,
  object_pk INTEGER NOT NULL REFERENCES objects(id),
  started_at TEXT NOT NULL,
  budget INTEGER NOT NULL,
  combos_checked INTEGER NOT NULL,
  completed INTEGER NOT NULL
);
"#;

fn now_ts() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{}", n.as_millis())
}

/// 运行 ID 时间戳（毫秒）。
pub fn store_run_ts() -> String {
    now_ts()
}

fn digest_filename(slot: usize, digest: &str) -> String {
    format!("slot-{slot:03}-{}.bin", &digest[..12])
}

impl Store {
    /// 打开（必要时初始化）复原舱。启动时清理全部 stripe 临时目录：
    /// 中断恢复只复用 provenance 完整的已提交 stripe，临时块绝不复用。
    pub fn open(root: impl Into<PathBuf>, fault: Arc<FaultGate>) -> std::io::Result<Store> {
        let root = root.into();
        fs::create_dir_all(root.join("inbox"))?;
        fs::create_dir_all(root.join("stripes"))?;
        fs::create_dir_all(root.join("exports"))?;
        let mut db = Connection::open(root.join("bay.db")).map_err(io_err)?;
        db.pragma_update(None, "foreign_keys", "ON").map_err(io_err)?;
        db.execute_batch(SCHEMA).map_err(io_err)?;
        let v: Option<String> = db
            .query_row("SELECT value FROM meta WHERE key='schema_version'", [], |r| r.get(0))
            .optional()
            .map_err(io_err)?;
        match v {
            None => {
                db.execute(
                    "INSERT INTO meta(key,value) VALUES('schema_version',?1)",
                    params![SCHEMA_VERSION.to_string()],
                )
                .map_err(io_err)?;
            }
            Some(s) if s.parse::<i64>().unwrap_or(0) == SCHEMA_VERSION => {}
            Some(s) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("不兼容的 schema 版本 {s}"),
                ))
            }
        }
        // 清理崩溃残留临时块。
        let stripes_dir = root.join("stripes");
        if stripes_dir.exists() {
            for obj in fs::read_dir(&stripes_dir)? {
                let obj = obj?.path();
                if !obj.is_dir() {
                    continue;
                }
                for st in fs::read_dir(&obj)? {
                    let st = st?.path();
                    if !st.is_dir() {
                        continue;
                    }
                    for e in fs::read_dir(&st)? {
                        let e = e?.path();
                        if e.is_dir() && e.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.starts_with("tmp-")) {
                            let _ = fs::remove_dir_all(&e);
                        }
                    }
                }
            }
        }
        Ok(Store { root, db, fault })
    }

    /// 经故障门的原子文件写：先写 `.part`，fsync 后 rename。
    pub fn atomic_write(&self, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.fault
            .ticket()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut tmp = dest.as_os_str().to_owned();
        tmp.push(".part");
        let tmp = PathBuf::from(tmp);
        fs::write(&tmp, bytes)?;
        if let Ok(f) = fs::File::open(&tmp) {
            let _ = f.sync_all();
        }
        fs::rename(&tmp, dest)
    }

    pub fn inbox_path(&self, batch_id: &str, name: &str) -> PathBuf {
        self.root.join("inbox").join(batch_id).join(name)
    }

    pub fn stripe_dir(&self, object_id: &str, stripe: usize) -> PathBuf {
        self.root
            .join("stripes")
            .join(object_id)
            .join(format!("stripe-{stripe:04}"))
    }

    pub fn committed_dir(&self, object_id: &str, stripe: usize) -> PathBuf {
        self.stripe_dir(object_id, stripe).join("committed")
    }

    pub fn export_dir(&self, export_id: &str) -> PathBuf {
        self.root.join("exports").join(export_id)
    }

    pub fn db_row(&self, sql: &str, id: i64) -> std::io::Result<(i64, i64)> {
        self.db
            .query_row(sql, params![id], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(io_err)
    }

    pub fn scalar_string(&self, sql: &str, id: i64) -> std::io::Result<String> {
        self.db
            .query_row(sql, params![id], |r| r.get::<_, String>(0))
            .map_err(io_err)
    }
}

// ---------- 行类型 ----------

#[derive(Clone, Debug)]
pub struct EvidenceRow {
    pub id: i64,
    pub stripe_idx: i64,
    pub slot: Option<i64>,
    pub replica_id: Option<i64>,
    pub kind: String,
    pub detail: String,
    pub phase: String,
}

#[derive(Clone, Debug)]
pub struct SolutionRow {
    pub id: i64,
    pub stripe_idx: i64,
    pub rank: i64,
    pub replica_ids: Vec<i64>,
    pub generation: i64,
    pub data_digests: Vec<String>,
    pub output_digest: String,
    pub tainted: bool,
    pub matches_object_digest: Option<bool>,
    pub committed: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PartShard {
    pub slot: usize,
    pub generation: i64,
    pub source: String,
    pub digest: String,
    pub replica_id: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExcludedNote {
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommittedShard {
    pub slot: usize,
    pub file: String,
    pub digest: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    pub provenance_version: String,
    pub object_id: String,
    pub stripe_idx: usize,
    pub generation: i64,
    pub field_bits: u32,
    pub k: usize,
    pub m: usize,
    pub shard_size: usize,
    pub rank: usize,
    pub participating: Vec<PartShard>,
    pub excluded: Vec<ExcludedNote>,
    pub shards: Vec<CommittedShard>,
    pub output_digest: String,
    pub run_id: String,
    pub committed_at: String,
}

pub const PROVENANCE_VERSION: &str = "stripe-bay/commit/v1";

/// 恢复引擎要持久化的一个可行方案。
#[derive(Clone, Debug)]
pub struct SolutionRec {
    pub replica_ids: Vec<i64>,
    pub generation: i64,
    pub data_digests: Vec<String>,
    pub output_digest: String,
    pub tainted: bool,
}

impl Store {
    pub fn ensure_object(
        &self,
        object_id: &str,
        params: &CodingParams,
        stripes: usize,
        object_digest: Option<&str>,
    ) -> std::io::Result<i64> {
        self.db
            .execute(
                "INSERT INTO objects(object_id,field_bits,k,m,shard_size,stripes,object_digest)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)
                 ON CONFLICT(object_id) DO UPDATE SET
                   field_bits=excluded.field_bits, k=excluded.k, m=excluded.m,
                   shard_size=excluded.shard_size, stripes=excluded.stripes,
                   object_digest=COALESCE(excluded.object_digest,objects.object_digest)",
                params![
                    object_id,
                    params.field_bits as i64,
                    params.k as i64,
                    params.m as i64,
                    params.shard_size as i64,
                    stripes as i64,
                    object_digest,
                ],
            )
            .map_err(io_err)?;
        self.db
            .query_row("SELECT id FROM objects WHERE object_id=?1", params![object_id], |r| r.get(0))
            .map_err(io_err)
    }

    pub fn get_object(&self, object_id: &str) -> std::io::Result<Option<ObjectRow>> {
        self.db
            .query_row(
                "SELECT id,object_id,field_bits,k,m,shard_size,stripes,object_digest
                 FROM objects WHERE object_id=?1",
                params![object_id],
                |r| {
                    Ok(ObjectRow {
                        id: r.get(0)?,
                        object_id: r.get(1)?,
                        field_bits: r.get(2)?,
                        k: r.get(3)?,
                        m: r.get(4)?,
                        shard_size: r.get(5)?,
                        stripes: r.get(6)?,
                        object_digest: r.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(io_err)
    }

    pub fn get_object_pk(&self, pk: i64) -> std::io::Result<ObjectRow> {
        self.db
            .query_row(
                "SELECT id,object_id,field_bits,k,m,shard_size,stripes,object_digest
                 FROM objects WHERE id=?1",
                params![pk],
                |r| {
                    Ok(ObjectRow {
                        id: r.get(0)?,
                        object_id: r.get(1)?,
                        field_bits: r.get(2)?,
                        k: r.get(3)?,
                        m: r.get(4)?,
                        shard_size: r.get(5)?,
                        stripes: r.get(6)?,
                        object_digest: r.get(7)?,
                    })
                },
            )
            .map_err(io_err)
    }

    pub fn list_objects(&self) -> std::io::Result<Vec<ObjectRow>> {
        let mut s = self
            .db
            .prepare("SELECT id,object_id,field_bits,k,m,shard_size,stripes,object_digest FROM objects ORDER BY object_id")
            .map_err(io_err)?;
        let rows = s
            .query_map([], |r| {
                Ok(ObjectRow {
                    id: r.get(0)?,
                    object_id: r.get(1)?,
                    field_bits: r.get(2)?,
                    k: r.get(3)?,
                    m: r.get(4)?,
                    shard_size: r.get(5)?,
                    stripes: r.get(6)?,
                    object_digest: r.get(7)?,
                })
            })
            .map_err(io_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(io_err)?);
        }
        Ok(out)
    }

    pub fn next_seq(&self, object_pk: i64) -> std::io::Result<i64> {
        let n: i64 = self
            .db
            .query_row(
                "SELECT COALESCE(MAX(received_seq),0)+1 FROM replicas WHERE object_pk=?1",
                params![object_pk],
                |r| r.get(0),
            )
            .map_err(io_err)?;
        Ok(n)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn insert_replica(
        &self,
        object_pk: i64,
        stripe: usize,
        slot: usize,
        generation: i64,
        source: &str,
        digest_expected: Option<&str>,
        bytes: &[u8],
        inbox_path: &str,
    ) -> std::io::Result<i64> {
        let digest_actual = sha256_hex(bytes);
        let seq = self.next_seq(object_pk)?;
        self.db
            .execute(
                "INSERT INTO replicas(object_pk,stripe_idx,slot,generation,source,
                   digest_expected,digest_actual,byte_len,inbox_path,received_seq)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                params![
                    object_pk,
                    stripe as i64,
                    slot as i64,
                    generation,
                    source,
                    digest_expected,
                    digest_actual,
                    bytes.len() as i64,
                    inbox_path,
                    seq,
                ],
            )
            .map_err(io_err)?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn list_replicas(&self, object_pk: i64) -> std::io::Result<Vec<ReplicaRow>> {
        let mut s = self
            .db
            .prepare(
                "SELECT id,object_pk,stripe_idx,slot,generation,source,
                        digest_expected,digest_actual,byte_len,inbox_path,received_seq
                 FROM replicas WHERE object_pk=?1 ORDER BY stripe_idx,slot,generation,id",
            )
            .map_err(io_err)?;
        let rows = s.query_map(params![object_pk], |r| {
            Ok(ReplicaRow {
                id: r.get(0)?,
                object_pk: r.get(1)?,
                stripe_idx: r.get(2)?,
                slot: r.get(3)?,
                generation: r.get(4)?,
                source: r.get(5)?,
                digest_expected: r.get(6)?,
                digest_actual: r.get(7)?,
                byte_len: r.get(8)?,
                inbox_path: r.get(9)?,
                received_seq: r.get(10)?,
            })
        }).map_err(io_err)?;
        rows.map(|r| r.map_err(io_err)).collect()
    }

    pub fn read_replica(&self, r: &ReplicaRow) -> std::io::Result<Vec<u8>> {
        fs::read(self.root.join(&r.inbox_path))
    }

    pub fn add_evidence(
        &self,
        object_pk: i64,
        stripe: usize,
        slot: Option<usize>,
        replica_id: Option<i64>,
        kind: EvidenceKind,
        detail: &str,
        phase: &str,
    ) -> std::io::Result<()> {
        self.db
            .execute(
                "INSERT INTO evidence(object_pk,stripe_idx,slot,replica_id,kind,detail,phase)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![
                    object_pk,
                    stripe as i64,
                    slot.map(|v| v as i64),
                    replica_id,
                    kind.as_str(),
                    detail,
                    phase,
                ],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    /// 枚举阶段的证据可重算，先清掉旧的；导入阶段证据保留。
    pub fn clear_enum_evidence(&self, object_pk: i64, stripe: usize) -> std::io::Result<()> {
        self.db
            .execute(
                "DELETE FROM evidence WHERE object_pk=?1 AND stripe_idx=?2 AND phase='enumeration'",
                params![object_pk, stripe as i64],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    pub fn list_evidence(&self, object_pk: i64) -> std::io::Result<Vec<EvidenceRow>> {
        let mut s = self
            .db
            .prepare(
                "SELECT id,stripe_idx,slot,replica_id,kind,detail,phase
                 FROM evidence WHERE object_pk=?1
                 ORDER BY stripe_idx,id",
            )
            .map_err(io_err)?;
        let rows = s.query_map(params![object_pk], |r| {
            Ok(EvidenceRow {
                id: r.get(0)?,
                stripe_idx: r.get(1)?,
                slot: r.get(2)?,
                replica_id: r.get(3)?,
                kind: r.get(4)?,
                detail: r.get(5)?,
                phase: r.get(6)?,
            })
        }).map_err(io_err)?;
        rows.map(|r| r.map_err(io_err)).collect()
    }
}

fn io_err(e: rusqlite::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e)
}

// ---------- 方案、提交、隔离、运行 ----------

impl Store {
    /// 枚举开始：移除该 stripe 上一轮的方案行；提交记录保留（复用判断另查）。
    pub fn replace_solutions(
        &self,
        object_pk: i64,
        stripe: usize,
        recs: &[SolutionRec],
    ) -> std::io::Result<Vec<i64>> {
        let tx = self.db.unchecked_transaction().map_err(io_err)?;
        // 先解除旧提交引用保护：删除未被提交引用的旧方案。
        tx.execute(
            "DELETE FROM stripe_solutions
             WHERE object_pk=?1 AND stripe_idx=?2
               AND id NOT IN (SELECT solution_id FROM stripe_commits
                              WHERE object_pk=?1 AND stripe_idx=?2)",
            params![object_pk, stripe as i64],
        )
        .map_err(io_err)?;
        let mut ids = Vec::new();
        for rec in recs {
            let ids_json = serde_json::to_string(&rec.replica_ids).unwrap();
            let digests_json = serde_json::to_string(&rec.data_digests).unwrap();
            tx.execute(
                "INSERT OR IGNORE INTO stripe_solutions
                   (object_pk,stripe_idx,rank,replica_ids,generation,data_digests,
                    output_digest,tainted,matches_object_digest,committed)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,0)",
                params![
                    object_pk,
                    stripe as i64,
                    rec.replica_ids.len() as i64,
                    ids_json,
                    rec.generation,
                    digests_json,
                    rec.output_digest,
                    rec.tainted as i64,
                ],
            )
            .map_err(io_err)?;
            let id: i64 = tx
                .query_row(
                    "SELECT id FROM stripe_solutions
                     WHERE object_pk=?1 AND stripe_idx=?2 AND output_digest=?3",
                    params![object_pk, stripe as i64, rec.output_digest],
                    |r| r.get(0),
                )
                .map_err(io_err)?;
            ids.push(id);
        }
        tx.commit().map_err(io_err)?;
        Ok(ids)
    }

    pub fn list_solutions(
        &self,
        object_pk: i64,
        stripe: usize,
    ) -> std::io::Result<Vec<SolutionRow>> {
        let mut s = self
            .db
            .prepare(
                "SELECT id,stripe_idx,rank,replica_ids,generation,output_digest,
                        tainted,matches_object_digest,committed
                 FROM stripe_solutions WHERE object_pk=?1 AND stripe_idx=?2
                 ORDER BY id",
            )
            .map_err(io_err)?;
        let rows = s
            .query_map(params![object_pk, stripe as i64], |r| {
                let ids: Vec<i64> = serde_json::from_str(&r.get::<_, String>(3)?).unwrap();
                Ok(SolutionRow {
                    id: r.get(0)?,
                    stripe_idx: r.get(1)?,
                    rank: r.get(2)?,
                    replica_ids: ids,
                    generation: r.get(4)?,
                    data_digests: serde_json::from_str(&r.get::<_, String>(5)?).unwrap(),
                    output_digest: r.get(6)?,
                    tainted: r.get::<_, i64>(7)? != 0,
                    matches_object_digest: r
                        .get::<_, Option<i64>>(8)?
                        .map(|v| v != 0),
                    committed: r.get::<_, i64>(9)? != 0,
                })
            })
            .map_err(io_err)?;
        rows.map(|r| r.map_err(io_err)).collect()
    }

    pub fn set_object_match(
        &self,
        object_pk: i64,
        stripe: usize,
        solution_id: i64,
        matches: bool,
    ) -> std::io::Result<()> {
        self.db
            .execute(
                "UPDATE stripe_solutions SET matches_object_digest=?3
                 WHERE object_pk=?1 AND stripe_idx=?2 AND id=?4",
                params![object_pk, stripe as i64, matches as i64, solution_id],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    pub fn committed_solution(
        &self,
        object_pk: i64,
        stripe: usize,
    ) -> std::io::Result<Option<(i64, String, String)>> {
        self.db
            .query_row(
                "SELECT c.solution_id,c.run_id,c.committed_at
                 FROM stripe_commits c WHERE object_pk=?1 AND stripe_idx=?2",
                params![object_pk, stripe as i64],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(io_err)
    }

    /// 读取已提交 provenance；文件缺失或摘要不符时返回错误，调用方必须重算。
    pub fn load_committed(&self, obj: &ObjectRow, stripe: usize) -> std::io::Result<Provenance> {
        let dir = self.committed_dir(&obj.object_id, stripe);
        let pb = dir.join("provenance.json");
        let bytes = fs::read(&pb)?;
        let p: Provenance = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        if p.object_id != obj.object_id || p.stripe_idx != stripe {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "provenance 与对象/stripe 不符",
            ));
        }
        for sh in &p.shards {
            let data = fs::read(dir.join(&sh.file))?;
            if sha256_hex(&data) != sh.digest {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("已提交 slot {} 摘要不完整", sh.slot),
                ));
            }
            if data.len() != p.shard_size {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("已提交 slot {} 长度不符", sh.slot),
                ));
            }
        }
        Ok(p)
    }

    /// 原子提交一个 stripe：新目录写块与 provenance，校验通过后原子改名 committed，
    /// 最后落 DB。任何一步失败都不会留下“半提交”可读状态。
    #[allow(clippy::too_many_arguments)]
    pub fn commit_solution(
        &self,
        obj: &ObjectRow,
        stripe: usize,
        sol: &SolutionRec,
        grid: &[Vec<u8>],
        participating: &[PartShard],
        excluded: &[ExcludedNote],
        run_id: &str,
    ) -> std::io::Result<i64> {
        let sdir = self.stripe_dir(&obj.object_id, stripe);
        fs::create_dir_all(&sdir)?;
        let unique = format!(
            "tmp-{}-{}",
            &run_id,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let fresh = sdir.join(unique);
        let _ = fs::remove_dir_all(&fresh);
        fs::create_dir_all(&fresh)?;
        let mut committed = Vec::new();
        for (slot, bytes) in grid.iter().enumerate() {
            let dig = sha256_hex(bytes);
            let fname = digest_filename(slot, &dig);
            self.atomic_write(&fresh.join(&fname), bytes)?;
            committed.push(CommittedShard { slot, file: fname, digest: dig });
        }
        let prov = Provenance {
            provenance_version: PROVENANCE_VERSION.into(),
            object_id: obj.object_id.clone(),
            stripe_idx: stripe,
            generation: sol.generation,
            field_bits: obj.field_bits as u32,
            k: obj.k as usize,
            m: obj.m as usize,
            shard_size: obj.shard_size as usize,
            rank: sol.replica_ids.len(),
            participating: participating.to_vec(),
            excluded: excluded.to_vec(),
            shards: committed,
            output_digest: sol.output_digest.clone(),
            run_id: run_id.into(),
            committed_at: now_ts(),
        };
        let prov_json = serde_json::to_vec_pretty(&prov).unwrap();
        self.atomic_write(&fresh.join("provenance.json"), &prov_json)?;
        // 提交前自检：所有文件按摘要重新核对。
        for sh in &prov.shards {
            let data = fs::read(fresh.join(&sh.file))?;
            if sha256_hex(&data) != sh.digest {
                return Err(std::io::Error::other("提交自检摘要不符"));
            }
        }
        let committed_dir = self.committed_dir(&obj.object_id, stripe);
        // 原子切换目录：旧 committed 先改名 retired-* 再删除。
        if committed_dir.exists() {
            let retired = sdir.join(format!(
                "retired-{}-{}",
                prov.committed_at,
                &sol.output_digest[..8]
            ));
            fs::rename(&committed_dir, &retired)?;
            fs::remove_dir_all(&retired).ok();
        }
        fs::rename(&fresh, &committed_dir)?;
        // 同步 DB。
        let tx = self.db.unchecked_transaction().map_err(io_err)?;
        let ids_json = serde_json::to_string(&sol.replica_ids).unwrap();
        let digests_json = serde_json::to_string(&sol.data_digests).unwrap();
        tx.execute(
            "INSERT INTO stripe_solutions
               (object_pk,stripe_idx,rank,replica_ids,generation,data_digests,
                output_digest,tainted,matches_object_digest,committed)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,NULL,1)
             ON CONFLICT(object_pk,stripe_idx,output_digest)
             DO UPDATE SET committed=1",
            params![
                obj.id,
                stripe as i64,
                sol.replica_ids.len() as i64,
                ids_json,
                sol.generation,
                digests_json,
                sol.output_digest,
                sol.tainted as i64,
            ],
        )
        .map_err(io_err)?;
        let solution_id: i64 = tx
            .query_row(
                "SELECT id FROM stripe_solutions
                 WHERE object_pk=?1 AND stripe_idx=?2 AND output_digest=?3",
                params![obj.id, stripe as i64, sol.output_digest],
                |r| r.get(0),
            )
            .map_err(io_err)?;
        tx.execute(
            "INSERT INTO stripe_commits(object_pk,stripe_idx,solution_id,committed_at,run_id)
             VALUES(?1,?2,?3,?4,?5)
             ON CONFLICT(object_pk,stripe_idx) DO UPDATE SET
               solution_id=excluded.solution_id,
               committed_at=excluded.committed_at,
               run_id=excluded.run_id",
            params![obj.id, stripe as i64, solution_id, prov.committed_at, run_id],
        )
        .map_err(io_err)?;
        tx.commit().map_err(io_err)?;
        Ok(solution_id)
    }

    /// 删除某 stripe 的提交（隔离来源后需要重算）。
    pub fn drop_commit(&self, object_pk: i64, stripe: usize) -> std::io::Result<()> {
        self.db
            .execute(
                "DELETE FROM stripe_commits WHERE object_pk=?1 AND stripe_idx=?2;
                 UPDATE stripe_solutions SET committed=0
                 WHERE object_pk=?1 AND stripe_idx=?2",
                params![object_pk, stripe as i64],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    pub fn quarantine_source(&self, object_pk: i64, source: &str) -> std::io::Result<bool> {
        let n = self
            .db
            .execute(
                "INSERT OR IGNORE INTO quarantined_sources(object_pk,source) VALUES(?1,?2)",
                params![object_pk, source],
            )
            .map_err(io_err)?;
        Ok(n > 0)
    }

    pub fn unquarantine_source(&self, object_pk: i64, source: &str) -> std::io::Result<bool> {
        let n = self
            .db
            .execute(
                "DELETE FROM quarantined_sources WHERE object_pk=?1 AND source=?2",
                params![object_pk, source],
            )
            .map_err(io_err)?;
        Ok(n > 0)
    }

    pub fn quarantined(&self, object_pk: i64) -> std::io::Result<Vec<String>> {
        let mut s = self
            .db
            .prepare("SELECT source FROM quarantined_sources WHERE object_pk=?1 ORDER BY source")
            .map_err(io_err)?;
        let rows = s
            .query_map(params![object_pk], |r| r.get::<_, String>(0))
            .map_err(io_err)?;
        rows.map(|r| r.map_err(io_err)).collect()
    }

    pub fn distinct_sources(&self, object_pk: i64) -> std::io::Result<Vec<String>> {
        let mut s = self
            .db
            .prepare(
                "SELECT DISTINCT source FROM replicas WHERE object_pk=?1
                 ORDER BY CASE source WHEN '' THEN 1 ELSE 0 END, source",
            )
            .map_err(io_err)?;
        let rows = s
            .query_map(params![object_pk], |r| r.get::<_, String>(0))
            .map_err(io_err)?;
        rows.map(|r| r.map_err(io_err)).collect()
    }

    pub fn start_run(
        &self,
        run_id: &str,
        object_pk: i64,
        budget: u64,
    ) -> std::io::Result<()> {
        self.db
            .execute(
                "INSERT INTO runs(run_id,object_pk,started_at,budget,combos_checked,completed)
                 VALUES(?1,?2,?3,?4,0,0)
                 ON CONFLICT(run_id) DO NOTHING",
                params![run_id, object_pk, now_ts(), budget as i64],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    pub fn update_run(
        &self,
        run_id: &str,
        combos_checked: u64,
        completed: bool,
    ) -> std::io::Result<()> {
        self.db
            .execute(
                "UPDATE runs SET combos_checked=?2, completed=?3 WHERE run_id=?1",
                params![run_id, combos_checked as i64, completed as i64],
            )
            .map(|_| ())
            .map_err(io_err)
    }

    pub fn last_run(&self, object_pk: i64) -> std::io::Result<Option<(String, i64, i64, bool)>> {
        self.db
            .query_row(
                "SELECT run_id,budget,combos_checked,completed FROM runs
                 WHERE object_pk=?1 ORDER BY started_at DESC LIMIT 1",
                params![object_pk],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? != 0)),
            )
            .optional()
            .map_err(io_err)
    }
}
