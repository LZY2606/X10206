use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror_lite::Error)]
pub enum StorageError {
    Io(String),
    Blocked(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(message) | Self::Blocked(message) => write!(formatter, "{message}"),
        }
    }
}

impl std::error::Error for StorageError {}

pub trait Storage: Send + Sync {
    fn write_atomic(&self, path: &str, bytes: &[u8]) -> Result<(), StorageError>;
    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError>;
    fn create_dir_all(&self, path: &str) -> Result<(), StorageError>;
    fn rename(&self, from: &str, to: &str) -> Result<(), StorageError>;
}

pub struct FileStorage {
    root: PathBuf,
}

impl FileStorage {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_path_buf(),
        }
    }

    fn resolve(&self, path: &str) -> Result<PathBuf, StorageError> {
        let candidate = self.root.join(path);
        let normalized_root = self
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.root.clone());
        let normalized_candidate = if candidate.exists() {
            candidate
                .canonicalize()
                .map_err(|error| StorageError::Io(error.to_string()))?
        } else {
            candidate.clone()
        };
        if !normalized_candidate.starts_with(&normalized_root) {
            return Err(StorageError::Io("路径逃出数据目录".to_string()));
        }
        Ok(candidate)
    }
}

impl Storage for FileStorage {
    fn write_atomic(&self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let target = self.resolve(path)?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| StorageError::Io(error.to_string()))?;
        }
        let temporary = target.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        {
            let mut file = fs::File::create(&temporary)
                .map_err(|error| StorageError::Io(error.to_string()))?;
            file.write_all(bytes)
                .map_err(|error| StorageError::Io(error.to_string()))?;
            file.sync_all()
                .map_err(|error| StorageError::Io(error.to_string()))?;
        }
        fs::rename(&temporary, &target).map_err(|error| StorageError::Io(error.to_string()))
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        fs::read(self.resolve(path)?).map_err(|error| StorageError::Io(error.to_string()))
    }

    fn create_dir_all(&self, path: &str) -> Result<(), StorageError> {
        fs::create_dir_all(self.resolve(path)?)
            .map_err(|error| StorageError::Io(error.to_string()))
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), StorageError> {
        fs::rename(self.resolve(from)?, self.resolve(to)?)
            .map_err(|error| StorageError::Io(error.to_string()))
    }
}

#[derive(Default, Clone)]
pub struct FailureInjection {
    blocked_substrings: Arc<Mutex<HashSet<String>>>,
    written: Arc<Mutex<HashSet<String>>>,
    fail_once_substrings: Arc<Mutex<HashSet<String>>>,
}

impl FailureInjection {
    pub fn block_substring(&self, value: impl Into<String>) {
        self.blocked_substrings.lock().unwrap().insert(value.into());
    }

    pub fn fail_once_substring(&self, value: impl Into<String>) {
        self.fail_once_substrings
            .lock()
            .unwrap()
            .insert(value.into());
    }

    pub fn written_paths(&self) -> HashSet<String> {
        self.written.lock().unwrap().clone()
    }

    fn is_blocked(&self, path: &str) -> bool {
        let blocked = self.blocked_substrings.lock().unwrap();
        if blocked.iter().any(|value| path.contains(value)) {
            return true;
        }
        drop(blocked);
        let mut once = self.fail_once_substrings.lock().unwrap();
        if let Some(value) = once
            .iter()
            .find(|value| path.contains(value.as_str()))
            .cloned()
        {
            once.remove(&value);
            return true;
        }
        false
    }
}

pub struct MemoryStorage {
    files: Arc<Mutex<HashSet<PathBuf>>>,
    bytes: Arc<Mutex<std::collections::HashMap<PathBuf, Vec<u8>>>>,
    injection: FailureInjection,
}

impl MemoryStorage {
    pub fn new(injection: FailureInjection) -> Self {
        Self {
            files: Arc::new(Mutex::new(HashSet::new())),
            bytes: Arc::new(Mutex::new(std::collections::HashMap::new())),
            injection,
        }
    }

    fn resolve(path: &str) -> PathBuf {
        let mut normalized = PathBuf::from(path.trim_start_matches('/'));
        if normalized.components().any(|component| {
            matches!(component, std::path::Component::ParentDir)
        }) {
            normalized = PathBuf::from("invalid-escape");
        }
        normalized
    }
}

impl Storage for MemoryStorage {
    fn write_atomic(&self, path: &str, bytes: &[u8]) -> Result<(), StorageError> {
        if self.injection.is_blocked(path) {
            return Err(StorageError::Blocked(format!("注入写失败：{path}")));
        }
        let resolved = Self::resolve(path);
        self.files.lock().unwrap().insert(resolved.clone());
        self.bytes.lock().unwrap().insert(resolved, bytes.to_vec());
        Ok(())
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let resolved = Self::resolve(path);
        self.bytes
            .lock()
            .unwrap()
            .get(&resolved)
            .cloned()
            .ok_or_else(|| StorageError::Io(format!("未找到 {path}")))
    }

    fn create_dir_all(&self, path: &str) -> Result<(), StorageError> {
        self.files.lock().unwrap().insert(Self::resolve(path));
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> Result<(), StorageError> {
        let from_path = Self::resolve(from);
        let to_path = Self::resolve(to);
        let mut files = self.files.lock().unwrap();
        files.remove(&from_path);
        files.insert(to_path);
        Ok(())
    }
}

pub type DynStorage = Arc<dyn Storage>;
