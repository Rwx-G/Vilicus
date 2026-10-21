//! Module files and their key epoch (AD-5, D3): `<module>.<partition>.db`, one SQLCipher file
//! with one key, and the clear sidecar `<file>.epoch` that names the key epoch needed to derive
//! that key, repeated in the file's `_meta` table for a cross-check.

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use vilicus_types::{Id, ModuleName};

use crate::error::{Error, Result};

/// The partition a module file belongs to (AD-5, AD-37).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Partition {
    /// The household partition.
    Household,
    /// The home partition, one per instance.
    Home,
    /// A member's personal partition, named by the member's id.
    Member(Id),
}

impl fmt::Display for Partition {
    /// The partition as it appears in a file name: `household`, `home` or the member id's text.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Household => formatter.write_str("household"),
            Self::Home => formatter.write_str("home"),
            Self::Member(id) => write!(formatter, "{id}"),
        }
    }
}

/// One module file: the module and partition it belongs to and the directory that holds it.
/// Module names carry no dot and partition labels no dot either, so a file name names one pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleFile {
    directory: PathBuf,
    module: ModuleName,
    partition: Partition,
}

impl ModuleFile {
    /// The file of `module` in `partition`, under `directory`.
    pub fn new(directory: impl Into<PathBuf>, module: ModuleName, partition: Partition) -> Self {
        Self {
            directory: directory.into(),
            module,
            partition,
        }
    }

    /// The module the file belongs to.
    pub fn module(&self) -> &ModuleName {
        &self.module
    }

    /// The partition the file belongs to.
    pub fn partition(&self) -> Partition {
        self.partition
    }

    /// The directory that holds the file, its WAL and its sidecar.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// The file name, `<module>.<partition>.db`.
    pub fn file_name(&self) -> String {
        format!("{}.{}.db", self.module, self.partition)
    }

    /// The path of the database file.
    pub fn path(&self) -> PathBuf {
        self.directory.join(self.file_name())
    }

    /// The path of the clear key epoch sidecar, `<file>.epoch`.
    pub fn epoch_path(&self) -> PathBuf {
        self.directory.join(format!("{}.epoch", self.file_name()))
    }

    /// The path of SQLite's WAL file, `<file>-wal`.
    pub fn wal_path(&self) -> PathBuf {
        self.directory.join(format!("{}-wal", self.file_name()))
    }

    /// The path of the pending sidecar, `<file>.epoch.next`, present only while a change of key
    /// epoch is in progress (see [`crate::Handle::write_epoch`]).
    pub fn pending_epoch_path(&self) -> PathBuf {
        self.directory
            .join(format!("{}.epoch.next", self.file_name()))
    }

    /// The path `create` builds a new file under, `<file>.create`, renamed into place once the
    /// file and its sidecar are durable.
    pub fn staging_path(&self) -> PathBuf {
        self.directory.join(format!("{}.create", self.file_name()))
    }
}

/// The sidecar path of any database path: `<path>.epoch`, for module files, copies and backups.
pub(crate) fn sidecar_of(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push(".epoch");
    PathBuf::from(name)
}

/// The key epoch of a module file: the version of the partition root its key derives from and
/// the file's generation (`doc/key-management.md` section 2). A counter, not a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyEpoch {
    /// The version of the partition root (member DEK, HK or home partition root).
    pub partition_root_version: u32,
    /// The file generation, which a rekey increases.
    pub generation: u32,
}

impl fmt::Display for KeyEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "partition root version {}, generation {}",
            self.partition_root_version, self.generation
        )
    }
}

/// The `_meta` keys of the two epoch values; `_meta` is a key-value table, so the module and
/// Core schema versions of AD-26 join it later as rows, without a schema change.
pub(crate) const META_PARTITION_ROOT_VERSION: &str = "partition_root_version";
pub(crate) const META_GENERATION: &str = "generation";

const SIDECAR_HEADER: &str = "vilicus key epoch 1";

impl KeyEpoch {
    fn to_sidecar(self) -> String {
        format!(
            "{SIDECAR_HEADER}\n{META_PARTITION_ROOT_VERSION} {}\n{META_GENERATION} {}\n",
            self.partition_root_version, self.generation
        )
    }

    fn from_sidecar(text: &str) -> Option<Self> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        if lines.next()? != SIDECAR_HEADER {
            return None;
        }
        let mut value = |name: &str| -> Option<u32> {
            let digits = lines.next()?.strip_prefix(name)?.strip_prefix(' ')?;
            let canonical = !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_digit())
                && (digits == "0" || !digits.starts_with('0'));
            canonical.then(|| digits.parse().ok()).flatten()
        };
        let epoch = Self {
            partition_root_version: value(META_PARTITION_ROOT_VERSION)?,
            generation: value(META_GENERATION)?,
        };
        lines.next().is_none().then_some(epoch)
    }
}

/// Reads the key epoch from the sidecar of `file`, which the caller needs to derive the file key.
/// A missing sidecar is [`Error::EpochSidecarMissing`]; a pending sidecar, left by an interrupted
/// change of epoch, is [`Error::EpochTransitionPending`], so neither epoch is used silently.
pub fn read_epoch(file: &ModuleFile) -> Result<KeyEpoch> {
    let current = read_sidecar(&file.epoch_path())?;
    match read_sidecar_if_present(&file.pending_epoch_path())? {
        Some(pending) => Err(Error::EpochTransitionPending { current, pending }),
        None => Ok(current),
    }
}

/// The epoch of the sidecar at `path`.
pub(crate) fn read_sidecar(path: &Path) -> Result<KeyEpoch> {
    read_sidecar_if_present(path)?.ok_or_else(|| Error::EpochSidecarMissing(path.to_path_buf()))
}

/// The epoch of the sidecar at `path`, or `None` when there is no file there.
pub(crate) fn read_sidecar_if_present(path: &Path) -> Result<Option<KeyEpoch>> {
    match fs::read_to_string(path) {
        Ok(text) => KeyEpoch::from_sidecar(&text)
            .map(Some)
            .ok_or_else(|| Error::MalformedEpoch(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Writes a sidecar atomically: a temporary file written and synced, renamed over `path`, then
/// the directory synced, so a crash leaves the old sidecar or the new one, never a torn one.
pub(crate) fn write_sidecar(path: &Path, epoch: KeyEpoch) -> Result<()> {
    let mut staging = path.as_os_str().to_owned();
    staging.push(".tmp");
    let staging = PathBuf::from(staging);
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staging)?;
    out.write_all(epoch.to_sidecar().as_bytes())?;
    out.sync_all()?;
    drop(out);
    fs::rename(&staging, path)?;
    sync_parent(path)
}

/// Syncs the directory that holds `path`, so a rename or a removal in it is durable.
pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    let directory = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member() -> Id {
        "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"
            .parse()
            .expect("test id")
    }

    #[test]
    fn a_file_is_named_module_dot_partition_dot_db() {
        let tasks = ModuleName::from_static("tasks");
        let cases = [
            (Partition::Household, "tasks.household.db"),
            (Partition::Home, "tasks.home.db"),
            (
                Partition::Member(member()),
                "tasks.017f22e2-79b0-7cc3-98c4-dc0c0c07398f.db",
            ),
        ];
        for (partition, name) in cases {
            let file = ModuleFile::new("/data", tasks.clone(), partition);
            assert_eq!(file.file_name(), name);
            assert_eq!(file.path(), Path::new("/data").join(name));
            assert_eq!(
                file.epoch_path(),
                Path::new("/data").join(format!("{name}.epoch"))
            );
        }
    }

    #[test]
    fn the_sidecar_round_trips_and_refuses_any_other_shape() {
        let epoch = KeyEpoch {
            partition_root_version: 3,
            generation: 0,
        };
        let text = epoch.to_sidecar();
        assert_eq!(
            text,
            "vilicus key epoch 1\npartition_root_version 3\ngeneration 0\n"
        );
        assert_eq!(KeyEpoch::from_sidecar(&text), Some(epoch));
        let refused = [
            "",
            "vilicus key epoch 1\npartition_root_version 3\ngeneration 0",
            "vilicus key epoch 2\npartition_root_version 3\ngeneration 0\n",
            "vilicus key epoch 1\npartition_root_version 03\ngeneration 0\n",
            "vilicus key epoch 1\npartition_root_version +3\ngeneration 0\n",
            "vilicus key epoch 1\npartition_root_version 3\ngeneration -1\n",
            "vilicus key epoch 1\ngeneration 0\npartition_root_version 3\n",
            "vilicus key epoch 1\npartition_root_version 3\ngeneration 0\nextra 1\n",
            "vilicus key epoch 1\npartition_root_version 4294967296\ngeneration 0\n",
            "vilicus key epoch 1\r\npartition_root_version 3\r\ngeneration 0\r\n",
        ];
        for text in refused {
            assert_eq!(KeyEpoch::from_sidecar(text), None, "{text:?}");
        }
    }
}
