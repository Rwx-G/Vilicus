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
pub fn read_epoch(file: &ModuleFile) -> Result<KeyEpoch> {
    let path = file.epoch_path();
    let text = fs::read_to_string(&path)?;
    KeyEpoch::from_sidecar(&text).ok_or(Error::MalformedEpoch(path))
}

/// Writes the sidecar atomically: a temporary file written and synced, renamed over the sidecar,
/// then the directory synced, so a crash leaves the old sidecar or the new one, never a torn one.
pub(crate) fn write_epoch_sidecar(file: &ModuleFile, epoch: KeyEpoch) -> Result<()> {
    let path = file.epoch_path();
    let staging = file
        .directory
        .join(format!("{}.epoch.tmp", file.file_name()));
    let mut out = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&staging)?;
    out.write_all(epoch.to_sidecar().as_bytes())?;
    out.sync_all()?;
    drop(out);
    fs::rename(&staging, &path)?;
    File::open(&file.directory)?.sync_all()?;
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
