//! The mark of a failed migration (AD-23, AD-54 `failed migration`, D84): a clear sidecar
//! `<file>.migration-failed` beside a module file whose migration failed, naming the code it
//! failed under, so the Core holds the file's state across starts instead of trying the same
//! migration again at every unlock. The file itself is never touched by a failure (AD-23).
//!
//! The mark holds no secret and no record content: the identity of the code (a SHA-256 the Core
//! computes over its migrations and the module's declaration), the track and the version that
//! failed. It is written atomically, like the key epoch sidecar, so a crash leaves the previous
//! mark or the new one. What the mark means, and when a mark names another code, is the Core's.

use core::fmt;
use std::fs;
use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::file::{self, ModuleFile};
use crate::handle::{self, MigrationTrack};

/// The first line of a mark, naming its format.
const MARK_HEADER: &str = "vilicus failed migration 1";

/// A failed migration of one file, as its mark records it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailedMigrationMark {
    /// The identity of the code the migration failed under, as the Core computes it.
    pub code: [u8; 32],
    /// The track of the migration that failed.
    pub track: MigrationTrack,
    /// The version that migration would have brought the track to.
    pub version: u32,
}

impl fmt::Display for FailedMigrationMark {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} migration {} failed under code {}",
            self.track,
            self.version,
            hex(&self.code)
        )
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn track_name(track: MigrationTrack) -> &'static str {
    match track {
        MigrationTrack::Core => "core",
        MigrationTrack::Module => "module",
    }
}

impl FailedMigrationMark {
    fn to_text(self) -> String {
        format!(
            "{MARK_HEADER}\ncode {}\ntrack {}\nversion {}\n",
            hex(&self.code),
            track_name(self.track),
            self.version
        )
    }

    /// The mark `text` holds, in exactly the form [`to_text`](Self::to_text) writes.
    fn from_text(text: &str) -> Option<Self> {
        let mut lines = text.strip_suffix('\n')?.split('\n');
        if lines.next()? != MARK_HEADER {
            return None;
        }
        let mut value = |name: &str| lines.next()?.strip_prefix(name)?.strip_prefix(' ');
        let code = value("code")?;
        let track = value("track")?;
        let version = value("version")?;
        let canonical_hex = code.len() == 64
            && code
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let canonical_version = !version.is_empty()
            && version.bytes().all(|byte| byte.is_ascii_digit())
            && (version == "0" || !version.starts_with('0'));
        if !canonical_hex || !canonical_version || lines.next().is_some() {
            return None;
        }
        let mut digest = [0; 32];
        for (byte, pair) in digest.iter_mut().zip(code.as_bytes().chunks(2)) {
            *byte = u8::from_str_radix(core::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(Self {
            code: digest,
            track: [MigrationTrack::Core, MigrationTrack::Module]
                .into_iter()
                .find(|known| track_name(*known) == track)?,
            version: version.parse().ok()?,
        })
    }
}

/// The path of the mark of `file`, `<file>.migration-failed`.
pub fn failed_migration_mark_path(file: &ModuleFile) -> PathBuf {
    file.directory()
        .join(format!("{}.migration-failed", file.file_name()))
}

/// The mark of a failed migration beside `file`, if one is there. A mark in any other form than
/// the one [`mark_failed_migration`] writes is [`Error::MalformedFailureMark`].
pub fn failed_migration_mark(file: &ModuleFile) -> Result<Option<FailedMigrationMark>> {
    let path = failed_migration_mark_path(file);
    match fs::read_to_string(&path) {
        Ok(text) => FailedMigrationMark::from_text(&text)
            .map(Some)
            .ok_or(Error::MalformedFailureMark(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Writes `mark` beside `file` atomically, replacing any earlier mark.
pub fn mark_failed_migration(file: &ModuleFile, mark: FailedMigrationMark) -> Result<()> {
    file::write_atomically(&failed_migration_mark_path(file), mark.to_text().as_bytes())
}

/// Removes the mark beside `file`, and what an interrupted write of one left; nothing to remove is
/// no error.
pub fn clear_failed_migration_mark(file: &ModuleFile) -> Result<()> {
    let path = failed_migration_mark_path(file);
    let mut staging = path.as_os_str().to_owned();
    staging.push(".tmp");
    let present = path.exists() || PathBuf::from(&staging).exists();
    handle::remove_if_present(&path)?;
    handle::remove_if_present(&PathBuf::from(staging))?;
    if present {
        file::sync_parent(&path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mark() -> FailedMigrationMark {
        FailedMigrationMark {
            code: [0xa5; 32],
            track: MigrationTrack::Module,
            version: 12,
        }
    }

    #[test]
    fn the_mark_round_trips_and_refuses_any_other_shape() {
        let text = mark().to_text();
        assert_eq!(
            text,
            format!(
                "vilicus failed migration 1\ncode {}\ntrack module\nversion 12\n",
                "a5".repeat(32)
            )
        );
        assert_eq!(FailedMigrationMark::from_text(&text), Some(mark()));
        let core = FailedMigrationMark {
            track: MigrationTrack::Core,
            version: 0,
            ..mark()
        };
        assert_eq!(FailedMigrationMark::from_text(&core.to_text()), Some(core));
        let refused = [
            String::new(),
            text.trim_end().to_owned(),
            text.replace("migration 1", "migration 2"),
            text.replace("a5a5", "A5A5"),
            text.replace(&"a5".repeat(32), &"a5".repeat(31)),
            text.replace("track module", "track Module"),
            text.replace("version 12", "version 012"),
            text.replace("version 12", "version -1"),
            text.replace("version 12", "version 4294967296"),
            format!("{text}extra 1\n"),
            text.replace('\n', "\r\n"),
        ];
        for text in refused {
            assert_eq!(FailedMigrationMark::from_text(&text), None, "{text:?}");
        }
    }
}
