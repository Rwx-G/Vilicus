//! Side measurements the gate run depends on: how long an AD-31 writer pause lasts as a file
//! and its WAL grow, and what one `fdatasync` costs on the storage under the run.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

use rusqlite::params;

use crate::crypto;
use crate::load::copy_and_hash;
use crate::stats::Summary;
use crate::storage;
use crate::writer::Writer;

/// Approximate bytes a seeded record takes in the file (400-byte body plus envelope).
const BYTES_PER_SEED_ROW: u64 = 470;

/// One pause measured on one file.
#[derive(Clone, Copy, Debug)]
pub struct PauseRow {
    pub file_mib: f64,
    pub wal_mib: f64,
    pub wal_updates: u32,
    /// From the pause request to the paused writer: the TRUNCATE checkpoint.
    pub checkpoint: Duration,
    /// Copy with SHA-256 and `fsync` while paused.
    pub copy: Duration,
    /// The whole time writes to the file wait.
    pub pause: Duration,
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / f64::from(1 << 20)
}

/// Seeds a file of about `target_mib` MiB, leaves `wal_updates` single-row commits in its WAL
/// with automatic checkpoints off (a long day without a checkpoint), then pauses its writer,
/// copies the file and resumes, as a backup cycle does.
pub fn pause_bound(workdir: &Path, target_mib: u64, wal_updates: u32) -> Result<PauseRow, String> {
    std::fs::create_dir_all(workdir).map_err(|e| e.to_string())?;
    let path = workdir.join(format!("bound-{target_mib}.db"));
    let key = crypto::random::<32>();
    let rows =
        u32::try_from(target_mib * (1 << 20) / BYTES_PER_SEED_ROW).map_err(|e| e.to_string())?;
    storage::create_module_file(&path, &key, rows, 400, 0).map_err(|e| e.to_string())?;
    let writer = Writer::spawn(
        "bound",
        storage::open_writer(&path, &key).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    // The writer connection stays open, so closing the filler checkpoints nothing.
    let filler = storage::open_backup_target(&path, &key).map_err(|e| e.to_string())?;
    filler
        .pragma_update(None, "wal_autocheckpoint", 0)
        .map_err(|e| e.to_string())?;
    filler
        .pragma_update(None, "synchronous", "OFF")
        .map_err(|e| e.to_string())?;
    let mut state = u64::from_be_bytes(crypto::random());
    for update in 0..wal_updates {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let id = (state >> 33) % u64::from(rows) + 1;
        filler
            .execute(
                "UPDATE records SET title = ?1, rev = rev + 1 WHERE id = ?2",
                params![format!("update {update}"), id as i64],
            )
            .map_err(|e| e.to_string())?;
    }
    drop(filler);
    let file_bytes = std::fs::metadata(&path).map_err(|e| e.to_string())?.len();
    let wal_bytes = std::fs::metadata(path.with_extension("db-wal"))
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let target = workdir.join(format!("bound-{target_mib}.copy"));
    let (checkpoint, copy, pause) = runtime.block_on(async {
        let requested = Instant::now();
        let guard = writer.pause().await?;
        let paused = Instant::now();
        let source = path.clone();
        tokio::task::spawn_blocking(move || copy_and_hash(&source, &target, None))
            .await
            .map_err(|e| e.to_string())??;
        let copied = Instant::now();
        drop(guard);
        Ok::<_, String>((paused - requested, copied - paused, copied - requested))
    })?;
    drop(writer);
    for leftover in [
        path.clone(),
        path.with_extension("db-wal"),
        path.with_extension("db-shm"),
        workdir.join(format!("bound-{target_mib}.copy")),
    ] {
        // Scratch files; one left behind only costs disk space in the container.
        let _ = std::fs::remove_file(leftover);
    }
    Ok(PauseRow {
        file_mib: mib(file_bytes),
        wal_mib: mib(wal_bytes),
        wal_updates,
        checkpoint,
        copy,
        pause,
    })
}

/// Times `iterations` rounds of a 4 KiB write followed by `fdatasync` in `dir`.
pub fn fsync_bench(dir: &Path, iterations: u32) -> Result<Summary, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let path = dir.join("fsync-bench.bin");
    let mut file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    let block = [0x5a_u8; 4096];
    let mut samples = Vec::new();
    for _ in 0..iterations {
        let started = Instant::now();
        file.write_all(&block).map_err(|e| e.to_string())?;
        file.sync_data().map_err(|e| e.to_string())?;
        samples.push(started.elapsed());
    }
    drop(file);
    let _ = std::fs::remove_file(&path);
    Ok(Summary::of("4 KiB write + fdatasync", &samples))
}
