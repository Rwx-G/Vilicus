//! Spike databases: one SQLCipher (or plain) file in WAL mode per scenario, the journal
//! workload of story 3.6 and the crypto-shredding workload, and byte-level views of the
//! main file, the WAL and the shm.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use std::ffi::c_int;

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, ffi, params};

use crate::pages::{self, Encoding, WalHeader};
use crate::rng::{Rng, to_hex};
use crate::scan::NeedleSet;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const SEED: u64 = 0xE17;
const DAY: i64 = 86_400;
/// FR-29 and D113: undo journal entries are kept 30 days.
const RETENTION_DAYS: i64 = 30;
const NOW: i64 = 1_790_000_000;
const JOURNAL_ROWS: usize = 48;
const JOURNAL_TRANSACTIONS: usize = 4;
/// A before-image of this many random bytes spills into overflow pages; the smaller one
/// stays inside its b-tree leaf. Images are random bytes rather than JSON text so that
/// the 8-byte scan pass cannot match by accident.
const OVERFLOW_IMAGE_BYTES: usize = 12_000;
const INLINE_IMAGE_BYTES: usize = 400;
const AFTER_IMAGE_BYTES: usize = 200;
const SHRED_RECORDS: i64 = 20;
/// Stand-in for a 256-bit record key wrapped with an AEAD: 32 key bytes plus a 16-byte tag.
const WRAPPED_KEY_BYTES: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The product case: a SQLCipher file opened with a raw 256-bit key.
    SqlCipher,
    /// The same pages without a key, to show the bytes directly.
    Plain,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::SqlCipher => "sqlcipher",
            Mode::Plain => "plain",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecureDelete {
    Off,
    Fast,
    On,
}

impl SecureDelete {
    /// The keyword to set and the value the pragma reports back. FAST must be set by
    /// name: SQLite reads a numeric argument as a boolean, so `2` would mean ON.
    fn pragma(self) -> (&'static str, i64) {
        match self {
            SecureDelete::Off => ("OFF", 0),
            SecureDelete::On => ("ON", 1),
            SecureDelete::Fast => ("FAST", 2),
        }
    }
}

static NEXT_DATABASE: AtomicU64 = AtomicU64::new(0);

pub struct Db {
    dir: PathBuf,
    path: PathBuf,
    encoding: Encoding,
    secure_delete: SecureDelete,
    conn: Option<Connection>,
}

impl Db {
    pub fn create(
        name: &str,
        mode: Mode,
        secure_delete: SecureDelete,
        rng: &mut Rng,
    ) -> Result<Self> {
        let number = NEXT_DATABASE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("e17-spike-{}-{number}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let encoding = match mode {
            Mode::Plain => Encoding::Plain,
            Mode::SqlCipher => Encoding::SqlCipher(rng.bytes(32).try_into().expect("32 bytes")),
        };
        let mut db = Self {
            path: dir.join("module.db"),
            dir,
            encoding,
            secure_delete,
            conn: None,
        };
        let conn = db.open_connection()?;
        let journal_mode: String =
            conn.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if journal_mode != "wal" {
            return Err(format!("journal_mode is {journal_mode}, not wal").into());
        }
        db.conn = Some(conn);
        Ok(db)
    }

    /// A connection with the key applied and nothing else, as any caller that forgets
    /// the per-connection pragmas would get it.
    pub fn open_keyed(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)?;
        if let Encoding::SqlCipher(key) = self.encoding {
            conn.pragma_update(None, "key", format!("x'{}'", to_hex(&key)))?;
        }
        // Fails with "file is not a database" when the key does not open the file.
        conn.query_row("SELECT count(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })?;
        Ok(conn)
    }

    /// A connection as the product opens one: key first, then `secure_delete`.
    pub fn open_connection(&self) -> Result<Connection> {
        let conn = self.open_keyed()?;
        let (keyword, wanted) = self.secure_delete.pragma();
        let applied: i64 =
            conn.query_row(&format!("PRAGMA secure_delete = {keyword}"), [], |row| {
                row.get(0)
            })?;
        if applied != wanted {
            return Err(format!("secure_delete is {applied}, wanted {wanted}").into());
        }
        Ok(conn)
    }

    pub fn conn(&self) -> &Connection {
        self.conn.as_ref().expect("the spike connection is open")
    }

    pub fn encoding(&self) -> Encoding {
        self.encoding
    }

    /// Runs `PRAGMA wal_checkpoint(<mode>)` and returns (busy, log frames, checkpointed frames).
    pub fn checkpoint(&self, mode: &str) -> Result<(i64, i64, i64)> {
        Ok(self
            .conn()
            .query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?)
    }

    pub fn vacuum(&self) -> Result<()> {
        Ok(self.conn().execute_batch("VACUUM")?)
    }

    /// Sets `PRAGMA journal_size_limit` on the spike connection and returns the value applied.
    pub fn set_journal_size_limit(&self, bytes: i64) -> Result<i64> {
        Ok(self
            .conn()
            .query_row(&format!("PRAGMA journal_size_limit = {bytes}"), [], |row| {
                row.get(0)
            })?)
    }

    /// Closes the spike connection; as the last connection, SQLite checkpoints and removes the WAL.
    pub fn close(&mut self) -> Result<()> {
        if let Some(conn) = self.conn.take() {
            conn.close().map_err(|(_, error)| error)?;
        }
        Ok(())
    }

    pub fn wal_exists(&self) -> bool {
        suffixed(&self.path, "-wal").exists()
    }

    pub fn images(&self) -> Result<Images> {
        let main_raw = pages::read_or_empty(&self.path)?;
        let wal_raw = pages::read_or_empty(&suffixed(&self.path, "-wal"))?;
        let shm_raw = pages::read_or_empty(&suffixed(&self.path, "-shm"))?;
        let wal = pages::wal_pages(&wal_raw, self.encoding)?;
        Ok(Images {
            main: pages::main_file_pages(&main_raw, self.encoding)?,
            main_raw,
            wal: wal.pages,
            wal_frames: wal.frames,
            wal_header: wal.header,
            wal_raw,
            shm_raw,
        })
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        self.conn.take();
        // Scratch files under the temp directory; a leftover is harmless and not worth a panic.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// Bytes of the three files at one moment, decoded (decrypted) and raw.
pub struct Images {
    pub main_raw: Vec<u8>,
    pub main: Vec<u8>,
    pub wal_raw: Vec<u8>,
    pub wal: Vec<u8>,
    pub wal_frames: usize,
    pub wal_header: Option<WalHeader>,
    /// The shm is never encrypted by SQLCipher, so it is scanned as is.
    pub shm_raw: Vec<u8>,
}

impl Images {
    /// Needles found in the decrypted main file, the decrypted WAL frames and the shm.
    pub fn decoded(&self, needles: &NeedleSet) -> Found {
        Found {
            main: needles.found_in(&self.main),
            wal: needles.found_in(&self.wal),
            shm: needles.found_in(&self.shm_raw),
            of: needles.len(),
        }
    }

    /// The same scan with the 8-byte window.
    pub fn decoded_short(&self, needles: &NeedleSet) -> Found {
        Found {
            main: needles.found_in_short(&self.main),
            wal: needles.found_in_short(&self.wal),
            shm: needles.found_in_short(&self.shm_raw),
            of: needles.len(),
        }
    }

    /// Needles found in the bytes as stored, without decryption.
    pub fn raw(&self, needles: &NeedleSet) -> Found {
        Found {
            main: needles.found_in(&self.main_raw),
            wal: needles.found_in(&self.wal_raw),
            shm: needles.found_in(&self.shm_raw),
            of: needles.len(),
        }
    }

    pub fn sizes(&self) -> String {
        format!(
            "file {} B, WAL {} B ({} frames), shm {} B",
            self.main_raw.len(),
            self.wal_raw.len(),
            self.wal_frames,
            self.shm_raw.len()
        )
    }
}

/// How many distinct needles have at least one window (16 or 8 bytes) in each file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub main: usize,
    pub wal: usize,
    pub shm: usize,
    pub of: usize,
}

impl Found {
    pub fn nowhere(&self) -> bool {
        self.main == 0 && self.wal == 0 && self.shm == 0
    }
}

impl fmt::Display for Found {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {}/{}, WAL {}/{}, shm {}/{}",
            self.main, self.of, self.wal, self.of, self.shm, self.of
        )
    }
}

/// The `_journal` table of spine AD-26 holding before and after images of known plaintext.
pub struct Journal {
    pub db: Db,
    pub live: NeedleSet,
    pub expired: NeedleSet,
    pub expired_inline: NeedleSet,
    pub expired_overflow: NeedleSet,
}

/// Writes the journal rows. Half are older than the retention period, interleaved with
/// live rows so that both share b-tree pages; half of each kind spill into overflow pages.
/// The `call_id` column has a unique index, so index cells carry known content too.
pub fn journal(
    name: &str,
    mode: Mode,
    secure_delete: SecureDelete,
    checkpoint_before_purge: bool,
) -> Result<Journal> {
    let mut rng = Rng::new(SEED);
    let db = Db::create(name, mode, secure_delete, &mut rng)?;
    db.conn().execute_batch(
        "CREATE TABLE _journal (
             id INTEGER PRIMARY KEY,
             call_id TEXT NOT NULL UNIQUE,
             principal TEXT NOT NULL,
             created_at INTEGER NOT NULL,
             before_image BLOB NOT NULL,
             after_image BLOB NOT NULL
         );
         CREATE INDEX _journal_created_at ON _journal (created_at);",
    )?;
    let mut live = NeedleSet::default();
    let mut expired = NeedleSet::default();
    let mut expired_inline = NeedleSet::default();
    let mut expired_overflow = NeedleSet::default();
    let rows: Vec<usize> = (0..JOURNAL_ROWS).collect();
    for transaction_rows in rows.chunks(JOURNAL_ROWS / JOURNAL_TRANSACTIONS) {
        let tx = db.conn().unchecked_transaction()?;
        for &row in transaction_rows {
            let is_expired = row % 2 == 1;
            let overflows = row % 4 >= 2;
            let call_id = rng.hex(16);
            let before_image = rng.bytes(if overflows {
                OVERFLOW_IMAGE_BYTES
            } else {
                INLINE_IMAGE_BYTES
            });
            let after_image = rng.bytes(AFTER_IMAGE_BYTES);
            let created_at = if is_expired {
                NOW - (RETENTION_DAYS + 1) * DAY
            } else {
                NOW - DAY
            };
            tx.execute(
                "INSERT INTO _journal (call_id, principal, created_at, before_image, after_image)
                 VALUES (?1, 'member:user01', ?2, ?3, ?4)",
                params![call_id, created_at, before_image, after_image],
            )?;
            for field in [call_id.as_bytes(), &before_image, &after_image] {
                if is_expired {
                    expired.add(field);
                    if overflows {
                        expired_overflow.add(field);
                    } else {
                        expired_inline.add(field);
                    }
                } else {
                    live.add(field);
                }
            }
        }
        tx.commit()?;
    }
    if checkpoint_before_purge {
        db.checkpoint("TRUNCATE")?;
    }
    Ok(Journal {
        db,
        live,
        expired,
        expired_inline,
        expired_overflow,
    })
}

impl Journal {
    /// The retention purge of story 3.6: one DELETE of every entry past the undo period.
    pub fn purge_expired(&self) -> Result<usize> {
        Ok(self.db.conn().execute(
            "DELETE FROM _journal WHERE created_at < ?1",
            [NOW - RETENTION_DAYS * DAY],
        )?)
    }
}

/// Records encrypted under per-record keys whose wrapped form is stored in the same file
/// (`doc/architecture.md` section 5.1). The record cipher itself is out of scope: the
/// ciphertext and the wrapped key are random bytes of the right sizes, because the
/// question is only whether those bytes leave the disk. The file also has a minimal
/// `_journal`, for the case where the key row is deleted through a journaled write.
pub struct Shredding {
    pub db: Db,
    pub shredded_keys: NeedleSet,
    pub kept_keys: NeedleSet,
    pub shredded_ciphertexts: NeedleSet,
    shredded_ids: Vec<i64>,
}

/// Writes the records and their wrapped keys, then checkpoints, as keys written long
/// before they are destroyed are.
pub fn shredding(name: &str, mode: Mode, secure_delete: SecureDelete) -> Result<Shredding> {
    let mut rng = Rng::new(SEED);
    let db = Db::create(name, mode, secure_delete, &mut rng)?;
    db.conn().execute_batch(
        "CREATE TABLE records (id INTEGER PRIMARY KEY, ciphertext BLOB NOT NULL);
         CREATE TABLE record_keys (
             record_id INTEGER PRIMARY KEY REFERENCES records (id),
             wrapped_key BLOB NOT NULL
         );
         CREATE TABLE _journal (
             id INTEGER PRIMARY KEY,
             record_id INTEGER NOT NULL,
             before_image BLOB NOT NULL
         );",
    )?;
    let mut shredded_keys = NeedleSet::default();
    let mut kept_keys = NeedleSet::default();
    let mut shredded_ciphertexts = NeedleSet::default();
    let mut shredded_ids = Vec::new();
    let tx = db.conn().unchecked_transaction()?;
    for id in 0..SHRED_RECORDS {
        let ciphertext = rng.bytes(600);
        let wrapped_key = rng.bytes(WRAPPED_KEY_BYTES);
        tx.execute(
            "INSERT INTO records (id, ciphertext) VALUES (?1, ?2)",
            params![id, ciphertext],
        )?;
        tx.execute(
            "INSERT INTO record_keys (record_id, wrapped_key) VALUES (?1, ?2)",
            params![id, wrapped_key],
        )?;
        if id % 2 == 0 {
            shredded_ids.push(id);
            shredded_keys.add(&wrapped_key);
            shredded_ciphertexts.add(&ciphertext);
        } else {
            kept_keys.add(&wrapped_key);
        }
    }
    tx.commit()?;
    db.checkpoint("TRUNCATE")?;
    Ok(Shredding {
        db,
        shredded_keys,
        kept_keys,
        shredded_ciphertexts,
        shredded_ids,
    })
}

impl Shredding {
    /// Destroys the key of every shredded record; the record ciphertext stays in place.
    pub fn shred(&self) -> Result<usize> {
        let tx = self.db.conn().unchecked_transaction()?;
        let mut deleted = 0;
        for id in &self.shredded_ids {
            deleted += tx.execute("DELETE FROM record_keys WHERE record_id = ?1", [id])?;
        }
        tx.commit()?;
        Ok(deleted)
    }

    /// Destroys the keys through a journaled write, as the typed record API of AD-9 and
    /// AD-26 would: the before-image of each deleted key row is written to `_journal` in
    /// the same transaction.
    pub fn shred_journaled(&self) -> Result<usize> {
        let tx = self.db.conn().unchecked_transaction()?;
        let mut deleted = 0;
        for id in &self.shredded_ids {
            tx.execute(
                "INSERT INTO _journal (record_id, before_image)
                 SELECT record_id, wrapped_key FROM record_keys WHERE record_id = ?1",
                [id],
            )?;
            deleted += tx.execute("DELETE FROM record_keys WHERE record_id = ?1", [id])?;
        }
        tx.commit()?;
        Ok(deleted)
    }

    /// Deletes the journal rows that hold a destroyed key.
    pub fn purge_key_journal(&self) -> Result<usize> {
        let tx = self.db.conn().unchecked_transaction()?;
        let mut deleted = 0;
        for id in &self.shredded_ids {
            deleted += tx.execute("DELETE FROM _journal WHERE record_id = ?1", [id])?;
        }
        tx.commit()?;
        Ok(deleted)
    }
}

/// Installs an authorizer in the shape of story 1.7, stricter for the spike: every
/// PRAGMA, ATTACH and DETACH statement is refused.
pub fn refuse_pragmas_and_attach(conn: &Connection) -> Result<()> {
    conn.authorizer(Some(|context: AuthContext<'_>| match context.action {
        AuthAction::Pragma { .. } | AuthAction::Attach { .. } | AuthAction::Detach { .. } => {
            Authorization::Deny
        }
        _ => Authorization::Allow,
    }))?;
    Ok(())
}

/// `sqlite3_wal_checkpoint_v2` in TRUNCATE mode on the main database. It prepares no SQL
/// statement, so no authorizer sees it. Returns (log frames, checkpointed frames).
#[allow(unsafe_code)] // FFI to SQLite's checkpoint API; the handle stays owned by `conn`.
pub fn checkpoint_truncate_c_api(conn: &Connection) -> Result<(c_int, c_int)> {
    let mut log: c_int = 0;
    let mut checkpointed: c_int = 0;
    // SAFETY: the handle is valid while `conn` is borrowed and used on this thread only;
    // the database name is a NUL-terminated literal; both out pointers are live locals.
    let rc = unsafe {
        ffi::sqlite3_wal_checkpoint_v2(
            conn.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_CHECKPOINT_TRUNCATE,
            &mut log,
            &mut checkpointed,
        )
    };
    if rc != ffi::SQLITE_OK {
        return Err(format!("sqlite3_wal_checkpoint_v2 returned {rc}").into());
    }
    Ok((log, checkpointed))
}
