//! The audit writer (spine AD-17, AD-55): a separate process that owns `audit.db`, appends
//! each entry the Core sends over its append socket to an HMAC-SHA-256 chain, commits, and
//! only then acknowledges. The Core holds a single append connection.
//!
//! Its admin socket serves the backup (AD-31): a flush checkpoints `audit.db` in TRUNCATE
//! mode and holds appends until the backup closes the admin connection, so the file the
//! backup copies meanwhile is complete and stable.
//!
//! Framing is a 4-byte big-endian length then the payload; the product uses CBOR (AD-12),
//! which changes the bytes, not the round trip measured here.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use aws_lc_rs::hmac;
use rusqlite::{Connection, params};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::storage::{self, FileKey};

/// Largest entry the writer accepts.
pub const MAX_ENTRY: usize = 64 * 1024;
/// Acknowledgement: the entry's sequence number then its chain MAC.
const ACK_LEN: usize = 8 + 32;
const SCHEMA: &str =
    "CREATE TABLE entries (seq INTEGER PRIMARY KEY, entry BLOB NOT NULL, mac BLOB NOT NULL);";
const FLUSH: u8 = b'F';
const FLUSHED: u8 = b'K';
const FLUSH_FAILED: u8 = b'E';

/// The audit writer's two keys: the `audit.db` file key and the chain MAC key.
#[derive(Clone)]
pub struct AuditKeys {
    pub db_key: FileKey,
    pub mac_key: [u8; 32],
}

impl AuditKeys {
    /// Both keys as 64 bytes, as the parent hands them to the writer process on its stdin.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.db_key);
        bytes[32..].copy_from_slice(&self.mac_key);
        bytes
    }

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut db_key = [0; 32];
        let mut mac_key = [0; 32];
        db_key.copy_from_slice(&bytes[..32]);
        mac_key.copy_from_slice(&bytes[32..]);
        Self { db_key, mac_key }
    }
}

/// Creates an empty `audit.db`.
pub fn create_audit_db(path: &Path, keys: &AuditKeys) -> rusqlite::Result<()> {
    let mut conn = sqlite_authorizer::open(path, &keys.db_key, sqlite_authorizer::Role::Migration)?;
    sqlite_authorizer::apply_migration(&mut conn, SCHEMA)
}

/// The MAC of entry `seq`, chained to the previous entry's MAC (zeros before the first).
pub fn chain_mac(key: &hmac::Key, previous: &[u8; 32], seq: u64, entry: &[u8]) -> [u8; 32] {
    let mut context = hmac::Context::with_key(key);
    context.update(previous);
    context.update(&seq.to_be_bytes());
    context.update(entry);
    let mut mac = [0; 32];
    mac.copy_from_slice(context.sign().as_ref());
    mac
}

struct Chain {
    conn: Connection,
    seq: u64,
    head: [u8; 32],
}

/// Serves the single append connection the Core opens, until the Core closes it, and the
/// admin socket meanwhile. `commit_delay` is slept before each commit (tests only).
pub fn serve(
    append: &UnixListener,
    admin: Option<&UnixListener>,
    db_path: &Path,
    keys: &AuditKeys,
    commit_delay: Duration,
) -> Result<u64, String> {
    let conn = storage::open_writer(db_path, &keys.db_key).map_err(|e| e.to_string())?;
    let (seq, head) = chain_head(&conn).map_err(|e| e.to_string())?;
    let chain = Mutex::new(Chain { conn, seq, head });
    let key = hmac::Key::new(hmac::HMAC_SHA256, &keys.mac_key);
    let done = AtomicBool::new(false);
    if let Some(admin) = admin {
        admin.set_nonblocking(true).map_err(|e| e.to_string())?;
    }
    std::thread::scope(|scope| {
        if let Some(admin) = admin {
            scope.spawn(|| admin_loop(admin, &chain, &done));
        }
        let appended = append_loop(append, &chain, &key, commit_delay);
        done.store(true, Ordering::SeqCst);
        appended
    })
}

fn append_loop(
    listener: &UnixListener,
    chain: &Mutex<Chain>,
    key: &hmac::Key,
    commit_delay: Duration,
) -> Result<u64, String> {
    let (mut stream, _) = listener.accept().map_err(|e| e.to_string())?;
    let mut appended = 0;
    while let Some(entry) = read_frame(&mut stream)? {
        let mut ack = [0; ACK_LEN];
        {
            let mut chain = chain.lock().map_err(|_| "audit chain lock poisoned")?;
            let next = chain.seq + 1;
            let mac = chain_mac(key, &chain.head, next, &entry);
            if !commit_delay.is_zero() {
                std::thread::sleep(commit_delay);
            }
            chain
                .conn
                .execute(
                    "INSERT INTO entries (seq, entry, mac) VALUES (?1, ?2, ?3)",
                    params![next as i64, entry, mac.as_slice()],
                )
                .map_err(|e| e.to_string())?;
            chain.seq = next;
            chain.head = mac;
            ack[..8].copy_from_slice(&next.to_be_bytes());
            ack[8..].copy_from_slice(&mac);
        }
        appended += 1;
        stream.write_all(&ack).map_err(|e| e.to_string())?;
    }
    Ok(appended)
}

fn admin_loop(listener: &UnixListener, chain: &Mutex<Chain>, done: &AtomicBool) {
    while !done.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // A failed flush only fails that backup, which sees the closed connection.
                let _ = flush_and_hold(stream, chain);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return,
        }
    }
}

/// Checkpoints `audit.db` in TRUNCATE mode, acknowledges, and holds the chain (so no append
/// changes the file) until the admin client closes the connection.
fn flush_and_hold(mut stream: UnixStream, chain: &Mutex<Chain>) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    let mut command = [0; 1];
    stream.read_exact(&mut command)?;
    if command[0] != FLUSH {
        return Ok(());
    }
    let chain = chain
        .lock()
        .map_err(|_| std::io::Error::other("audit chain lock poisoned"))?;
    let flushed = storage::checkpoint_truncate(&chain.conn).is_ok();
    stream.write_all(&[if flushed { FLUSHED } else { FLUSH_FAILED }])?;
    let mut rest = [0; 1];
    while stream.read(&mut rest)? > 0 {}
    drop(chain);
    Ok(())
}

fn chain_head(conn: &Connection) -> rusqlite::Result<(u64, [u8; 32])> {
    let last = conn.query_row(
        "SELECT seq, mac FROM entries ORDER BY seq DESC LIMIT 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
    );
    match last {
        Ok((seq, mac)) => {
            let mut head = [0; 32];
            head.copy_from_slice(&mac);
            Ok((seq as u64, head))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok((0, [0; 32])),
        Err(error) => Err(error),
    }
}

fn read_frame(stream: &mut UnixStream) -> Result<Option<Vec<u8>>, String> {
    let mut length = [0; 4];
    match stream.read_exact(&mut length) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.to_string()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length > MAX_ENTRY {
        return Err(format!("audit entry of {length} bytes refused"));
    }
    let mut entry = vec![0; length];
    stream.read_exact(&mut entry).map_err(|e| e.to_string())?;
    Ok(Some(entry))
}

/// Recomputes the whole chain from `audit.db`; returns the number of entries, or the first
/// sequence number whose MAC or position does not match.
pub fn verify_chain(db_path: &Path, keys: &AuditKeys) -> Result<u64, String> {
    let conn = storage::open_reader(db_path, &keys.db_key).map_err(|e| e.to_string())?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &keys.mac_key);
    let mut statement = conn
        .prepare("SELECT seq, entry, mac FROM entries ORDER BY seq")
        .map_err(|e| e.to_string())?;
    let mut rows = statement.query([]).map_err(|e| e.to_string())?;
    let mut head = [0; 32];
    let mut expected = 1_u64;
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let seq: i64 = row.get(0).map_err(|e| e.to_string())?;
        let entry: Vec<u8> = row.get(1).map_err(|e| e.to_string())?;
        let mac: Vec<u8> = row.get(2).map_err(|e| e.to_string())?;
        if seq as u64 != expected || chain_mac(&key, &head, expected, &entry)[..] != mac[..] {
            return Err(format!("audit chain broken at entry {expected}"));
        }
        head.copy_from_slice(&mac);
        expected += 1;
    }
    Ok(expected - 1)
}

/// The Core side of the append socket.
pub struct AuditClient {
    stream: tokio::sync::Mutex<tokio::net::UnixStream>,
}

impl AuditClient {
    pub async fn connect(socket: &Path) -> std::io::Result<Self> {
        Ok(Self {
            stream: tokio::sync::Mutex::new(tokio::net::UnixStream::connect(socket).await?),
        })
    }

    /// Appends `entry` and returns its sequence number once the writer has committed it.
    pub async fn append(&self, entry: &[u8]) -> std::io::Result<u64> {
        let length = u32::try_from(entry.len())
            .ok()
            .filter(|length| *length as usize <= MAX_ENTRY)
            .ok_or_else(|| std::io::Error::other("audit entry too large"))?;
        let mut frame = Vec::with_capacity(4 + entry.len());
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(entry);
        let mut stream = self.stream.lock().await;
        stream.write_all(&frame).await?;
        let mut ack = [0; ACK_LEN];
        stream.read_exact(&mut ack).await?;
        let mut seq = [0; 8];
        seq.copy_from_slice(&ack[..8]);
        Ok(u64::from_be_bytes(seq))
    }
}

/// A flushed audit writer; appends wait until this is dropped.
pub struct AuditFlush {
    _connection: tokio::net::UnixStream,
}

/// Asks the audit writer, on its admin socket, to checkpoint and hold appends.
pub async fn flush(admin_socket: &Path) -> std::io::Result<AuditFlush> {
    let mut connection = tokio::net::UnixStream::connect(admin_socket).await?;
    connection.write_all(&[FLUSH]).await?;
    let mut reply = [0; 1];
    connection.read_exact(&mut reply).await?;
    if reply[0] != FLUSHED {
        return Err(std::io::Error::other("audit writer could not flush"));
    }
    Ok(AuditFlush {
        _connection: connection,
    })
}
