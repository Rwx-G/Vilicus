//! One writer thread per open file (spine AD-9). The thread owns the file's only write
//! connection and runs jobs in arrival order; the async side waits on a oneshot reply.
//!
//! Two backup commands come from spine AD-31: [`Writer::pause`] checkpoints the WAL away and
//! holds the writer until the guard drops (the files the backup copies as root), and
//! [`Writer::online_backup`] copies the file with SQLite's online backup API in bounded steps,
//! running the jobs queued meanwhile between two steps (the home partition, whose writer is
//! never paused).
//!
//! A pause never waits on a long reader: its TRUNCATE checkpoint runs with a short busy
//! timeout ([`PAUSE_CHECKPOINT_TIMEOUT`]); when a reader still holds the WAL the writer stays
//! unpaused, keeps serving jobs, and [`Writer::pause`] retries.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use rusqlite::backup::{Backup, StepResult};
use rusqlite::{Connection, ffi};
use tokio::sync::oneshot;

use crate::storage;

/// Busy timeout of the checkpoint a pause starts with.
pub const PAUSE_CHECKPOINT_TIMEOUT: Duration = Duration::from_millis(20);
/// Gap between two pause attempts.
pub const PAUSE_RETRY_GAP: Duration = Duration::from_millis(10);
/// Attempts before a pause gives up (about 15 s with the timeout and the gap).
pub const PAUSE_ATTEMPTS: u32 = 500;

type Job = Box<dyn FnOnce(&Connection) + Send>;

enum Command {
    Run(Job),
    Pause {
        checkpointed: oneshot::Sender<Result<(), PauseRefused>>,
        resume: mpsc::Receiver<()>,
    },
    OnlineBackup {
        target: Box<Connection>,
        pages_per_step: i32,
        done: oneshot::Sender<Result<BackupSteps, String>>,
    },
}

enum PauseRefused {
    Busy,
    Failed(String),
}

/// What a backup is doing to a writer, as seen by a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BackupActivity {
    Idle,
    /// Checkpointing for a pause, or paused.
    Paused,
    OnlineBackup,
}

impl BackupActivity {
    const IDLE: u8 = 0;
    const PAUSED: u8 = 1;
    const ONLINE: u8 = 2;

    fn from_code(code: u8) -> Self {
        match code {
            Self::PAUSED => Self::Paused,
            Self::ONLINE => Self::OnlineBackup,
            _ => Self::Idle,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Idle => "file idle",
            Self::Paused => "file paused",
            Self::OnlineBackup => "online backup",
        }
    }
}

/// What an online backup did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupSteps {
    /// Backup steps run.
    pub steps: u32,
    /// Jobs the writer ran between two steps.
    pub interleaved_jobs: u32,
}

/// Holds a paused writer; dropping it resumes the writer.
pub struct PauseGuard {
    _resume: mpsc::Sender<()>,
}

/// The handle to one file's writer thread.
pub struct Writer {
    name: String,
    commands: Option<mpsc::Sender<Command>>,
    thread: Option<JoinHandle<()>>,
    activity: Arc<AtomicU8>,
    pause_retries: AtomicU64,
}

impl Writer {
    /// Starts the writer thread of `name`, which owns `conn` from now on.
    pub fn spawn(name: &str, conn: Connection) -> std::io::Result<Self> {
        let (commands, receiver) = mpsc::channel();
        let activity = Arc::new(AtomicU8::new(BackupActivity::IDLE));
        let thread_activity = Arc::clone(&activity);
        let thread = std::thread::Builder::new()
            .name(format!("writer-{name}"))
            .spawn(move || writer_loop(&conn, &receiver, &thread_activity))?;
        Ok(Self {
            name: name.to_owned(),
            commands: Some(commands),
            thread: Some(thread),
            activity,
            pause_retries: AtomicU64::new(0),
        })
    }

    /// The file name the writer was started for.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// What a backup is doing to this writer right now.
    pub fn activity(&self) -> BackupActivity {
        BackupActivity::from_code(self.activity.load(Ordering::SeqCst))
    }

    /// Pause attempts refused because a reader held the WAL.
    pub fn pause_retries(&self) -> u64 {
        self.pause_retries.load(Ordering::SeqCst)
    }

    fn send(&self, command: Command) -> Result<(), String> {
        self.commands
            .as_ref()
            .and_then(|commands| commands.send(command).ok())
            .ok_or_else(|| format!("writer {} is gone", self.name))
    }

    /// Runs `job` on the writer thread. A job that panics is caught there (spine AD-9 fault
    /// isolation) and reported as an error; its open transaction rolls back when dropped.
    pub async fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce(&Connection) -> T + Send + 'static,
    ) -> Result<T, String> {
        let (reply, result) = oneshot::channel();
        self.send(Command::Run(Box::new(move |conn| {
            // The receiver may be gone if the caller was cancelled; nothing to do then.
            let _ = reply.send(job(conn));
        })))?;
        result
            .await
            .map_err(|_| format!("a job on writer {} panicked", self.name))
    }

    /// Checkpoints the WAL in TRUNCATE mode, then holds the writer until the guard drops.
    /// While a reader keeps the checkpoint from completing, the writer stays in service and
    /// the pause is retried.
    pub async fn pause(&self) -> Result<PauseGuard, String> {
        for _ in 0..PAUSE_ATTEMPTS {
            let (checkpointed, done) = oneshot::channel();
            let (resume_sender, resume) = mpsc::channel();
            self.send(Command::Pause {
                checkpointed,
                resume,
            })?;
            match done
                .await
                .map_err(|_| format!("writer {} dropped a pause", self.name))?
            {
                Ok(()) => {
                    return Ok(PauseGuard {
                        _resume: resume_sender,
                    });
                }
                Err(PauseRefused::Busy) => {
                    self.pause_retries.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(PAUSE_RETRY_GAP).await;
                }
                Err(PauseRefused::Failed(message)) => return Err(message),
            }
        }
        Err(format!(
            "writer {}: a reader held the WAL for {PAUSE_ATTEMPTS} pause attempts",
            self.name
        ))
    }

    /// Copies the file into `target` with the online backup API, `pages_per_step` pages per
    /// step, releasing the writer to queued jobs between steps.
    pub async fn online_backup(
        &self,
        target: Connection,
        pages_per_step: i32,
    ) -> Result<BackupSteps, String> {
        let (done, result) = oneshot::channel();
        self.send(Command::OnlineBackup {
            target: Box::new(target),
            pages_per_step,
            done,
        })?;
        result
            .await
            .map_err(|_| format!("writer {} dropped a backup", self.name))?
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.commands.take();
        if let Some(thread) = self.thread.take() {
            // A writer thread that panicked outside a job has nothing left to report here.
            let _ = thread.join();
        }
    }
}

fn writer_loop(conn: &Connection, receiver: &mpsc::Receiver<Command>, activity: &AtomicU8) {
    let mut deferred = VecDeque::new();
    loop {
        let command = match deferred.pop_front() {
            Some(command) => command,
            None => match receiver.recv() {
                Ok(command) => command,
                Err(mpsc::RecvError) => return,
            },
        };
        match command {
            Command::Run(job) => run_job(conn, job),
            Command::Pause {
                checkpointed,
                resume,
            } => {
                activity.store(BackupActivity::PAUSED, Ordering::SeqCst);
                let outcome =
                    match storage::checkpoint_truncate_within(conn, PAUSE_CHECKPOINT_TIMEOUT) {
                        Ok(_) => Ok(()),
                        Err(ffi::SQLITE_BUSY) => Err(PauseRefused::Busy),
                        Err(code) => Err(PauseRefused::Failed(format!(
                            "sqlite3_wal_checkpoint_v2 returned {code}"
                        ))),
                    };
                let paused = outcome.is_ok();
                let _ = checkpointed.send(outcome);
                if paused {
                    // Returns when the guard's sender is dropped.
                    let _ = resume.recv();
                }
                activity.store(BackupActivity::IDLE, Ordering::SeqCst);
            }
            Command::OnlineBackup {
                mut target,
                pages_per_step,
                done,
            } => {
                activity.store(BackupActivity::ONLINE, Ordering::SeqCst);
                let outcome =
                    online_backup(conn, &mut target, pages_per_step, receiver, &mut deferred);
                activity.store(BackupActivity::IDLE, Ordering::SeqCst);
                let _ = done.send(outcome);
            }
        }
    }
}

fn run_job(conn: &Connection, job: Job) {
    // A panicking job drops its reply sender; the caller sees the error.
    let _ = catch_unwind(AssertUnwindSafe(|| job(conn)));
}

fn online_backup(
    conn: &Connection,
    target: &mut Connection,
    pages_per_step: i32,
    receiver: &mpsc::Receiver<Command>,
    deferred: &mut VecDeque<Command>,
) -> Result<BackupSteps, String> {
    let backup = Backup::new(conn, target).map_err(|error| error.to_string())?;
    let mut report = BackupSteps {
        steps: 0,
        interleaved_jobs: 0,
    };
    loop {
        let step = backup
            .step(pages_per_step)
            .map_err(|error| error.to_string())?;
        report.steps += 1;
        match step {
            StepResult::Done => return Ok(report),
            StepResult::Busy | StepResult::Locked => std::thread::sleep(Duration::from_millis(1)),
            _ => {}
        }
        // Writes on the source connection between steps update the copy in place (SQLite
        // backup API), so the copy stays consistent and never restarts.
        while let Ok(command) = receiver.try_recv() {
            match command {
                Command::Run(job) => {
                    run_job(conn, job);
                    report.interleaved_jobs += 1;
                }
                other => deferred.push_back(other),
            }
        }
    }
}
