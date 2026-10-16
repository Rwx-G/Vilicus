//! The action pipeline of `doc/architecture.md` section 9.2, reduced to what costs time: schema
//! validation, the principal check (capability token for token principals), deterministic
//! rules (tier, caps), taint, then the write on the file's writer thread with the envelope and
//! the `_journal` row (AD-26), then the audit append, acknowledged before the response.
//!
//! The alignment controller and the human steps are out of scope: no call in the load is
//! elevated, tier 2 or H, and a call that would be is refused here, never queued.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::digest;
use rusqlite::{Connection, OptionalExtension, params};

use crate::audit::AuditClient;
use crate::crypto;
use crate::writer::{BackupActivity, Writer};

/// The open files of the simulated household.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileId {
    TasksAdult1,
    TasksAdult2,
    TasksHousehold,
    CalendarHousehold,
    ReferenceHousehold,
    Home,
}

/// Partition kinds of spine AD-5 and AD-37.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionKind {
    Personal(u8),
    Household,
    Home,
}

impl FileId {
    pub const ALL: [FileId; 6] = [
        FileId::TasksAdult1,
        FileId::TasksAdult2,
        FileId::TasksHousehold,
        FileId::CalendarHousehold,
        FileId::ReferenceHousehold,
        FileId::Home,
    ];

    /// `<module>.<partition>`, the file name stem.
    pub fn name(self) -> &'static str {
        match self {
            FileId::TasksAdult1 => "tasks.adult1",
            FileId::TasksAdult2 => "tasks.adult2",
            FileId::TasksHousehold => "tasks.household",
            FileId::CalendarHousehold => "calendar.household",
            FileId::ReferenceHousehold => "reference.household",
            FileId::Home => "home.home",
        }
    }

    pub fn partition(self) -> PartitionKind {
        match self {
            FileId::TasksAdult1 => PartitionKind::Personal(1),
            FileId::TasksAdult2 => PartitionKind::Personal(2),
            FileId::TasksHousehold | FileId::CalendarHousehold | FileId::ReferenceHousehold => {
                PartitionKind::Household
            }
            FileId::Home => PartitionKind::Home,
        }
    }

    /// The personal tasks file of `member`.
    pub fn personal_tasks(member: u8) -> FileId {
        if member == 1 {
            FileId::TasksAdult1
        } else {
            FileId::TasksAdult2
        }
    }

    fn module(self) -> &'static str {
        self.name().split('.').next().unwrap_or_default()
    }
}

/// The registered tools the load calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Tool {
    TasksCreate,
    TasksUpdate,
    CalendarUpdate,
    ReferenceWrite,
    HomeSetState,
    HomeReport,
}

/// One capability matrix row, as far as the pipeline reads it.
#[derive(Clone, Copy, Debug)]
pub struct MatrixRow {
    pub tier: u8,
    pub module: &'static str,
    pub creates: bool,
    /// Adapter state reports are observations, never journaled (AD-26).
    pub journaled: bool,
}

impl Tool {
    pub fn name(self) -> &'static str {
        match self {
            Tool::TasksCreate => "tasks.create",
            Tool::TasksUpdate => "tasks.update",
            Tool::CalendarUpdate => "calendar.update",
            Tool::ReferenceWrite => "reference.write",
            Tool::HomeSetState => "home.set_state",
            Tool::HomeReport => "home.report",
        }
    }

    pub fn row(self) -> MatrixRow {
        let (tier, module, creates, journaled) = match self {
            Tool::TasksCreate => (1, "tasks", true, true),
            Tool::TasksUpdate => (1, "tasks", false, true),
            Tool::CalendarUpdate => (1, "calendar", false, true),
            Tool::ReferenceWrite => (1, "reference", false, true),
            Tool::HomeSetState => (1, "home", false, true),
            Tool::HomeReport => (0, "home", false, false),
        };
        MatrixRow {
            tier,
            module,
            creates,
            journaled,
        }
    }
}

/// Capability token identifier: opaque, its scope lives only in Core state (AD-11).
pub type TokenId = u128;

/// The principal of a call (AD-8), restricted to the kinds the load uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    Member(u8),
    AiTask(TokenId),
    Plugin(TokenId),
    Rule(u16),
    Adapter(u8),
}

impl Principal {
    fn label(self) -> String {
        match self {
            Principal::Member(member) => format!("member:{member}"),
            Principal::AiTask(token) => format!("ai_task:{:08x}", token as u32),
            Principal::Plugin(token) => format!("plugin:{:08x}", token as u32),
            Principal::Rule(rule) => format!("rule:{rule}"),
            Principal::Adapter(adapter) => format!("adapter:{adapter}"),
        }
    }
}

/// One tool call.
#[derive(Clone, Debug)]
pub struct Call {
    pub principal: Principal,
    pub call_id: [u8; 16],
    pub tool: Tool,
    pub file: FileId,
    /// The record an update targets; `None` for a create.
    pub record_id: Option<i64>,
    pub title: String,
    pub body: String,
    /// Whether the token's session has consumed `external` or `member` data.
    pub session_tainted: bool,
    /// Record ids the call read to produce its parameters, journaled with the write (I9).
    pub inputs: Vec<i64>,
}

impl Call {
    pub fn new(principal: Principal, tool: Tool, file: FileId, record_id: Option<i64>) -> Self {
        Self {
            principal,
            call_id: crypto::random(),
            tool,
            file,
            record_id,
            title: format!("{} on {}", tool.name(), file.name()),
            body: "updated body text from the simulated household".to_owned(),
            session_tainted: false,
            inputs: Vec::new(),
        }
    }
}

/// Why a call was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    Schema(&'static str),
    Token(&'static str),
    Principal(&'static str),
    Rule(&'static str),
    Elevated,
    Conflict,
    Duplicate,
    Storage(String),
    Audit(String),
}

/// Time spent in each pipeline stage.
#[derive(Clone, Copy, Debug, Default)]
pub struct Timings {
    pub policy: Duration,
    pub write: Duration,
    pub audit: Duration,
}

/// A completed call.
#[derive(Clone, Copy, Debug)]
pub struct Outcome {
    pub record_id: i64,
    pub rev: i64,
    pub audit_seq: u64,
    pub timings: Timings,
    /// What a backup was doing to the file's writer when the write was queued or done.
    pub backup: BackupActivity,
}

struct TokenScope {
    member: u8,
    tools: Vec<Tool>,
    files: Vec<FileId>,
    remaining_calls: u32,
    expires: Instant,
}

/// Calls per principal per minute before the cap refuses (section 9.5 shape).
pub const CAP_PER_MINUTE: u32 = 1_000;
/// V0.1 token lifetime and budget (D113).
pub const TOKEN_TTL: Duration = Duration::from_secs(600);
pub const TOKEN_BUDGET: u32 = 50;

/// The Core's pipeline state.
pub struct Core {
    writers: HashMap<FileId, Writer>,
    tokens: Mutex<HashMap<TokenId, TokenScope>>,
    caps: Mutex<HashMap<String, (Instant, u32)>>,
    validated_rules: HashSet<u16>,
    adapter_grants: HashSet<u8>,
    audit: AuditClient,
    audit_appends: AtomicU64,
}

struct Stamp {
    source: &'static str,
    taint: &'static str,
    data_types: &'static str,
    author: String,
}

impl Core {
    pub fn new(
        writers: HashMap<FileId, Writer>,
        audit: AuditClient,
        validated_rules: HashSet<u16>,
        adapter_grants: HashSet<u8>,
    ) -> Self {
        Self {
            writers,
            tokens: Mutex::new(HashMap::new()),
            caps: Mutex::new(HashMap::new()),
            validated_rules,
            adapter_grants,
            audit,
            audit_appends: AtomicU64::new(0),
        }
    }

    pub fn writer(&self, file: FileId) -> Option<&Writer> {
        self.writers.get(&file)
    }

    /// Audit entries acknowledged so far, refusals included.
    pub fn audit_appends(&self) -> u64 {
        self.audit_appends.load(Ordering::Relaxed)
    }

    /// Issues a token for `member` limited to `tools` on `files`.
    pub fn issue_token(
        &self,
        member: u8,
        tools: &[Tool],
        files: &[FileId],
        budget: u32,
        ttl: Duration,
    ) -> TokenId {
        let id = u128::from_be_bytes(crypto::random());
        self.tokens.lock().expect("token table").insert(
            id,
            TokenScope {
                member,
                tools: tools.to_vec(),
                files: files.to_vec(),
                remaining_calls: budget,
                expires: Instant::now() + ttl,
            },
        );
        id
    }

    /// Runs one call through the pipeline. A refusal is audited too.
    pub async fn execute(&self, call: Call) -> Result<Outcome, Refusal> {
        let started = Instant::now();
        let param_hash = param_hash(&call);
        let stamp = match self.evaluate(&call) {
            Ok(stamp) => stamp,
            Err(refusal) => {
                self.append_audit(&call, &param_hash, "refused").await?;
                return Err(refusal);
            }
        };
        let policy_done = Instant::now();
        let writer = self
            .writers
            .get(&call.file)
            .ok_or_else(|| Refusal::Storage(format!("{} is not open", call.file.name())))?;
        let principal = call.principal.label();
        let write = WriteRequest {
            principal,
            call_id: call.call_id,
            record_id: call.record_id,
            title: call.title.clone(),
            body: call.body.clone(),
            inputs: call
                .inputs
                .iter()
                .map(i64::to_string)
                .collect::<Vec<_>>()
                .join(","),
            topic: format!("{}.changed", call.tool.row().module),
            row: call.tool.row(),
            stamp,
        };
        let queued_during = writer.activity();
        let (record_id, rev) = writer
            .run(move |conn| write_record(conn, &write))
            .await
            .map_err(Refusal::Storage)??;
        let write_done = Instant::now();
        let backup = queued_during.max(writer.activity());
        let audit_seq = self.append_audit(&call, &param_hash, "done").await?;
        let audit_done = Instant::now();
        Ok(Outcome {
            record_id,
            rev,
            audit_seq,
            timings: Timings {
                policy: policy_done - started,
                write: write_done - policy_done,
                audit: audit_done - write_done,
            },
            backup,
        })
    }

    async fn append_audit(
        &self,
        call: &Call,
        param_hash: &[u8],
        outcome: &str,
    ) -> Result<u64, Refusal> {
        let entry = format!(
            "{}|{}|{}|{}|{}|{}",
            unix_now(),
            call.principal.label(),
            call.tool.name(),
            call.file.name(),
            hex(param_hash),
            outcome
        );
        let seq = self
            .audit
            .append(entry.as_bytes())
            .await
            .map_err(|error| Refusal::Audit(error.to_string()))?;
        self.audit_appends.fetch_add(1, Ordering::Relaxed);
        Ok(seq)
    }

    fn evaluate(&self, call: &Call) -> Result<Stamp, Refusal> {
        // 1. Schema validation: strict, never repaired.
        if call.title.is_empty() || call.title.chars().count() > 120 {
            return Err(Refusal::Schema("title length"));
        }
        if call.body.len() > 4_000 || call.body.chars().any(char::is_control) {
            return Err(Refusal::Schema("body"));
        }
        let row = call.tool.row();
        if row.creates != call.record_id.is_none() {
            return Err(Refusal::Schema("record id"));
        }
        if row.module != call.file.module() {
            return Err(Refusal::Schema("tool and file modules differ"));
        }
        // 2. Principal: capability token for token principals, scope for the others.
        let author = match call.principal {
            Principal::AiTask(token) | Principal::Plugin(token) => self.spend_token(token, call)?,
            Principal::Member(member) => {
                if let PartitionKind::Personal(owner) = call.file.partition()
                    && owner != member
                {
                    return Err(Refusal::Principal("another member's partition"));
                }
                format!("member:{member}")
            }
            Principal::Rule(rule) => {
                if !self.validated_rules.contains(&rule) || call.tool != Tool::HomeSetState {
                    return Err(Refusal::Principal("rule not validated for this tool"));
                }
                format!("rule:{rule}")
            }
            Principal::Adapter(adapter) => {
                if !self.adapter_grants.contains(&adapter) || call.tool != Tool::HomeReport {
                    return Err(Refusal::Principal("adapter not granted this tool"));
                }
                format!("adapter:{adapter}")
            }
        };
        // 3. Deterministic rules: tier and caps. Tier 2 needs the native app (absent).
        if row.tier >= 2 {
            return Err(Refusal::Rule("tier 2 needs a paired native app"));
        }
        self.count_cap(call.principal.label())?;
        // 4. Taint, for token principals only (D58).
        let token_principal = matches!(call.principal, Principal::AiTask(_) | Principal::Plugin(_));
        if token_principal && call.session_tainted && row.tier >= 1 {
            return Err(Refusal::Elevated);
        }
        let (source, taint) = match call.principal {
            Principal::Plugin(_) => ("plugin", "external"),
            Principal::AiTask(_) => ("assistant", "trusted"),
            Principal::Member(_) => ("member", "trusted"),
            Principal::Rule(_) => ("rule", "trusted"),
            Principal::Adapter(_) => ("adapter", "trusted"),
        };
        let data_types = match call.file.partition() {
            PartitionKind::Personal(_) => "personal_other",
            PartitionKind::Household => "household_other",
            PartitionKind::Home => "home_state",
        };
        Ok(Stamp {
            source,
            taint,
            data_types,
            author,
        })
    }

    fn spend_token(&self, token: TokenId, call: &Call) -> Result<String, Refusal> {
        let mut tokens = self.tokens.lock().expect("token table");
        let scope = tokens.get_mut(&token).ok_or(Refusal::Token("unknown"))?;
        if Instant::now() >= scope.expires {
            tokens.remove(&token);
            return Err(Refusal::Token("expired"));
        }
        if !scope.tools.contains(&call.tool) || !scope.files.contains(&call.file) {
            return Err(Refusal::Token("out of scope"));
        }
        if scope.remaining_calls == 0 {
            return Err(Refusal::Token("budget spent"));
        }
        scope.remaining_calls -= 1;
        Ok(format!("member:{}", scope.member))
    }

    fn count_cap(&self, principal: String) -> Result<(), Refusal> {
        let now = Instant::now();
        let mut caps = self.caps.lock().expect("cap table");
        let (window, count) = caps.entry(principal).or_insert((now, 0));
        if now.duration_since(*window) >= Duration::from_secs(60) {
            *window = now;
            *count = 0;
        }
        *count += 1;
        if *count > CAP_PER_MINUTE {
            return Err(Refusal::Rule("cap reached"));
        }
        Ok(())
    }
}

struct WriteRequest {
    principal: String,
    call_id: [u8; 16],
    record_id: Option<i64>,
    title: String,
    body: String,
    inputs: String,
    topic: String,
    row: MatrixRow,
    stamp: Stamp,
}

fn image(title: &str, body: &str, rev: i64) -> Vec<u8> {
    format!("{title}\u{1f}{body}\u{1f}{rev}").into_bytes()
}

/// The write transaction of AD-9, AD-10 and AD-26: envelope stamped by the Core, `rev`
/// checked and bumped, before and after images and input ids in `_journal`, (principal,
/// `call_id`) unique, and the change event in `_outbox`, all in one transaction.
fn write_record(conn: &Connection, request: &WriteRequest) -> Result<(i64, i64), Refusal> {
    let storage = |error: rusqlite::Error| Refusal::Storage(error.to_string());
    let now = unix_now();
    let tx = conn.unchecked_transaction().map_err(storage)?;
    let stamp = &request.stamp;
    let (record_id, rev_before, before_image, rev_after) = match request.record_id {
        None => {
            tx.execute(
                "INSERT INTO records
                     (source, taint, data_types, author, created_at, updated_at, rev, title, body)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, 1, ?6, ?7)",
                params![
                    stamp.source,
                    stamp.taint,
                    stamp.data_types,
                    stamp.author,
                    now,
                    request.title,
                    request.body
                ],
            )
            .map_err(storage)?;
            (tx.last_insert_rowid(), None, None, 1)
        }
        Some(id) => {
            let before: Option<(i64, String, String)> = tx
                .query_row(
                    "SELECT rev, title, body FROM records WHERE id = ?1",
                    [id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(storage)?;
            let (rev, title, body) = before.ok_or(Refusal::Conflict)?;
            let changed = tx
                .execute(
                    "UPDATE records SET source = ?1, taint = ?2, data_types = ?3, author = ?4,
                         updated_at = ?5, rev = rev + 1, title = ?6, body = ?7
                     WHERE id = ?8 AND rev = ?9",
                    params![
                        stamp.source,
                        stamp.taint,
                        stamp.data_types,
                        stamp.author,
                        now,
                        request.title,
                        request.body,
                        id,
                        rev
                    ],
                )
                .map_err(storage)?;
            if changed != 1 {
                return Err(Refusal::Conflict);
            }
            (id, Some(rev), Some(image(&title, &body, rev)), rev + 1)
        }
    };
    if request.row.journaled {
        let inserted = tx.execute(
            "INSERT INTO _journal (principal, call_id, record_id, rev_before, rev_after,
                 before_image, after_image, inputs, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                request.principal,
                request.call_id.as_slice(),
                record_id,
                rev_before,
                rev_after,
                before_image,
                image(&request.title, &request.body, rev_after),
                request.inputs,
                now
            ],
        );
        match inserted {
            Ok(_) => {}
            Err(error)
                if error.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation) =>
            {
                return Err(Refusal::Duplicate);
            }
            Err(error) => return Err(storage(error)),
        }
        let mut payload = record_id.to_be_bytes().to_vec();
        payload.extend_from_slice(&rev_after.to_be_bytes());
        tx.execute(
            "INSERT INTO _outbox (event_id, topic, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![
                crypto::random::<16>().as_slice(),
                request.topic,
                payload,
                now
            ],
        )
        .map_err(storage)?;
    }
    tx.commit().map_err(storage)?;
    Ok((record_id, rev_after))
}

/// The canonical parameter hash the audit entry carries instead of parameters (AD-13 shape).
fn param_hash(call: &Call) -> Vec<u8> {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(call.tool.name().as_bytes());
    context.update(call.file.name().as_bytes());
    context.update(&call.record_id.unwrap_or(-1).to_be_bytes());
    context.update(call.title.as_bytes());
    context.update(call.body.as_bytes());
    context.finish().as_ref().to_vec()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
