//! The Core's side of E22: registered devices, signed sessions, pending pairings and light
//! confirmations. All state is in memory, so sessions do not survive a Core restart.
//!
//! Lifetimes are checked on a monotonic clock, so a wall-clock step neither expires nor revives
//! anything; the wall clock is used only for the expiry shown in a confirmation's canonical
//! bytes. The test harness can advance both by the same offset.

use std::collections::HashMap;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use opaque_ke::{
    ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization,
    CredentialRequest, Identifiers, RegistrationRequest, RegistrationUpload, ServerLogin,
    ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::OsRng;

use crate::confirm::{self, Challenge};
use crate::device::{self, Id, PUBLIC_KEY_LEN};
use crate::pairing::{self, Code, Suite};

/// How long a pairing code lives (PRD FR-16).
pub const PAIRING_TTL_SECS: u64 = 120;
/// OPAQUE login starts a pairing code allows (PRD FR-16).
pub const PAIRING_ATTEMPTS: u8 = 3;
/// How long a finished or expired pairing keeps its handle reserved.
pub const PAIRING_RETENTION_SECS: u64 = 600;
/// OPAQUE login starts one source may make per [`LOGIN_RATE_WINDOW_SECS`], whatever the
/// handle: without it, one client could spend the attempts of every handle.
pub const LOGIN_RATE_LIMIT: u32 = 10;
/// The window of [`LOGIN_RATE_LIMIT`].
pub const LOGIN_RATE_WINDOW_SECS: u64 = 60;
/// How long a session-opening challenge lives.
pub const SESSION_CHALLENGE_TTL_SECS: u64 = 60;
/// How long a light confirmation challenge lives.
pub const CONFIRMATION_TTL_SECS: u64 = 300;

/// Why the Core refused an operation. The `code` is what the API returns and the browser
/// driver checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownToken,
    BadProof,
    UnknownDevice,
    UnknownChallenge,
    ChallengeExpired,
    UnknownSession,
    MissingSignature,
    BadRequestSignature,
    CounterNotIncreasing,
    UnknownPairing,
    PairingExpired,
    PairingUsed,
    RateLimited,
    OpaqueFailed,
    BindingMismatch,
    BadMessage,
    UnknownRequest,
    RequestDecided,
    UnknownNonce,
    NonceUsed,
    NonceForOtherRequest,
    NonceForOtherDevice,
    BadConfirmationSignature,
}

impl Refusal {
    /// A stable snake-case name.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownToken => "unknown_token",
            Self::BadProof => "bad_proof_of_possession",
            Self::UnknownDevice => "unknown_device",
            Self::UnknownChallenge => "unknown_challenge",
            Self::ChallengeExpired => "challenge_expired",
            Self::UnknownSession => "unknown_session",
            Self::MissingSignature => "missing_signature",
            Self::BadRequestSignature => "bad_request_signature",
            Self::CounterNotIncreasing => "counter_not_increasing",
            Self::UnknownPairing => "unknown_pairing",
            Self::PairingExpired => "pairing_expired",
            Self::PairingUsed => "pairing_used",
            Self::RateLimited => "rate_limited",
            Self::OpaqueFailed => "opaque_failed",
            Self::BindingMismatch => "binding_mismatch",
            Self::BadMessage => "bad_message",
            Self::UnknownRequest => "unknown_request",
            Self::RequestDecided => "request_decided",
            Self::UnknownNonce => "unknown_nonce",
            Self::NonceUsed => "nonce_used",
            Self::NonceForOtherRequest => "nonce_for_other_request",
            Self::NonceForOtherDevice => "nonce_for_other_device",
            Self::BadConfirmationSignature => "bad_confirmation_signature",
        }
    }
}

/// How a device was registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Enrollment,
    Pairing,
}

struct Device {
    public_key: Vec<u8>,
    origin: Origin,
}

struct Session {
    device_id: Id,
    last_counter: Option<u64>,
}

struct SessionChallenge {
    device_id: Id,
    deadline: u64,
}

struct Pairing {
    /// The device that started the issuance; `None` for a code issued on the host.
    issuer: Option<Id>,
    credential_id: Vec<u8>,
    record: Option<ServerRegistration<Suite>>,
    deadline: u64,
    attempts: u8,
    used: bool,
}

/// One OPAQUE login run, kept per login identifier so a second start never cancels a run in
/// flight. `handle` is `None` for a run answered with a fake response.
struct Login {
    handle: Option<String>,
    state: ServerLogin<Suite>,
    deadline: u64,
}

struct Pending {
    hash: [u8; 32],
    device_id: Id,
    decided: bool,
}

struct ConfirmationChallenge {
    request_id: Id,
    device_id: Id,
    bytes: Vec<u8>,
    deadline: u64,
    used: bool,
}

/// A registered device and its first session, returned by enrollment and pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registered {
    pub device_id: Id,
    pub session_id: Id,
}

/// The issuer's view of a started issuance: the handle, the OPAQUE registration response, and
/// the Core's signature over both.
pub struct IssueStart {
    pub handle: String,
    pub response: Vec<u8>,
    pub signature: Vec<u8>,
}

/// What the test harness reads about a pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PairingState {
    pub registered: bool,
    pub attempts: u8,
    pub used: bool,
    pub expired: bool,
}

/// The Core's in-memory state.
pub struct Core {
    rng: SystemRandom,
    started: Instant,
    clock_offset: u64,
    opaque: ServerSetup<Suite>,
    identity: EcdsaKeyPair,
    enrollment_tokens: HashMap<Id, bool>,
    devices: HashMap<Id, Device>,
    sessions: HashMap<Id, Session>,
    session_challenges: HashMap<Id, SessionChallenge>,
    pairings: HashMap<String, Pairing>,
    logins: HashMap<Id, Login>,
    login_rate: HashMap<String, (u64, u32)>,
    pending: HashMap<Id, Pending>,
    confirmations: HashMap<Id, ConfirmationChallenge>,
}

impl Default for Core {
    fn default() -> Self {
        Self::new()
    }
}

impl Core {
    /// A Core with a fresh OPAQUE server setup and identity key.
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .expect("key generation works");
        let identity = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
            .expect("a fresh PKCS#8 parses");
        Self {
            rng,
            started: Instant::now(),
            clock_offset: 0,
            opaque: ServerSetup::<Suite>::new(&mut OsRng),
            identity,
            enrollment_tokens: HashMap::new(),
            devices: HashMap::new(),
            sessions: HashMap::new(),
            session_challenges: HashMap::new(),
            pairings: HashMap::new(),
            logins: HashMap::new(),
            login_rate: HashMap::new(),
            pending: HashMap::new(),
            confirmations: HashMap::new(),
        }
    }

    /// Monotonic seconds since the Core started, plus the test offset: every lifetime check.
    fn mono(&self) -> u64 {
        self.started.elapsed().as_secs() + self.clock_offset
    }

    /// Wall-clock seconds since the Unix epoch, plus the test offset: displayed expiries only.
    pub fn wall(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
            + self.clock_offset
    }

    /// Moves the Core's clocks forward (test harness only).
    pub fn advance_clock(&mut self, seconds: u64) {
        self.clock_offset += seconds;
    }

    /// The Core's identity public key (uncompressed P-256), which signs registration responses.
    pub fn identity_public_key(&self) -> Vec<u8> {
        self.identity.public_key().as_ref().to_vec()
    }

    /// The OPAQUE server static public key.
    pub fn opaque_public_key(&self) -> Vec<u8> {
        self.opaque.keypair().public().serialize().to_vec()
    }

    fn random_id(&self) -> Id {
        let mut id = [0u8; 16];
        self.rng.fill(&mut id).expect("the system RNG works");
        id
    }

    // ---- Enrollment (FR-15) and sessions (AD-21) -------------------------------------------

    /// Issues a one-time enrollment token; it stands for the enrollment of PRD FR-15.
    pub fn issue_enrollment_token(&mut self) -> Id {
        let token = self.random_id();
        self.enrollment_tokens.insert(token, false);
        token
    }

    /// Registers the enrollment browser's public key, proven by a signature over the token.
    pub fn enroll(
        &mut self,
        token: &Id,
        public_key: &[u8],
        proof: &[u8],
    ) -> Result<Registered, Refusal> {
        match self.enrollment_tokens.get(token) {
            Some(false) => {}
            _ => return Err(Refusal::UnknownToken),
        }
        if !device::verify(public_key, &device::pop_message(token, public_key), proof) {
            return Err(Refusal::BadProof);
        }
        self.enrollment_tokens.insert(*token, true);
        Ok(self.register(public_key, Origin::Enrollment))
    }

    fn register(&mut self, public_key: &[u8], origin: Origin) -> Registered {
        let device_id = self.random_id();
        self.devices.insert(
            device_id,
            Device {
                public_key: public_key.to_vec(),
                origin,
            },
        );
        Registered {
            device_id,
            session_id: self.open_session_for(device_id),
        }
    }

    fn open_session_for(&mut self, device_id: Id) -> Id {
        let session_id = self.random_id();
        self.sessions.insert(
            session_id,
            Session {
                device_id,
                last_counter: None,
            },
        );
        session_id
    }

    /// The device registered with this public key, if any.
    pub fn device_by_key(&self, public_key: &[u8]) -> Option<(Id, Origin)> {
        self.devices
            .iter()
            .find(|(_, device)| device.public_key == public_key)
            .map(|(id, device)| (*id, device.origin))
    }

    /// The public key of a registered device.
    pub fn device_key(&self, device_id: &Id) -> Option<&[u8]> {
        self.devices
            .get(device_id)
            .map(|device| device.public_key.as_slice())
    }

    /// A nonce a registered device signs to open a new session (after a reload or a restart).
    pub fn session_challenge(&mut self, device_id: &Id) -> Result<Id, Refusal> {
        if !self.devices.contains_key(device_id) {
            return Err(Refusal::UnknownDevice);
        }
        let nonce = self.random_id();
        let deadline = self.mono() + SESSION_CHALLENGE_TTL_SECS;
        self.session_challenges.insert(
            nonce,
            SessionChallenge {
                device_id: *device_id,
                deadline,
            },
        );
        Ok(nonce)
    }

    /// Opens a session for a device that signed a fresh challenge; each challenge is single use.
    pub fn open_session(
        &mut self,
        device_id: &Id,
        nonce: &Id,
        signature: &[u8],
    ) -> Result<Id, Refusal> {
        let challenge = self
            .session_challenges
            .remove(nonce)
            .ok_or(Refusal::UnknownChallenge)?;
        if challenge.device_id != *device_id {
            return Err(Refusal::UnknownChallenge);
        }
        if self.mono() > challenge.deadline {
            return Err(Refusal::ChallengeExpired);
        }
        let public_key = self.device_key(device_id).ok_or(Refusal::UnknownDevice)?;
        if !device::verify(
            public_key,
            &device::session_message(device_id, nonce),
            signature,
        ) {
            return Err(Refusal::BadProof);
        }
        Ok(self.open_session_for(*device_id))
    }

    /// Verifies the AD-21 signature of one request and advances the session counter. Returns
    /// the device the session is bound to. A refused request leaves the counter where it was.
    pub fn verify_request(
        &mut self,
        session_id: &Id,
        counter: u64,
        method: &str,
        path: &str,
        body: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<Id, Refusal> {
        let session = self
            .sessions
            .get(session_id)
            .ok_or(Refusal::UnknownSession)?;
        let signature = signature.ok_or(Refusal::MissingSignature)?;
        let public_key = &self
            .devices
            .get(&session.device_id)
            .ok_or(Refusal::UnknownDevice)?
            .public_key;
        let digest = device::request_digest(session_id, counter, method, path, body);
        if !device::verify(public_key, &digest, signature) {
            return Err(Refusal::BadRequestSignature);
        }
        if session.last_counter.is_some_and(|last| counter <= last) {
            return Err(Refusal::CounterNotIncreasing);
        }
        let device_id = session.device_id;
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.last_counter = Some(counter);
        }
        Ok(device_id)
    }

    // ---- Pairing codes (FR-16, D35) ---------------------------------------------------------

    fn new_handle(&self) -> String {
        loop {
            let handle = pairing::random_digits(pairing::HANDLE_DIGITS, |buf| {
                self.rng.fill(buf).expect("the system RNG works");
            });
            if !self.pairings.contains_key(&handle) {
                return handle;
            }
        }
    }

    /// First half of issuing a code from a paired device: the device has blinded the secret;
    /// the Core allocates a handle, answers with its OPRF evaluation, and signs the handle and
    /// the response with its identity key, which the device pinned when it was registered.
    pub fn issue_start(
        &mut self,
        issuer: &Id,
        registration_request: &[u8],
    ) -> Result<IssueStart, Refusal> {
        self.issue_start_as(Some(*issuer), registration_request)
    }

    fn issue_start_as(
        &mut self,
        issuer: Option<Id>,
        registration_request: &[u8],
    ) -> Result<IssueStart, Refusal> {
        self.drop_expired();
        let request = RegistrationRequest::<Suite>::deserialize(registration_request)
            .map_err(|_| Refusal::BadMessage)?;
        let handle = self.new_handle();
        let credential_id = pairing::credential_identifier(&self.random_id());
        let response = ServerRegistration::<Suite>::start(&self.opaque, request, &credential_id)
            .map_err(|_| Refusal::OpaqueFailed)?
            .message
            .serialize()
            .to_vec();
        let signature = self
            .identity
            .sign(
                &self.rng,
                &pairing::registration_message(&handle, &response),
            )
            .map_err(|_| Refusal::OpaqueFailed)?
            .as_ref()
            .to_vec();
        let deadline = self.mono() + PAIRING_TTL_SECS;
        self.pairings.insert(
            handle.clone(),
            Pairing {
                issuer,
                credential_id,
                record: None,
                deadline,
                attempts: 0,
                used: false,
            },
        );
        Ok(IssueStart {
            handle,
            response,
            signature,
        })
    }

    /// Second half of issuing a code: the device that started it uploads its registration
    /// record. Returns the seconds the code has left.
    pub fn issue_finish(
        &mut self,
        issuer: &Id,
        handle: &str,
        upload: &[u8],
    ) -> Result<u64, Refusal> {
        self.issue_finish_as(Some(*issuer), handle, upload)
    }

    fn issue_finish_as(
        &mut self,
        issuer: Option<Id>,
        handle: &str,
        upload: &[u8],
    ) -> Result<u64, Refusal> {
        let now = self.mono();
        let pairing = self
            .pairings
            .get_mut(handle)
            .filter(|pairing| pairing.issuer == issuer)
            .ok_or(Refusal::UnknownPairing)?;
        if pairing.record.is_some() {
            return Err(Refusal::PairingUsed);
        }
        if now > pairing.deadline {
            return Err(Refusal::PairingExpired);
        }
        let upload =
            RegistrationUpload::<Suite>::deserialize(upload).map_err(|_| Refusal::BadMessage)?;
        pairing.record = Some(ServerRegistration::finish(upload));
        Ok(pairing.deadline - now)
    }

    /// Issues a code on the host, as `vilicus device pair` does: the Core draws the secret and
    /// runs the OPAQUE client side itself (with the browser's KSF), so the code never transits
    /// the Gateway.
    pub fn issue_on_host(&mut self) -> Result<Code, Refusal> {
        let secret = pairing::random_digits(pairing::SECRET_DIGITS, |buf| {
            self.rng.fill(buf).expect("the system RNG works");
        });
        let start = ClientRegistration::<Suite>::start(&mut OsRng, secret.as_bytes())
            .map_err(|_| Refusal::OpaqueFailed)?;
        let issued = self.issue_start_as(None, &start.message.serialize())?;
        let response = opaque_ke::RegistrationResponse::<Suite>::deserialize(&issued.response)
            .map_err(|_| Refusal::BadMessage)?;
        let ksf = pairing::client_ksf();
        let finish = start
            .state
            .finish(
                &mut OsRng,
                secret.as_bytes(),
                response,
                ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
            )
            .map_err(|_| Refusal::OpaqueFailed)?;
        self.issue_finish_as(None, &issued.handle, &finish.message.serialize())?;
        Ok(Code {
            handle: issued.handle,
            secret,
        })
    }

    /// Forgets pairings that expired more than [`PAIRING_RETENTION_SECS`] ago, and login runs
    /// past their deadline.
    fn drop_expired(&mut self) {
        let now = self.mono();
        self.pairings
            .retain(|_, pairing| now <= pairing.deadline + PAIRING_RETENTION_SECS);
        self.logins.retain(|_, login| now <= login.deadline);
    }

    /// What the test harness reads about a pairing.
    pub fn pairing_state(&self, handle: &str) -> Option<PairingState> {
        let now = self.mono();
        self.pairings.get(handle).map(|pairing| PairingState {
            registered: pairing.record.is_some(),
            attempts: pairing.attempts,
            used: pairing.used,
            expired: now > pairing.deadline,
        })
    }

    /// Clears the per-source rate limit (test harness only).
    pub fn reset_login_rate(&mut self) {
        self.login_rate.clear();
    }

    fn charge_login_rate(&mut self, source: &str) -> Result<(), Refusal> {
        let now = self.mono();
        let entry = self.login_rate.entry(source.to_owned()).or_insert((now, 0));
        if now >= entry.0 + LOGIN_RATE_WINDOW_SECS {
            *entry = (now, 0);
        }
        if entry.1 >= LOGIN_RATE_LIMIT {
            return Err(Refusal::RateLimited);
        }
        entry.1 += 1;
        Ok(())
    }

    /// A new browser starts the OPAQUE login for a handle. Every start is charged to its
    /// source's rate limit, then answered the same way whatever the handle's state: a live
    /// pairing (registered, unused, unexpired, attempts left) spends an attempt and gets a real
    /// response; anything else gets OPAQUE's fake response, which the client cannot tell from a
    /// wrong secret. Returns the login identifier and the server's message.
    pub fn login_start(
        &mut self,
        source: &str,
        handle: &str,
        credential_request: &[u8],
    ) -> Result<(Id, Vec<u8>), Refusal> {
        self.charge_login_rate(source)?;
        let request = CredentialRequest::<Suite>::deserialize(credential_request)
            .map_err(|_| Refusal::BadMessage)?;
        self.drop_expired();
        let now = self.mono();
        let login_id = self.random_id();
        let (live, record, credential_id) = match self.pairings.get_mut(handle) {
            Some(pairing)
                if !pairing.used
                    && now <= pairing.deadline
                    && pairing.attempts < PAIRING_ATTEMPTS
                    && pairing.record.is_some() =>
            {
                pairing.attempts += 1;
                (true, pairing.record.clone(), pairing.credential_id.clone())
            }
            Some(pairing) => (false, None, pairing.credential_id.clone()),
            None => (
                false,
                None,
                pairing::credential_identifier(&[b"unknown/", handle.as_bytes()].concat()),
            ),
        };
        let start = ServerLogin::start(
            &mut OsRng,
            &self.opaque,
            record,
            request,
            &credential_id,
            ServerLoginParameters::default(),
        )
        .map_err(|_| Refusal::OpaqueFailed)?;
        self.logins.insert(
            login_id,
            Login {
                handle: live.then(|| handle.to_owned()),
                state: start.state,
                deadline: now + PAIRING_TTL_SECS,
            },
        );
        Ok((login_id, start.message.serialize().to_vec()))
    }

    /// The new browser finishes the OPAQUE login and sends its public key with the binding tag
    /// and a proof of possession. Once the OPAQUE login verifies, the code is used up, whether
    /// or not the binding holds. Returns the registration and the tag that authenticates the
    /// Core's identity key to the new browser.
    pub fn login_finish(
        &mut self,
        login_id: &Id,
        credential_finalization: &[u8],
        public_key: &[u8],
        tag: &[u8],
        proof: &[u8],
    ) -> Result<(Registered, Vec<u8>), Refusal> {
        let now = self.mono();
        let finalization = CredentialFinalization::<Suite>::deserialize(credential_finalization)
            .map_err(|_| Refusal::BadMessage)?;
        let login = self
            .logins
            .remove(login_id)
            .ok_or(Refusal::UnknownPairing)?;
        let session_key = login
            .state
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|_| Refusal::OpaqueFailed)?
            .session_key;
        let handle = login.handle.ok_or(Refusal::OpaqueFailed)?;
        let pairing = self
            .pairings
            .get_mut(&handle)
            .ok_or(Refusal::UnknownPairing)?;
        if pairing.used {
            return Err(Refusal::PairingUsed);
        }
        if now > pairing.deadline {
            return Err(Refusal::PairingExpired);
        }
        pairing.used = true;
        let message = pairing::bind_message(&handle, login_id, public_key);
        if public_key.len() != PUBLIC_KEY_LEN
            || !pairing::verify_bind_tag(&session_key, &message, tag)
        {
            return Err(Refusal::BindingMismatch);
        }
        if !device::verify(
            public_key,
            &device::pop_message(&message, public_key),
            proof,
        ) {
            return Err(Refusal::BadProof);
        }
        let core_key_tag = pairing::core_key_tag(&session_key, &self.identity_public_key());
        Ok((self.register(public_key, Origin::Pairing), core_key_tag))
    }

    // ---- Light confirmations (FR-28, D38) ----------------------------------------------------

    /// Creates a pending elevated request addressed to a device's member (test harness: in the
    /// product the assistant's call creates it).
    pub fn create_pending(
        &mut self,
        device_id: &Id,
        tool: &str,
        title: &str,
    ) -> Result<Id, Refusal> {
        if !self.devices.contains_key(device_id) {
            return Err(Refusal::UnknownDevice);
        }
        let request_id = self.random_id();
        let bytes = confirm::pending_request_bytes(&request_id, tool, title)
            .map_err(|_| Refusal::BadMessage)?;
        self.pending.insert(
            request_id,
            Pending {
                hash: device::sha256(&bytes),
                device_id: *device_id,
                decided: false,
            },
        );
        Ok(request_id)
    }

    /// Issues the canonical bytes a device signs to approve one pending request. A request
    /// addressed to another device is refused as unknown.
    pub fn confirmation_challenge(
        &mut self,
        device_id: &Id,
        request_id: &Id,
    ) -> Result<(Id, Vec<u8>), Refusal> {
        let pending = self
            .pending
            .get(request_id)
            .filter(|pending| pending.device_id == *device_id)
            .ok_or(Refusal::UnknownRequest)?;
        if pending.decided {
            return Err(Refusal::RequestDecided);
        }
        let nonce = self.random_id();
        let bytes = confirm::challenge_bytes(&Challenge {
            request_id,
            request_hash: &pending.hash,
            device_id,
            nonce: &nonce,
            expires_at: self.wall() + CONFIRMATION_TTL_SECS,
        })
        .map_err(|_| Refusal::BadMessage)?;
        let deadline = self.mono() + CONFIRMATION_TTL_SECS;
        self.confirmations.insert(
            nonce,
            ConfirmationChallenge {
                request_id: *request_id,
                device_id: *device_id,
                bytes: bytes.clone(),
                deadline,
                used: false,
            },
        );
        Ok((nonce, bytes))
    }

    /// Approves a pending request with a device signature over the challenge bytes the Core
    /// issued for it. A nonce approves once; a decided request accepts nothing more.
    pub fn approve(
        &mut self,
        device_id: &Id,
        request_id: &Id,
        nonce: &Id,
        signature: &[u8],
    ) -> Result<(), Refusal> {
        let now = self.mono();
        let challenge = self.confirmations.get(nonce).ok_or(Refusal::UnknownNonce)?;
        if challenge.used {
            return Err(Refusal::NonceUsed);
        }
        if challenge.request_id != *request_id {
            return Err(Refusal::NonceForOtherRequest);
        }
        if challenge.device_id != *device_id {
            return Err(Refusal::NonceForOtherDevice);
        }
        if now > challenge.deadline {
            return Err(Refusal::ChallengeExpired);
        }
        let pending = self
            .pending
            .get(request_id)
            .ok_or(Refusal::UnknownRequest)?;
        if pending.decided {
            return Err(Refusal::RequestDecided);
        }
        let public_key = self.device_key(device_id).ok_or(Refusal::UnknownDevice)?;
        if !device::verify(public_key, &challenge.bytes, signature) {
            return Err(Refusal::BadConfirmationSignature);
        }
        if let Some(challenge) = self.confirmations.get_mut(nonce) {
            challenge.used = true;
        }
        if let Some(pending) = self.pending.get_mut(request_id) {
            pending.decided = true;
        }
        Ok(())
    }
}
