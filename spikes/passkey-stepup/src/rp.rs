//! The relying party: users, sessions, passkey registration and login, and the step-up bound to
//! one pending request. Everything is in memory; the spike has no storage.
//!
//! Store invariant: every check and every state change of one call happens under one lock, so
//! "not yet used" is checked and set atomically. A pending request is approved at most once even
//! when the same valid assertion arrives twice at the same time.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use webauthn_rs::prelude::{
    AuthenticationResult, Base64UrlSafeData, CreationChallengeResponse, CredentialID, Passkey,
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid, Webauthn, WebauthnBuilder, WebauthnError,
};

use crate::action::{self, ActionError, ActionInput, REQUEST_ID_LEN};
use crate::stepup::{self, BindError, SESSION_ID_LEN};

pub type SessionId = [u8; SESSION_ID_LEN];
pub type RequestId = [u8; REQUEST_ID_LEN];

/// Longest user name accepted; the spike has no other use for long names.
const MAX_USERNAME_LEN: usize = 64;
/// How long the server keeps a ceremony valid after the browser's prompt timeout ends: the
/// assertion still has to travel back once the prompt closes.
pub const EXPIRY_SLACK: Duration = Duration::from_secs(2);
/// Domain label of the decoy credential identifier returned for an unknown user name.
const DECOY_LABEL: &[u8] = b"vilicus/v1/login-decoy";

/// Why a ceremony or a step-up is refused. [`RpError::code`] is all the client sees; the
/// `Display` form carries the detail for the server log.
#[derive(Debug)]
pub enum RpError {
    NoSession,
    NotAuthenticated,
    InvalidUsername,
    UserExists,
    NoCeremony,
    /// `webauthn-rs` refused a ceremony start or a credential.
    Webauthn(WebauthnError),
    Action(ActionError),
    /// No such request in the caller's session (another session's request reads the same).
    UnknownRequest,
    /// The client presented the request with a hash other than the one the server computed.
    ActionMismatch,
    /// The challenge recomputed for the presenting session differs from the request's.
    ChallengeMismatch,
    /// The signature counter did not advance past the last one the server saw.
    CounterRegressed,
    Expired,
    AlreadyUsed,
    Bind(BindError),
}

impl RpError {
    /// A stable, machine-readable reason.
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoSession => "no_session",
            Self::NotAuthenticated => "not_authenticated",
            Self::InvalidUsername => "invalid_username",
            Self::UserExists => "user_exists",
            Self::NoCeremony => "no_ceremony",
            Self::ChallengeMismatch | Self::Webauthn(WebauthnError::MismatchedChallenge) => {
                "challenge_mismatch"
            }
            Self::Webauthn(_) => "assertion_rejected",
            Self::Action(_) => "invalid_action",
            Self::UnknownRequest => "unknown_request",
            Self::ActionMismatch => "action_mismatch",
            Self::CounterRegressed => "counter_regressed",
            Self::Expired => "expired",
            Self::AlreadyUsed => "already_used",
            Self::Bind(_) => "internal",
        }
    }
}

impl std::fmt::Display for RpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Webauthn(error) => write!(f, "{}: {error:?}", self.code()),
            Self::Action(error) => write!(f, "{}: {error}", self.code()),
            Self::Bind(error) => write!(f, "{}: {error}", self.code()),
            _ => f.write_str(self.code()),
        }
    }
}

impl std::error::Error for RpError {}

/// What the server sends to start a step-up: the request it created and the options whose
/// challenge derives from that request's hash.
#[derive(Debug, Clone)]
pub struct StepUpStart {
    pub request_id: RequestId,
    pub canonical_request: Vec<u8>,
    pub request_hash: [u8; 32],
    pub options: RequestChallengeResponse,
}

/// A request the step-up approved: the caller executes exactly these canonical bytes, which
/// hash to `request_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    pub request_id: RequestId,
    pub request_hash: [u8; 32],
    pub canonical_request: Vec<u8>,
}

struct User {
    id: Uuid,
    passkeys: Vec<Passkey>,
    /// Last signature counter seen per credential, across every ceremony. The counter inside a
    /// `webauthn-rs` authentication state is a snapshot taken at its start, so two states
    /// started together would each accept the same counter value.
    counters: HashMap<CredentialID, u32>,
}

struct Ceremony<T> {
    username: String,
    state: T,
    expires_at: Instant,
}

#[derive(Default)]
struct Session {
    user: Option<String>,
    registration: Option<(Uuid, Ceremony<PasskeyRegistration>)>,
    login: Option<Ceremony<PasskeyAuthentication>>,
}

struct PendingStepUp {
    session: SessionId,
    user: String,
    canonical_request: Vec<u8>,
    request_hash: [u8; 32],
    state: PasskeyAuthentication,
    expires_at: Instant,
    used: bool,
}

#[derive(Default)]
struct State {
    users: HashMap<String, User>,
    sessions: HashMap<SessionId, Session>,
    step_ups: HashMap<RequestId, PendingStepUp>,
}

pub struct RelyingParty {
    webauthn: Webauthn,
    prompt_timeout: Duration,
    decoy_key: [u8; 32],
    state: Mutex<State>,
}

fn decoy_error(error: serde_json::Error) -> RpError {
    RpError::Bind(BindError::Serde(error))
}

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    aws_lc_rs::rand::fill(&mut bytes).expect("the system CSPRNG is available");
    bytes
}

/// Refuses an assertion whose counter does not exceed the last one seen for its credential
/// (both zero means the authenticator keeps no counter), then records it.
fn check_and_record_counter(user: &mut User, result: &AuthenticationResult) -> Result<(), RpError> {
    let seen = user.counters.get(result.cred_id()).copied().unwrap_or(0);
    let counter = result.counter();
    if (counter > 0 || seen > 0) && counter <= seen {
        return Err(RpError::CounterRegressed);
    }
    user.counters.insert(result.cred_id().clone(), counter);
    for passkey in &mut user.passkeys {
        passkey.update_credential(result);
    }
    Ok(())
}

impl RelyingParty {
    /// A relying party for `rp_id` (the host name) accepting ceremonies from `origin` only.
    /// `prompt_timeout` is the WebAuthn timeout sent to the browser; every ceremony expires on
    /// the server [`EXPIRY_SLACK`] after it.
    pub fn new(rp_id: &str, origin: &Url, prompt_timeout: Duration) -> Result<Self, WebauthnError> {
        let webauthn = WebauthnBuilder::new(rp_id, origin)?
            .rp_name("Vilicus E2 spike")
            .timeout(prompt_timeout)
            .build()?;
        Ok(Self {
            webauthn,
            prompt_timeout,
            decoy_key: random(),
            state: Mutex::new(State::default()),
        })
    }

    /// Time from the start of a ceremony to its expiry on the server.
    pub fn ceremony_lifetime(&self) -> Duration {
        self.prompt_timeout + EXPIRY_SLACK
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while holding the lock leaves no half-written invariant the spike relies on.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Opens an anonymous session for the ceremonies that precede login.
    pub fn open_session(&self) -> SessionId {
        let id = random();
        self.lock().sessions.insert(id, Session::default());
        id
    }

    pub fn session_user(&self, session: &SessionId) -> Option<String> {
        self.lock().sessions.get(session)?.user.clone()
    }

    pub fn has_session(&self, session: &SessionId) -> bool {
        self.lock().sessions.contains_key(session)
    }

    pub fn register_start(
        &self,
        session: &SessionId,
        username: &str,
        now: Instant,
    ) -> Result<CreationChallengeResponse, RpError> {
        if username.is_empty()
            || username.len() > MAX_USERNAME_LEN
            || !username
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(RpError::InvalidUsername);
        }
        let mut state = self.lock();
        if state.users.contains_key(username) {
            return Err(RpError::UserExists);
        }
        let user_id = Uuid::from_bytes(random());
        let (options, registration) = self
            .webauthn
            .start_passkey_registration(user_id, username, username, None)
            .map_err(RpError::Webauthn)?;
        let session = state.sessions.get_mut(session).ok_or(RpError::NoSession)?;
        session.registration = Some((
            user_id,
            Ceremony {
                username: username.to_owned(),
                state: registration,
                expires_at: now + self.ceremony_lifetime(),
            },
        ));
        Ok(options)
    }

    pub fn register_finish(
        &self,
        session: &SessionId,
        credential: &RegisterPublicKeyCredential,
        now: Instant,
    ) -> Result<String, RpError> {
        let mut state = self.lock();
        let (user_id, ceremony) = state
            .sessions
            .get_mut(session)
            .ok_or(RpError::NoSession)?
            .registration
            .take()
            .ok_or(RpError::NoCeremony)?;
        if now >= ceremony.expires_at {
            return Err(RpError::Expired);
        }
        let passkey = self
            .webauthn
            .finish_passkey_registration(credential, &ceremony.state)
            .map_err(RpError::Webauthn)?;
        if state.users.contains_key(&ceremony.username) {
            return Err(RpError::UserExists);
        }
        state.users.insert(
            ceremony.username.clone(),
            User {
                id: user_id,
                passkeys: vec![passkey],
                counters: HashMap::new(),
            },
        );
        Ok(ceremony.username)
    }

    /// Starts a login. An unknown user name gets the same shape of answer as a known one, with
    /// one decoy credential identifier stable per name, and a login that can only fail.
    pub fn login_start(
        &self,
        session: &SessionId,
        username: &str,
        now: Instant,
    ) -> Result<RequestChallengeResponse, RpError> {
        let mut state = self.lock();
        let (options, authentication) = match state.users.get(username) {
            Some(user) => self
                .webauthn
                .start_passkey_authentication(&user.passkeys)
                .map_err(RpError::Webauthn)?,
            None => {
                let (options, authentication) = self
                    .webauthn
                    .start_passkey_authentication(&[])
                    .map_err(RpError::Webauthn)?;
                let decoy = aws_lc_rs::digest::digest(
                    &aws_lc_rs::digest::SHA256,
                    &[DECOY_LABEL, &self.decoy_key, username.as_bytes()].concat(),
                );
                // `AllowCredentials` is not re-exported by `webauthn-rs`; edit the JSON form.
                let mut value = serde_json::to_value(&options).map_err(decoy_error)?;
                value["publicKey"]["allowCredentials"] = serde_json::json!([{
                    "type": "public-key",
                    "id": Base64UrlSafeData::from(decoy.as_ref().to_vec()),
                }]);
                let options = serde_json::from_value(value).map_err(decoy_error)?;
                (options, authentication)
            }
        };
        let session = state.sessions.get_mut(session).ok_or(RpError::NoSession)?;
        session.login = Some(Ceremony {
            username: username.to_owned(),
            state: authentication,
            expires_at: now + self.ceremony_lifetime(),
        });
        Ok(options)
    }

    /// Verifies the login assertion and returns a new session identifier: the pre-login
    /// session is closed, so a session id seen before login is worthless after it.
    pub fn login_finish(
        &self,
        session: &SessionId,
        credential: &PublicKeyCredential,
        now: Instant,
    ) -> Result<(SessionId, String), RpError> {
        let mut state = self.lock();
        let ceremony = state
            .sessions
            .get_mut(session)
            .ok_or(RpError::NoSession)?
            .login
            .take()
            .ok_or(RpError::NoCeremony)?;
        if now >= ceremony.expires_at {
            return Err(RpError::Expired);
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &ceremony.state)
            .map_err(RpError::Webauthn)?;
        let user = state
            .users
            .get_mut(&ceremony.username)
            .ok_or(RpError::Webauthn(WebauthnError::CredentialNotFound))?;
        check_and_record_counter(user, &result)?;
        state.sessions.remove(session);
        let new_session = random();
        state.sessions.insert(
            new_session,
            Session {
                user: Some(ceremony.username.clone()),
                ..Session::default()
            },
        );
        Ok((new_session, ceremony.username))
    }

    /// Creates the pending request first, then a step-up whose challenge derives from its
    /// canonical hash and from the session handle (AD-8 rule 3).
    pub fn step_up_start(
        &self,
        session: &SessionId,
        input: &ActionInput,
        now: Instant,
    ) -> Result<StepUpStart, RpError> {
        let mut state = self.lock();
        // Expired requests stay one more lifetime, so a late assertion reads `expired`.
        let lifetime = self.ceremony_lifetime();
        state
            .step_ups
            .retain(|_, pending| pending.expires_at + lifetime > now);
        let username = state
            .sessions
            .get(session)
            .ok_or(RpError::NoSession)?
            .user
            .clone()
            .ok_or(RpError::NotAuthenticated)?;
        let user = state
            .users
            .get(&username)
            .ok_or(RpError::NotAuthenticated)?;
        let request_id: RequestId = random();
        let canonical_request = action::canonical_request(&request_id, user.id.as_bytes(), input)
            .map_err(RpError::Action)?;
        let request_hash = action::request_hash(&canonical_request);
        let (mut options, random_state) = self
            .webauthn
            .start_passkey_authentication(&user.passkeys)
            .map_err(RpError::Webauthn)?;
        let challenge = stepup::derive_challenge(&stepup::session_handle(session), &request_hash);
        let bound_state = stepup::bind_challenge(&mut options, &random_state, &challenge)
            .map_err(RpError::Bind)?;
        state.step_ups.insert(
            request_id,
            PendingStepUp {
                session: *session,
                user: username,
                canonical_request: canonical_request.clone(),
                request_hash,
                state: bound_state,
                expires_at: now + lifetime,
                used: false,
            },
        );
        Ok(StepUpStart {
            request_id,
            canonical_request,
            request_hash,
            options,
        })
    }

    /// Verifies a step-up assertion for one request of the caller's session. `claimed_hash` is
    /// the request hash the client says it approves; the server returns only its own stored
    /// request. The checks run in this order: session, request of this session, hash, single
    /// use, expiry, the challenge recomputed for this session, the assertion, the counter.
    pub fn step_up_finish(
        &self,
        session: &SessionId,
        request_id: &RequestId,
        claimed_hash: &[u8; 32],
        credential: &PublicKeyCredential,
        now: Instant,
    ) -> Result<Approved, RpError> {
        let mut state = self.lock();
        state
            .sessions
            .get(session)
            .ok_or(RpError::NoSession)?
            .user
            .as_ref()
            .ok_or(RpError::NotAuthenticated)?;
        let pending = state
            .step_ups
            .get(request_id)
            .filter(|pending| &pending.session == session)
            .ok_or(RpError::UnknownRequest)?;
        if &pending.request_hash != claimed_hash {
            return Err(RpError::ActionMismatch);
        }
        if pending.used {
            return Err(RpError::AlreadyUsed);
        }
        if now >= pending.expires_at {
            return Err(RpError::Expired);
        }
        let expected =
            stepup::derive_challenge(&stepup::session_handle(session), &pending.request_hash);
        if stepup::state_challenge(&pending.state).map_err(RpError::Bind)? != expected {
            return Err(RpError::ChallengeMismatch);
        }
        let result = self
            .webauthn
            .finish_passkey_authentication(credential, &pending.state)
            .map_err(RpError::Webauthn)?;
        let username = pending.user.clone();
        let approved = Approved {
            request_id: *request_id,
            request_hash: pending.request_hash,
            canonical_request: pending.canonical_request.clone(),
        };
        let user = state
            .users
            .get_mut(&username)
            .ok_or(RpError::NotAuthenticated)?;
        check_and_record_counter(user, &result)?;
        if let Some(pending) = state.step_ups.get_mut(request_id) {
            pending.used = true;
        }
        Ok(approved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The derived challenge alone refuses a request whose recorded session was altered: the
    /// session check passes, the recomputed challenge does not.
    #[test]
    fn challenge_recomputed_for_the_presenting_session_refuses_a_moved_request() {
        let origin = Url::parse("https://rp.vilicus.test:8443").unwrap();
        let rp = RelyingParty::new("rp.vilicus.test", &origin, Duration::from_secs(30)).unwrap();
        let (owner, intruder): (SessionId, SessionId) = ([1; SESSION_ID_LEN], [2; SESSION_ID_LEN]);
        let request_hash = [3u8; 32];
        let (mut options, state) = rp.webauthn.start_passkey_authentication(&[]).unwrap();
        let challenge = stepup::derive_challenge(&stepup::session_handle(&owner), &request_hash);
        let bound = stepup::bind_challenge(&mut options, &state, &challenge).unwrap();
        {
            let mut store = rp.lock();
            store.sessions.insert(
                intruder,
                Session {
                    user: Some("owner".to_owned()),
                    ..Session::default()
                },
            );
            store.step_ups.insert(
                [4; REQUEST_ID_LEN],
                PendingStepUp {
                    // Moved to the intruder's session, as a store bug or an edit would.
                    session: intruder,
                    user: "owner".to_owned(),
                    canonical_request: Vec::new(),
                    request_hash,
                    state: bound,
                    expires_at: Instant::now() + Duration::from_secs(30),
                    used: false,
                },
            );
        }
        let any_credential: PublicKeyCredential = serde_json::from_value(json!({
            "id": "AAAA", "rawId": "AAAA", "type": "public-key",
            "response": {
                "authenticatorData": "AAAA", "clientDataJSON": "AAAA",
                "signature": "AAAA", "userHandle": null
            },
            "extensions": {}
        }))
        .unwrap();
        let refused = rp.step_up_finish(
            &intruder,
            &[4; REQUEST_ID_LEN],
            &request_hash,
            &any_credential,
            Instant::now(),
        );
        assert!(
            matches!(refused, Err(RpError::ChallengeMismatch)),
            "{refused:?}"
        );
    }
}
