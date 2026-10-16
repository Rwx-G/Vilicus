//! The relying party driven by a minimal software authenticator (ES256, `none` attestation),
//! without a browser: every refusal of the story is checked here once, then again through real
//! browsers by `run.sh`. The authenticator is test code, not a model of any real one.

use std::sync::Barrier;
use std::time::{Duration, Instant};

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use dcbor::{CBOR, Map};
use passkey_stepup::action::{self, ActionInput};
use passkey_stepup::rp::{RelyingParty, RpError, SessionId, StepUpStart};
use passkey_stepup::stepup;
use serde_json::{Value, json};
use webauthn_rs::prelude::{
    Base64UrlSafeData, CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, WebauthnError,
};

const RP_ID: &str = "rp.vilicus.test";
const ORIGIN: &str = "https://rp.vilicus.test:8443";
const PROMPT_TIMEOUT: Duration = Duration::from_secs(30);
/// Authenticator data flags.
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const ATTESTED_CREDENTIAL: u8 = 0x40;

fn b64(bytes: &[u8]) -> Value {
    serde_json::to_value(Base64UrlSafeData::from(bytes.to_vec())).unwrap()
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&digest::SHA256, bytes).as_ref().to_vec()
}

struct SoftAuthenticator {
    key: EcdsaKeyPair,
    credential_id: Vec<u8>,
    counter: u32,
    origin: String,
    user_verified: bool,
}

impl SoftAuthenticator {
    fn new() -> Self {
        let mut credential_id = vec![0u8; 16];
        aws_lc_rs::rand::fill(&mut credential_id).unwrap();
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap(),
            credential_id,
            counter: 0,
            origin: ORIGIN.to_owned(),
            user_verified: true,
        }
    }

    fn flags(&self) -> u8 {
        USER_PRESENT | if self.user_verified { USER_VERIFIED } else { 0 }
    }

    fn client_data(&self, kind: &str, challenge: &Value) -> Vec<u8> {
        json!({
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": false,
        })
        .to_string()
        .into_bytes()
    }

    fn register(&mut self, options: &CreationChallengeResponse) -> RegisterPublicKeyCredential {
        let options = serde_json::to_value(options).unwrap();
        let client_data = self.client_data("webauthn.create", &options["publicKey"]["challenge"]);
        let point = self.key.public_key().as_ref();
        let mut cose = Map::new();
        cose.insert(CBOR::from(1u64), CBOR::from(2u64));
        cose.insert(CBOR::from(3u64), CBOR::from(-7i64));
        cose.insert(CBOR::from(-1i64), CBOR::from(1u64));
        cose.insert(CBOR::from(-2i64), CBOR::to_byte_string(&point[1..33]));
        cose.insert(CBOR::from(-3i64), CBOR::to_byte_string(&point[33..65]));
        let mut auth_data = sha256(RP_ID.as_bytes());
        auth_data.push(self.flags() | ATTESTED_CREDENTIAL);
        auth_data.extend_from_slice(&self.counter.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]);
        auth_data.extend_from_slice(
            &u16::try_from(self.credential_id.len())
                .unwrap()
                .to_be_bytes(),
        );
        auth_data.extend_from_slice(&self.credential_id);
        auth_data.extend_from_slice(&CBOR::from(cose).to_cbor_data());
        let mut attestation = Map::new();
        attestation.insert(CBOR::from("fmt"), CBOR::from("none"));
        attestation.insert(CBOR::from("attStmt"), CBOR::from(Map::new()));
        attestation.insert(CBOR::from("authData"), CBOR::to_byte_string(auth_data));
        serde_json::from_value(json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "attestationObject": b64(&CBOR::from(attestation).to_cbor_data()),
                "clientDataJSON": b64(&client_data),
            },
            "extensions": {},
        }))
        .unwrap()
    }

    fn assert(&mut self, options: &RequestChallengeResponse) -> PublicKeyCredential {
        self.counter += 1;
        self.assert_with_counter(options, self.counter)
    }

    fn assert_with_counter(
        &self,
        options: &RequestChallengeResponse,
        counter: u32,
    ) -> PublicKeyCredential {
        let options = serde_json::to_value(options).unwrap();
        let client_data = self.client_data("webauthn.get", &options["publicKey"]["challenge"]);
        let mut auth_data = sha256(RP_ID.as_bytes());
        auth_data.push(self.flags());
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&sha256(&client_data));
        let signature = self.key.sign(&SystemRandom::new(), &signed).unwrap();
        serde_json::from_value(json!({
            "id": b64(&self.credential_id),
            "rawId": b64(&self.credential_id),
            "type": "public-key",
            "response": {
                "authenticatorData": b64(&auth_data),
                "clientDataJSON": b64(&client_data),
                "signature": b64(signature.as_ref()),
                "userHandle": null,
            },
            "extensions": {},
        }))
        .unwrap()
    }
}

fn relying_party() -> RelyingParty {
    RelyingParty::new(RP_ID, &Url::parse(ORIGIN).unwrap(), PROMPT_TIMEOUT).unwrap()
}

fn action(detail: &str) -> ActionInput {
    ActionInput {
        kind: "member.suspend".to_owned(),
        target: "member-2".to_owned(),
        detail: detail.to_owned(),
    }
}

/// Registers `owner` with a new authenticator and logs in; returns the logged-in session.
fn enrolled(rp: &RelyingParty) -> (SoftAuthenticator, SessionId) {
    let mut authenticator = SoftAuthenticator::new();
    let session = rp.open_session();
    let options = rp
        .register_start(&session, "owner", Instant::now())
        .unwrap();
    rp.register_finish(&session, &authenticator.register(&options), Instant::now())
        .unwrap();
    let session = login(rp, &mut authenticator);
    (authenticator, session)
}

fn login(rp: &RelyingParty, authenticator: &mut SoftAuthenticator) -> SessionId {
    let session = rp.open_session();
    let options = rp.login_start(&session, "owner", Instant::now()).unwrap();
    let (logged_in, user) = rp
        .login_finish(&session, &authenticator.assert(&options), Instant::now())
        .unwrap();
    assert_eq!(user, "owner");
    logged_in
}

fn start(rp: &RelyingParty, session: &SessionId, detail: &str) -> StepUpStart {
    rp.step_up_start(session, &action(detail), Instant::now())
        .unwrap()
}

fn finish(
    rp: &RelyingParty,
    session: &SessionId,
    pending: &StepUpStart,
    credential: &PublicKeyCredential,
) -> Result<passkey_stepup::rp::Approved, RpError> {
    rp.step_up_finish(
        session,
        &pending.request_id,
        &pending.request_hash,
        credential,
        Instant::now(),
    )
}

fn signed_challenge(credential: &PublicKeyCredential) -> Vec<u8> {
    let credential = serde_json::to_value(credential).unwrap();
    let client_data: Base64UrlSafeData =
        serde_json::from_value(credential["response"]["clientDataJSON"].clone()).unwrap();
    let client_data: Value = serde_json::from_slice(client_data.as_ref()).unwrap();
    let challenge: Base64UrlSafeData =
        serde_json::from_value(client_data["challenge"].clone()).unwrap();
    challenge.into()
}

#[test]
fn registration_and_login_succeed_and_rotate_the_session() {
    let rp = relying_party();
    let mut authenticator = SoftAuthenticator::new();
    let anonymous = rp.open_session();
    let options = rp
        .register_start(&anonymous, "owner", Instant::now())
        .unwrap();
    rp.register_finish(
        &anonymous,
        &authenticator.register(&options),
        Instant::now(),
    )
    .unwrap();
    let options = rp.login_start(&anonymous, "owner", Instant::now()).unwrap();
    let (session, _) = rp
        .login_finish(&anonymous, &authenticator.assert(&options), Instant::now())
        .unwrap();
    assert_ne!(session, anonymous);
    assert_eq!(rp.session_user(&session).as_deref(), Some("owner"));
    assert!(!rp.has_session(&anonymous));
}

#[test]
fn step_up_signs_the_challenge_derived_from_the_request_hash() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    let credential = authenticator.assert(&pending.options);
    assert_eq!(
        signed_challenge(&credential),
        stepup::derive_challenge(&stepup::session_handle(&session), &pending.request_hash).to_vec()
    );
    let approved = finish(&rp, &session, &pending, &credential).unwrap();
    assert_eq!(approved.request_hash, pending.request_hash);
}

#[test]
fn approved_carries_the_canonical_request_to_execute() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "execute me");
    let credential = authenticator.assert(&pending.options);
    let approved = finish(&rp, &session, &pending, &credential).unwrap();
    assert_eq!(
        action::request_hash(&approved.canonical_request),
        approved.request_hash
    );
    let decoded = action::decode_request(&approved.canonical_request).unwrap();
    assert_eq!(decoded.request_id, pending.request_id);
    assert_eq!(decoded.input, action("execute me"));
}

#[test]
fn assertion_for_one_request_is_refused_for_another() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let first = start(&rp, &session, "a");
    let second = start(&rp, &session, "b");
    let for_first = authenticator.assert(&first.options);
    let refused = finish(&rp, &session, &second, &for_first);
    assert!(
        matches!(
            refused,
            Err(RpError::Webauthn(WebauthnError::MismatchedChallenge))
        ),
        "{refused:?}"
    );
    let for_second = authenticator.assert(&second.options);
    finish(&rp, &session, &second, &for_second).unwrap();
}

#[test]
fn request_presented_with_another_hash_is_refused() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let first = start(&rp, &session, "a");
    let second = start(&rp, &session, "b");
    let credential = authenticator.assert(&first.options);
    let refused = rp.step_up_finish(
        &session,
        &first.request_id,
        &second.request_hash,
        &credential,
        Instant::now(),
    );
    assert!(
        matches!(refused, Err(RpError::ActionMismatch)),
        "{refused:?}"
    );
}

#[test]
fn replayed_assertion_is_refused() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    let credential = authenticator.assert(&pending.options);
    finish(&rp, &session, &pending, &credential).unwrap();
    let refused = finish(&rp, &session, &pending, &credential);
    assert!(matches!(refused, Err(RpError::AlreadyUsed)), "{refused:?}");
}

#[test]
fn same_assertion_sent_twice_at_once_is_approved_once() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    let credential = authenticator.assert(&pending.options);
    let barrier = Barrier::new(2);
    let outcomes: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..2)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    finish(&rp, &session, &pending, &credential)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert_eq!(outcomes.iter().filter(|o| o.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|o| matches!(o, Err(RpError::AlreadyUsed)))
            .count(),
        1
    );
}

#[test]
fn counter_value_seen_once_is_refused_on_another_pending_request() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    // Both requests snapshot the same stored counter at start.
    let first = start(&rp, &session, "a");
    let second = start(&rp, &session, "b");
    let for_first = authenticator.assert(&first.options);
    finish(&rp, &session, &first, &for_first).unwrap();
    // A clone of the authenticator answers the second request with the counter already used.
    let clone_answer = authenticator.assert_with_counter(&second.options, authenticator.counter);
    let refused = finish(&rp, &session, &second, &clone_answer);
    assert!(
        matches!(refused, Err(RpError::CounterRegressed)),
        "{refused:?}"
    );
    let honest = authenticator.assert(&second.options);
    finish(&rp, &session, &second, &honest).unwrap();
}

#[test]
fn assertion_without_user_verification_is_refused() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    authenticator.user_verified = false;
    let credential = authenticator.assert(&pending.options);
    let refused = finish(&rp, &session, &pending, &credential);
    assert!(
        matches!(
            refused,
            Err(RpError::Webauthn(WebauthnError::UserNotVerified))
        ),
        "{refused:?}"
    );
}

#[test]
fn expired_request_is_refused() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    let credential = authenticator.assert(&pending.options);
    let refused = rp.step_up_finish(
        &session,
        &pending.request_id,
        &pending.request_hash,
        &credential,
        Instant::now() + rp.ceremony_lifetime(),
    );
    assert!(matches!(refused, Err(RpError::Expired)), "{refused:?}");
}

#[test]
fn server_expiry_is_the_prompt_timeout_plus_the_slack() {
    let rp = relying_party();
    assert_eq!(
        rp.ceremony_lifetime(),
        PROMPT_TIMEOUT + passkey_stepup::rp::EXPIRY_SLACK
    );
}

#[test]
fn login_and_registration_states_expire() {
    let rp = relying_party();
    let mut authenticator = SoftAuthenticator::new();
    let session = rp.open_session();
    let options = rp
        .register_start(&session, "owner", Instant::now())
        .unwrap();
    let refused = rp.register_finish(
        &session,
        &authenticator.register(&options),
        Instant::now() + rp.ceremony_lifetime(),
    );
    assert!(matches!(refused, Err(RpError::Expired)), "{refused:?}");
    let (mut authenticator, _) = enrolled(&rp);
    let session = rp.open_session();
    let options = rp.login_start(&session, "owner", Instant::now()).unwrap();
    let refused = rp.login_finish(
        &session,
        &authenticator.assert(&options),
        Instant::now() + rp.ceremony_lifetime(),
    );
    assert!(matches!(refused, Err(RpError::Expired)), "{refused:?}");
}

#[test]
fn unknown_user_gets_options_of_the_same_shape_and_cannot_log_in() {
    let rp = relying_party();
    let (mut authenticator, _) = enrolled(&rp);
    let session = rp.open_session();
    let known = rp.login_start(&session, "owner", Instant::now()).unwrap();
    let unknown = rp.login_start(&session, "nobody", Instant::now()).unwrap();
    let again = rp.login_start(&session, "nobody", Instant::now()).unwrap();
    let ids = |options: &RequestChallengeResponse| {
        serde_json::to_value(options).unwrap()["publicKey"]["allowCredentials"]
            .as_array()
            .unwrap()
            .iter()
            .map(|credential| credential["id"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&known).len(), ids(&unknown).len());
    assert_eq!(ids(&unknown), ids(&again));
    let refused = rp.login_finish(&session, &authenticator.assert(&again), Instant::now());
    assert!(matches!(refused, Err(RpError::Webauthn(_))), "{refused:?}");
}

#[test]
fn request_of_another_session_reads_as_unknown() {
    let rp = relying_party();
    let (mut authenticator, first_session) = enrolled(&rp);
    let second_session = login(&rp, &mut authenticator);
    let pending = start(&rp, &first_session, "a");
    let credential = authenticator.assert(&pending.options);
    let refused = finish(&rp, &second_session, &pending, &credential);
    assert!(
        matches!(refused, Err(RpError::UnknownRequest)),
        "{refused:?}"
    );
    // The same action asked in the second session gets another challenge, so the assertion
    // made in the first session does not verify there either.
    let same_action = start(&rp, &second_session, "a");
    let refused = finish(&rp, &second_session, &same_action, &credential);
    assert!(
        matches!(
            refused,
            Err(RpError::Webauthn(WebauthnError::MismatchedChallenge))
        ),
        "{refused:?}"
    );
}

#[test]
fn login_assertion_does_not_approve_a_step_up() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let anonymous = rp.open_session();
    let login_options = rp.login_start(&anonymous, "owner", Instant::now()).unwrap();
    let login_assertion = authenticator.assert(&login_options);
    let pending = start(&rp, &session, "a");
    let refused = finish(&rp, &session, &pending, &login_assertion);
    assert!(
        matches!(
            refused,
            Err(RpError::Webauthn(WebauthnError::MismatchedChallenge))
        ),
        "{refused:?}"
    );
}

#[test]
fn assertion_from_another_origin_is_refused() {
    let rp = relying_party();
    let (mut authenticator, session) = enrolled(&rp);
    let pending = start(&rp, &session, "a");
    authenticator.origin = "https://attacker.example:8443".to_owned();
    let credential = authenticator.assert(&pending.options);
    let refused = finish(&rp, &session, &pending, &credential);
    assert!(
        matches!(
            refused,
            Err(RpError::Webauthn(WebauthnError::InvalidRPOrigin))
        ),
        "{refused:?}"
    );
}

#[test]
fn step_up_needs_a_logged_in_session() {
    let rp = relying_party();
    let _enrolled = enrolled(&rp);
    let anonymous = rp.open_session();
    let refused = rp.step_up_start(&anonymous, &action("a"), Instant::now());
    assert!(
        matches!(refused, Err(RpError::NotAuthenticated)),
        "{refused:?}"
    );
}
