//! The Core's checks with Rust clients standing in for the browser: the AD-21 request
//! signature, session reopening, OPAQUE pairing with its relay and replay attacks, and light
//! confirmations. The browser driver runs the same flows with WebCrypto and the WASM client.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use browser_device_key::core::{
    CONFIRMATION_TTL_SECS, Core, LOGIN_RATE_LIMIT, Origin, PAIRING_ATTEMPTS, PAIRING_TTL_SECS,
    Refusal, Registered, SESSION_CHALLENGE_TTL_SECS,
};
use browser_device_key::device::{self, Id};
use browser_device_key::pairing::{self, Code, Suite};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, Identifiers, RegistrationResponse,
};
use rand_core::OsRng;

const SOURCE: &str = "192.0.2.10";

struct TestDevice {
    key: EcdsaKeyPair,
    rng: SystemRandom,
}

impl TestDevice {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        Self { key, rng }
    }

    fn public_key(&self) -> Vec<u8> {
        self.key.public_key().as_ref().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.key.sign(&self.rng, message).unwrap().as_ref().to_vec()
    }

    fn sign_request(
        &self,
        session: &Id,
        counter: u64,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Vec<u8> {
        self.sign(&device::request_digest(
            session, counter, method, path, body,
        ))
    }
}

fn enroll(core: &mut Core, device: &TestDevice) -> Registered {
    let token = core.issue_enrollment_token();
    let public_key = device.public_key();
    let proof = device.sign(&device::pop_message(&token, &public_key));
    core.enroll(&token, &public_key, &proof).unwrap()
}

/// A Core with one enrolled issuing device.
fn core_with_issuer() -> (Core, Id) {
    let mut core = Core::new();
    let issuer = enroll(&mut core, &TestDevice::new()).device_id;
    (core, issuer)
}

/// What the issuing browser does: draw a secret, register it with the Core through OPAQUE,
/// after checking the Core's signature over the response with the pinned identity key.
fn issue_from_device(core: &mut Core, issuer: &Id) -> Code {
    let secret = pairing::random_digits(pairing::SECRET_DIGITS, |buf| {
        aws_lc_rs::rand::fill(buf).unwrap();
    });
    let start = ClientRegistration::<Suite>::start(&mut OsRng, secret.as_bytes()).unwrap();
    let issued = core
        .issue_start(issuer, &start.message.serialize())
        .unwrap();
    assert!(device::verify(
        &core.identity_public_key(),
        &pairing::registration_message(&issued.handle, &issued.response),
        &issued.signature,
    ));
    let ksf = pairing::client_ksf();
    let finish = start
        .state
        .finish(
            &mut OsRng,
            secret.as_bytes(),
            RegistrationResponse::deserialize(&issued.response).unwrap(),
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .unwrap();
    core.issue_finish(issuer, &issued.handle, &finish.message.serialize())
        .unwrap();
    Code {
        handle: issued.handle,
        secret,
    }
}

/// What the new browser sends after a successful OPAQUE login.
struct LoginFinish {
    login_id: Id,
    finalization: Vec<u8>,
    session_key: Vec<u8>,
}

/// Runs the new browser's OPAQUE login; `None` when the client rejects the server's answer
/// (a wrong secret, or the fake answer for a handle that is not live).
fn login(core: &mut Core, handle: &str, secret: &str) -> Result<Option<LoginFinish>, Refusal> {
    let start = ClientLogin::<Suite>::start(&mut OsRng, secret.as_bytes()).unwrap();
    let (login_id, response) = core.login_start(SOURCE, handle, &start.message.serialize())?;
    let ksf = pairing::client_ksf();
    let finish = start.state.finish(
        &mut OsRng,
        secret.as_bytes(),
        CredentialResponse::deserialize(&response).unwrap(),
        ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
    );
    Ok(finish.ok().map(|finish| LoginFinish {
        login_id,
        finalization: finish.message.serialize().to_vec(),
        session_key: finish.session_key.to_vec(),
    }))
}

/// The binding tag and proof the new browser sends with its public key.
fn binding(handle: &str, finish: &LoginFinish, device: &TestDevice) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let public_key = device.public_key();
    let message = pairing::bind_message(handle, &finish.login_id, &public_key);
    let tag = pairing::bind_tag(&finish.session_key, &message);
    let proof = device.sign(&device::pop_message(&message, &public_key));
    (public_key, tag, proof)
}

fn finish_with(
    core: &mut Core,
    code: &Code,
    finish: &LoginFinish,
    device: &TestDevice,
) -> Result<Registered, Refusal> {
    let (public_key, tag, proof) = binding(&code.handle, finish, device);
    core.login_finish(
        &finish.login_id,
        &finish.finalization,
        &public_key,
        &tag,
        &proof,
    )
    .map(|(registered, _)| registered)
}

fn pair(core: &mut Core, code: &Code, device: &TestDevice) -> Result<Registered, Refusal> {
    let finish = login(core, &code.handle, &code.secret)?.expect("right secret, live code");
    finish_with(core, code, &finish, device)
}

#[test]
fn signed_requests_verify_and_replays_are_refused() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered {
        device_id,
        session_id,
    } = enroll(&mut core, &browser);
    let body = br#"{"hello":"world"}"#;
    let signature = browser.sign_request(&session_id, 1, "POST", "/api/echo", body);
    assert_eq!(
        core.verify_request(&session_id, 1, "POST", "/api/echo", body, Some(&signature)),
        Ok(device_id)
    );
    assert_eq!(
        core.verify_request(&session_id, 1, "POST", "/api/echo", body, Some(&signature)),
        Err(Refusal::CounterNotIncreasing)
    );
    let later = browser.sign_request(&session_id, 5, "POST", "/api/echo", body);
    assert!(
        core.verify_request(&session_id, 5, "POST", "/api/echo", body, Some(&later))
            .is_ok()
    );
    let lower = browser.sign_request(&session_id, 4, "POST", "/api/echo", body);
    assert_eq!(
        core.verify_request(&session_id, 4, "POST", "/api/echo", body, Some(&lower)),
        Err(Refusal::CounterNotIncreasing)
    );
    let next = browser.sign_request(&session_id, 6, "POST", "/api/echo", body);
    for (method, path, other_body) in [
        ("POST", "/api/echo", &br#"{"hello":"there"}"#[..]),
        ("POST", "/api/other", &body[..]),
        ("PUT", "/api/echo", &body[..]),
    ] {
        assert_eq!(
            core.verify_request(&session_id, 6, method, path, other_body, Some(&next)),
            Err(Refusal::BadRequestSignature)
        );
    }
    assert_eq!(
        core.verify_request(&session_id, 6, "POST", "/api/echo", body, None),
        Err(Refusal::MissingSignature)
    );
    let other = TestDevice::new();
    let forged = other.sign_request(&session_id, 7, "POST", "/api/echo", body);
    assert_eq!(
        core.verify_request(&session_id, 7, "POST", "/api/echo", body, Some(&forged)),
        Err(Refusal::BadRequestSignature)
    );
    assert_eq!(
        core.verify_request(&[0u8; 16], 7, "POST", "/api/echo", body, Some(&forged)),
        Err(Refusal::UnknownSession)
    );
    // The refused requests at counters 6 and 7 did not advance the counter.
    assert_eq!(
        core.verify_request(&session_id, 6, "POST", "/api/echo", body, Some(&next)),
        Ok(device_id)
    );
}

#[test]
fn enrollment_needs_an_unused_token_and_a_proof() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let token = core.issue_enrollment_token();
    let public_key = browser.public_key();
    let other = TestDevice::new();
    let wrong = other.sign(&device::pop_message(&token, &public_key));
    assert_eq!(
        core.enroll(&token, &public_key, &wrong),
        Err(Refusal::BadProof)
    );
    let proof = browser.sign(&device::pop_message(&token, &public_key));
    assert!(core.enroll(&token, &public_key, &proof).is_ok());
    assert_eq!(
        core.enroll(&token, &public_key, &proof),
        Err(Refusal::UnknownToken)
    );
}

#[test]
fn a_session_reopens_only_with_a_fresh_signed_challenge() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered { device_id, .. } = enroll(&mut core, &browser);
    let nonce = core.session_challenge(&device_id).unwrap();
    let other = TestDevice::new();
    let forged = other.sign(&device::session_message(&device_id, &nonce));
    assert_eq!(
        core.open_session(&device_id, &nonce, &forged),
        Err(Refusal::BadProof)
    );
    assert_eq!(
        core.open_session(&device_id, &nonce, &forged),
        Err(Refusal::UnknownChallenge)
    );
    let nonce = core.session_challenge(&device_id).unwrap();
    let signature = browser.sign(&device::session_message(&device_id, &nonce));
    let session_id = core.open_session(&device_id, &nonce, &signature).unwrap();
    assert_eq!(
        core.open_session(&device_id, &nonce, &signature),
        Err(Refusal::UnknownChallenge)
    );
    let request = browser.sign_request(&session_id, 1, "POST", "/api/echo", b"");
    assert_eq!(
        core.verify_request(&session_id, 1, "POST", "/api/echo", b"", Some(&request)),
        Ok(device_id)
    );
}

#[test]
fn a_session_challenge_expires() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered { device_id, .. } = enroll(&mut core, &browser);
    let nonce = core.session_challenge(&device_id).unwrap();
    core.advance_clock(SESSION_CHALLENGE_TTL_SECS + 1);
    let signature = browser.sign(&device::session_message(&device_id, &nonce));
    assert_eq!(
        core.open_session(&device_id, &nonce, &signature),
        Err(Refusal::ChallengeExpired)
    );
}

#[test]
fn a_session_challenge_is_bound_to_its_device() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered { device_id, .. } = enroll(&mut core, &browser);
    let other = TestDevice::new();
    let Registered {
        device_id: other_id,
        ..
    } = enroll(&mut core, &other);
    let nonce = core.session_challenge(&device_id).unwrap();
    let signature = other.sign(&device::session_message(&other_id, &nonce));
    assert_eq!(
        core.open_session(&other_id, &nonce, &signature),
        Err(Refusal::UnknownChallenge)
    );
}

#[test]
fn a_device_issued_code_pairs_the_new_browser_key() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let browser = TestDevice::new();
    let finish = login(&mut core, &code.handle, &code.secret)
        .unwrap()
        .unwrap();
    let (public_key, tag, proof) = binding(&code.handle, &finish, &browser);
    let (registered, core_key_tag) = core
        .login_finish(
            &finish.login_id,
            &finish.finalization,
            &public_key,
            &tag,
            &proof,
        )
        .unwrap();
    assert_eq!(
        core.device_by_key(&browser.public_key()),
        Some((registered.device_id, Origin::Pairing))
    );
    // The new browser can authenticate the Core's identity key with its session key.
    assert_eq!(
        core_key_tag,
        pairing::core_key_tag(&finish.session_key, &core.identity_public_key())
    );
    let signature = browser.sign_request(&registered.session_id, 1, "POST", "/api/echo", b"{}");
    assert!(
        core.verify_request(
            &registered.session_id,
            1,
            "POST",
            "/api/echo",
            b"{}",
            Some(&signature)
        )
        .is_ok()
    );
}

#[test]
fn a_host_issued_code_pairs_the_new_browser_key() {
    let mut core = Core::new();
    let code = core.issue_on_host().unwrap();
    let parsed = Code::parse(&code.display()).unwrap();
    assert!(pair(&mut core, &parsed, &TestDevice::new()).is_ok());
}

#[test]
fn the_registration_response_is_signed_by_the_core() {
    let (mut core, issuer) = core_with_issuer();
    let start = ClientRegistration::<Suite>::start(&mut OsRng, b"12345678").unwrap();
    let issued = core
        .issue_start(&issuer, &start.message.serialize())
        .unwrap();
    let mut substituted = issued.response.clone();
    substituted[0] ^= 1;
    assert!(!device::verify(
        &core.identity_public_key(),
        &pairing::registration_message(&issued.handle, &substituted),
        &issued.signature,
    ));
}

#[test]
fn only_the_starting_device_finishes_an_issuance() {
    let (mut core, issuer) = core_with_issuer();
    let other = enroll(&mut core, &TestDevice::new()).device_id;
    let secret = b"12345678";
    let start = ClientRegistration::<Suite>::start(&mut OsRng, secret).unwrap();
    let issued = core
        .issue_start(&issuer, &start.message.serialize())
        .unwrap();
    let ksf = pairing::client_ksf();
    let upload = start
        .state
        .finish(
            &mut OsRng,
            secret,
            RegistrationResponse::deserialize(&issued.response).unwrap(),
            ClientRegistrationFinishParameters::new(Identifiers::default(), Some(&ksf)),
        )
        .unwrap()
        .message
        .serialize()
        .to_vec();
    assert_eq!(
        core.issue_finish(&other, &issued.handle, &upload),
        Err(Refusal::UnknownPairing)
    );
    assert!(core.issue_finish(&issuer, &issued.handle, &upload).is_ok());
}

#[test]
fn a_code_is_single_use_and_a_spent_code_looks_like_a_wrong_one() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    pair(&mut core, &code, &TestDevice::new()).unwrap();
    assert!(
        login(&mut core, &code.handle, &code.secret)
            .unwrap()
            .is_none()
    );
    assert!(core.pairing_state(&code.handle).unwrap().used);
}

#[test]
fn wrong_secrets_use_up_the_attempts() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let wrong = if code.secret == "00000000" {
        "11111111"
    } else {
        "00000000"
    };
    for _ in 0..PAIRING_ATTEMPTS {
        assert!(
            login(&mut core, &code.handle, wrong).unwrap().is_none(),
            "client detects the wrong secret"
        );
    }
    assert!(
        login(&mut core, &code.handle, &code.secret)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        core.pairing_state(&code.handle).unwrap().attempts,
        PAIRING_ATTEMPTS
    );
}

#[test]
fn an_unknown_handle_gets_a_fake_answer() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let unknown = (0..1000)
        .map(|n| format!("{n:03}"))
        .find(|handle| core.pairing_state(handle).is_none())
        .unwrap();
    assert!(login(&mut core, &unknown, &code.secret).unwrap().is_none());
    // Nothing was charged to the live pairing.
    assert_eq!(core.pairing_state(&code.handle).unwrap().attempts, 0);
}

#[test]
fn login_starts_are_rate_limited_per_source() {
    let mut core = Core::new();
    for _ in 0..LOGIN_RATE_LIMIT {
        assert_eq!(
            core.login_start(SOURCE, "000", b"garbage"),
            Err(Refusal::BadMessage)
        );
    }
    assert_eq!(
        core.login_start(SOURCE, "000", b"garbage"),
        Err(Refusal::RateLimited)
    );
    assert_eq!(
        core.login_start("192.0.2.11", "000", b"garbage"),
        Err(Refusal::BadMessage)
    );
}

#[test]
fn an_expired_code_is_refused() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    core.advance_clock(PAIRING_TTL_SECS + 1);
    assert!(
        login(&mut core, &code.handle, &code.secret)
            .unwrap()
            .is_none()
    );
    assert!(core.pairing_state(&code.handle).unwrap().expired);
}

#[test]
fn a_code_expiring_between_start_and_finish_is_refused() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let finish = login(&mut core, &code.handle, &code.secret)
        .unwrap()
        .unwrap();
    core.advance_clock(PAIRING_TTL_SECS + 1);
    let browser = TestDevice::new();
    assert_eq!(
        finish_with(&mut core, &code, &finish, &browser),
        Err(Refusal::PairingExpired)
    );
    assert_eq!(core.device_by_key(&browser.public_key()), None);
}

#[test]
fn a_relay_cannot_substitute_its_key_and_burns_the_code() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let browser = TestDevice::new();
    let finish = login(&mut core, &code.handle, &code.secret)
        .unwrap()
        .unwrap();
    let (_, browser_tag, _) = binding(&code.handle, &finish, &browser);

    // The relay keeps the browser's tag (it lacks the session key) and proves its own key.
    let relay = TestDevice::new();
    let relay_key = relay.public_key();
    let message = pairing::bind_message(&code.handle, &finish.login_id, &relay_key);
    let relay_proof = relay.sign(&device::pop_message(&message, &relay_key));
    assert_eq!(
        core.login_finish(
            &finish.login_id,
            &finish.finalization,
            &relay_key,
            &browser_tag,
            &relay_proof
        )
        .map(|(r, _)| r),
        Err(Refusal::BindingMismatch)
    );
    assert_eq!(core.device_by_key(&relay_key), None);
    // The OPAQUE run completed, so the code is used up; the browser pairs again with a new one.
    assert!(core.pairing_state(&code.handle).unwrap().used);
    assert!(
        login(&mut core, &code.handle, &code.secret)
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_relay_tag_under_a_guessed_session_key_is_refused() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let finish = login(&mut core, &code.handle, &code.secret)
        .unwrap()
        .unwrap();
    let relay = TestDevice::new();
    let relay_key = relay.public_key();
    let message = pairing::bind_message(&code.handle, &finish.login_id, &relay_key);
    let tag = pairing::bind_tag(&[0u8; 64], &message);
    let proof = relay.sign(&device::pop_message(&message, &relay_key));
    assert_eq!(
        core.login_finish(
            &finish.login_id,
            &finish.finalization,
            &relay_key,
            &tag,
            &proof
        )
        .map(|(r, _)| r),
        Err(Refusal::BindingMismatch)
    );
}

#[test]
fn a_right_tag_without_the_matching_proof_is_refused() {
    for foreign_proof in [false, true] {
        let (mut core, issuer) = core_with_issuer();
        let code = issue_from_device(&mut core, &issuer);
        let browser = TestDevice::new();
        let finish = login(&mut core, &code.handle, &code.secret)
            .unwrap()
            .unwrap();
        let (public_key, tag, _) = binding(&code.handle, &finish, &browser);
        let proof = if foreign_proof {
            let message = pairing::bind_message(&code.handle, &finish.login_id, &public_key);
            TestDevice::new().sign(&device::pop_message(&message, &public_key))
        } else {
            vec![0u8; 64]
        };
        assert_eq!(
            core.login_finish(
                &finish.login_id,
                &finish.finalization,
                &public_key,
                &tag,
                &proof
            )
            .map(|(r, _)| r),
            Err(Refusal::BadProof)
        );
        assert_eq!(core.device_by_key(&public_key), None);
    }
}

#[test]
fn recorded_pairing_messages_cannot_be_replayed() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let browser = TestDevice::new();

    // The browser's run, observed: its first message and, later, its third.
    let start = ClientLogin::<Suite>::start(&mut OsRng, code.secret.as_bytes()).unwrap();
    let recorded_request = start.message.serialize().to_vec();
    let (browser_login, response) = core
        .login_start(SOURCE, &code.handle, &recorded_request)
        .unwrap();
    let ksf = pairing::client_ksf();
    let first = start
        .state
        .finish(
            &mut OsRng,
            code.secret.as_bytes(),
            CredentialResponse::deserialize(&response).unwrap(),
            ClientLoginFinishParameters::new(None, Identifiers::default(), Some(&ksf)),
        )
        .unwrap();
    let recorded_finalization = first.message.serialize().to_vec();

    // The observer replays the first message: the Core answers with a fresh server share, so
    // the recorded third message does not verify in the new run.
    let (replayed_login, _) = core
        .login_start(SOURCE, &code.handle, &recorded_request)
        .unwrap();
    let relay = TestDevice::new();
    assert_eq!(
        core.login_finish(
            &replayed_login,
            &recorded_finalization,
            &relay.public_key(),
            &[0u8; 32],
            &[0u8; 64]
        )
        .map(|(r, _)| r),
        Err(Refusal::OpaqueFailed)
    );
    // The replayed start did not cancel the browser's run, which still completes.
    let finish = LoginFinish {
        login_id: browser_login,
        finalization: recorded_finalization,
        session_key: first.session_key.to_vec(),
    };
    let registered = finish_with(&mut core, &code, &finish, &browser).unwrap();
    assert_eq!(
        core.device_key(&registered.device_id),
        Some(browser.public_key().as_slice())
    );
}

#[test]
fn a_finished_run_cannot_be_replayed() {
    let (mut core, issuer) = core_with_issuer();
    let code = issue_from_device(&mut core, &issuer);
    let browser = TestDevice::new();
    let finish = login(&mut core, &code.handle, &code.secret)
        .unwrap()
        .unwrap();
    finish_with(&mut core, &code, &finish, &browser).unwrap();
    assert_eq!(
        finish_with(&mut core, &code, &finish, &browser),
        Err(Refusal::UnknownPairing)
    );
}

#[test]
fn a_light_confirmation_approves_its_request_only() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered { device_id, .. } = enroll(&mut core, &browser);
    let other_browser = TestDevice::new();
    let Registered {
        device_id: other_device,
        ..
    } = enroll(&mut core, &other_browser);

    let a = core
        .create_pending(&device_id, "tasks.create", "A")
        .unwrap();
    let b = core
        .create_pending(&device_id, "tasks.create", "B")
        .unwrap();
    let (nonce_a, bytes_a) = core.confirmation_challenge(&device_id, &a).unwrap();
    let (nonce_b, bytes_b) = core.confirmation_challenge(&device_id, &b).unwrap();
    let signature_a = browser.sign(&bytes_a);

    // Another device cannot obtain a challenge for this device's request.
    assert_eq!(
        core.confirmation_challenge(&other_device, &a),
        Err(Refusal::UnknownRequest)
    );
    // Another request's bytes, or another request's nonce, are refused.
    assert_eq!(
        core.approve(&device_id, &b, &nonce_b, &signature_a),
        Err(Refusal::BadConfirmationSignature)
    );
    assert_eq!(
        core.approve(&device_id, &b, &nonce_a, &signature_a),
        Err(Refusal::NonceForOtherRequest)
    );
    // Tampered bytes are refused.
    let mut tampered = bytes_a.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        core.approve(&device_id, &a, &nonce_a, &browser.sign(&tampered)),
        Err(Refusal::BadConfirmationSignature)
    );
    // Another device cannot use this device's challenge.
    assert_eq!(
        core.approve(&other_device, &a, &nonce_a, &other_browser.sign(&bytes_a)),
        Err(Refusal::NonceForOtherDevice)
    );
    // The right signature approves, once.
    assert_eq!(core.approve(&device_id, &a, &nonce_a, &signature_a), Ok(()));
    assert_eq!(
        core.approve(&device_id, &a, &nonce_a, &signature_a),
        Err(Refusal::NonceUsed)
    );
    // A decided request accepts no new challenge, and an older challenge for it is useless.
    assert_eq!(
        core.confirmation_challenge(&device_id, &a),
        Err(Refusal::RequestDecided)
    );
    assert_eq!(
        core.approve(&device_id, &b, &nonce_b, &browser.sign(&bytes_b)),
        Ok(())
    );
}

#[test]
fn an_expired_confirmation_challenge_is_refused() {
    let mut core = Core::new();
    let browser = TestDevice::new();
    let Registered { device_id, .. } = enroll(&mut core, &browser);
    let request = core
        .create_pending(&device_id, "tasks.create", "A")
        .unwrap();
    let (nonce, bytes) = core.confirmation_challenge(&device_id, &request).unwrap();
    core.advance_clock(CONFIRMATION_TTL_SECS + 1);
    assert_eq!(
        core.approve(&device_id, &request, &nonce, &browser.sign(&bytes)),
        Err(Refusal::ChallengeExpired)
    );
}
