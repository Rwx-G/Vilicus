// Spike E22, pairing page (its CSP alone adds 'wasm-unsafe-eval'): issuing a code from a
// paired browser and redeeming it in a new browser (AC2), with `@serenity-kit/opaque` 1.1.0
// as the OPAQUE client.
//
// Issuing: the paired browser draws the secret, registers it with the Core as an OPAQUE
// password through signed requests, checks the Core's signature over the registration
// response with the identity key it pinned when it was registered, and shows
// `handle-secret`. Redeeming: the new browser runs an OPAQUE login with the secret, derives a
// key from the session key, sends its public key with an HMAC under that key and a proof of
// possession, and learns the Core's identity key authenticated by the same key.

import * as opaque from './opaque.js';
import {
  b64u,
  concat,
  createDeviceRecord,
  deviceSign,
  loadRecord,
  openSession,
  popMessage,
  postJson,
  probePage,
  saveRecord,
  setStatus,
  unb64u,
  utf8,
  verifyEcdsa,
} from './common.js';

const HANDLE_DIGITS = 3;
const SECRET_DIGITS = 8;
const BIND_LABEL = utf8('vilicus/v1/pair/bind');
const REGISTRATION_LABEL = utf8('vilicus/v1/pair/registration');
const CORE_KEY_LABEL = utf8('vilicus/v1/pair/core-key');

// Uniform decimal digits by rejection sampling, as `random_digits` in src/pairing.rs.
function randomDigits(count) {
  let out = '';
  const byte = new Uint8Array(1);
  while (out.length < count) {
    crypto.getRandomValues(byte);
    if (byte[0] < 250) out += String(byte[0] % 10);
  }
  return out;
}

function parseCode(typed) {
  const digits = typed.replace(/[- ]/g, '');
  if (!/^[0-9]+$/.test(digits) || digits.length !== HANDLE_DIGITS + SECRET_DIGITS) return null;
  return { handle: digits.slice(0, HANDLE_DIGITS), secret: digits.slice(HANDLE_DIGITS) };
}

async function probe() {
  const page = await probePage();
  try {
    await opaque.ready;
    page.opaque = 'ready';
  } catch (error) {
    page.opaque = `failed:${error.name}`;
  }
  return page;
}

// Probed from the module's own execution: code that a DevTools protocol evaluation runs
// synchronously may bypass the CSP's eval restriction in Chrome.
const loadProbe = probe();

async function issue() {
  await opaque.ready;
  const record = await loadRecord();
  if (!record || !record.deviceId) return { error: 'not_paired' };
  if (!record.coreKey) return { error: 'no_pinned_core_key' };
  const opened = await openSession(record);
  if (opened.error) return opened;
  const session = opened.session;

  const secret = randomDigits(SECRET_DIGITS);
  const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({ password: secret });
  const started = await session.post('/api/pair/issue/start', { registration_request: registrationRequest });
  if (started.status !== 200) return { error: started.json.error };
  const handle = started.json.handle;
  const authentic = await verifyEcdsa(
    unb64u(record.coreKey),
    concat(REGISTRATION_LABEL, utf8(handle), unb64u(started.json.registration_response)),
    unb64u(started.json.signature),
  );
  if (!authentic) return { error: 'registration_response_not_authenticated' };
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState,
    registrationResponse: started.json.registration_response,
    password: secret,
  });
  const finished = await session.post('/api/pair/issue/finish', { handle, registration_upload: registrationRecord });
  if (finished.status !== 200) return { error: finished.json.error };
  return { code: `${handle}-${secret.slice(0, 4)}-${secret.slice(4)}` };
}

async function bindKey(sessionKey) {
  const ikm = await crypto.subtle.importKey('raw', sessionKey, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: BIND_LABEL },
    ikm,
    256,
  );
  return crypto.subtle.importKey('raw', bits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function redeem(typed) {
  await opaque.ready;
  const code = parseCode(typed);
  if (!code) return { error: 'malformed_code' };
  const record = (await loadRecord()) ?? (await createDeviceRecord());
  if (record.deviceId) return { error: 'already_paired' };

  const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: code.secret });
  const started = await postJson('/api/pair/login/start', { handle: code.handle, credential_request: startLoginRequest });
  if (started.status !== 200) return { error: started.json.error, publicKey: b64u(record.publicKey) };
  const finished = opaque.client.finishLogin({
    clientLoginState,
    loginResponse: started.json.credential_response,
    password: code.secret,
  });
  // A wrong secret, and a code that is unknown, used, expired or out of attempts, all end
  // here: the Core answers them alike.
  if (!finished) return { error: 'opaque_client_rejected', publicKey: b64u(record.publicKey) };

  const loginId = started.json.login_id;
  const key = await bindKey(unb64u(finished.sessionKey));
  const message = concat(BIND_LABEL, utf8(code.handle), unb64u(loginId), record.publicKey);
  const tag = await crypto.subtle.sign('HMAC', key, message);
  const proof = await deviceSign(record, popMessage(message, record.publicKey));
  const bound = await postJson('/api/pair/login/finish', {
    login_id: loginId,
    credential_finalization: finished.finishLoginRequest,
    public_key: b64u(record.publicKey),
    tag: b64u(tag),
    proof: b64u(proof),
  });
  if (bound.status !== 200) return { error: bound.json.error, publicKey: b64u(record.publicKey) };
  const coreKey = unb64u(bound.json.core_key);
  const coreKeyAuthentic = await crypto.subtle.verify(
    'HMAC',
    key,
    unb64u(bound.json.core_key_tag),
    concat(CORE_KEY_LABEL, coreKey),
  );
  if (!coreKeyAuthentic) return { error: 'core_key_not_authenticated', publicKey: b64u(record.publicKey) };
  record.deviceId = bound.json.device_id;
  record.coreKey = bound.json.core_key;
  await saveRecord(record);

  // The new device's first session, signed with the key that was just bound.
  const opened = await openSession(record);
  if (opened.error) return { error: opened.error, publicKey: b64u(record.publicKey) };
  const echo = await opened.session.post('/api/echo', { paired: true });
  return { deviceId: record.deviceId, publicKey: b64u(record.publicKey), echoStatus: echo.status };
}

window.e22pair = { probe: () => loadProbe, issue, redeem };
setStatus('ready');
