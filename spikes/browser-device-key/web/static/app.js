// Spike E22, application page (no 'wasm-unsafe-eval'): enrollment of the device key (AC1),
// signed requests and their tampered variants (AC1), and light confirmations (AC3). The
// browser driver calls the functions of `window.e22` and checks what they return.

import {
  b64u,
  createDeviceRecord,
  deviceSign,
  inspectKey,
  loadRecord,
  openSession,
  popMessage,
  postJson,
  probePage,
  saveRecord,
  setStatus,
  unb64u,
} from './common.js';
import { checkConfirmation, decodeCanonical, encodeCanonical } from './confirm.js';

let session = null;

async function enroll(token) {
  const record = await createDeviceRecord();
  const proof = await deviceSign(record, popMessage(unb64u(token), record.publicKey));
  const result = await postJson('/api/enroll', { token, public_key: b64u(record.publicKey), proof: b64u(proof) });
  if (result.status !== 200) return { error: result.json.error };
  record.deviceId = result.json.device_id;
  // Trust on first use: the enrollment pins the Core's identity key, which later
  // authenticates the Core's answers when this browser issues pairing codes.
  record.coreKey = result.json.core_key;
  await saveRecord(record);
  return { deviceId: record.deviceId, publicKey: b64u(record.publicKey) };
}

async function startSession() {
  const record = await loadRecord();
  if (!record || !record.deviceId) return { error: 'no_device' };
  const opened = await openSession(record);
  if (opened.error) return opened;
  session = opened.session;
  return { ok: true };
}

async function echo(payload) {
  const result = await session.post('/api/echo', payload);
  return { status: result.status, error: result.json.error ?? null, deviceId: result.json.device_id ?? null };
}

// Each attack sends one request the Core must refuse, after a valid one where needed.
async function requestAttacks() {
  const outcomes = {};
  const outcome = (result) => ({ status: result.status, error: result.json.error ?? null });

  const valid = await session.post('/api/echo', { n: 1 });
  outcomes.valid = outcome(valid);
  // Replay: the exact bytes and headers of the valid request, sent again.
  outcomes.replay = outcome(await postJson(valid.sent.path, valid.sent.bodyText, valid.sent.headers));
  // A lower counter, freshly signed.
  outcomes.lower_counter = outcome(await session.post('/api/echo', { n: 2 }, { counter: 1 }));
  // Signed over one body, sent with another.
  outcomes.tampered_body = outcome(await session.post('/api/echo', { n: 3 }, { body: JSON.stringify({ n: 4 }) }));
  // Signed for another path.
  outcomes.tampered_path = outcome(await session.post('/api/echo', { n: 5 }, { path: '/api/pending/approve' }));
  // Signed for another method.
  outcomes.tampered_method = outcome(await session.post('/api/echo', { n: 6 }, { method: 'PUT' }));
  // The session id alone, as with a stolen cookie.
  outcomes.session_without_signature = outcome(
    await postJson('/api/echo', JSON.stringify({ n: 7 }), {
      'x-vilicus-session': valid.sent.headers['x-vilicus-session'],
      'x-vilicus-counter': '1000',
    }),
  );
  // The legitimate session still works afterwards.
  outcomes.after = outcome(await session.post('/api/echo', { n: 8 }));
  return outcomes;
}

// Ten signed requests issued at once through the session, which sends them in order.
async function concurrentEchoes(count) {
  const results = await Promise.all(Array.from({ length: count }, (_, n) => session.post('/api/echo', { n })));
  return results.map((r) => r.status);
}

// Control: requests signed with increasing counters but sent last-first, as unserialized
// concurrent requests can arrive. Every request but the first to arrive is refused.
async function outOfOrderEchoes(count) {
  const prepared = [];
  for (let n = 0; n < count; n += 1) {
    const bodyText = JSON.stringify({ n });
    prepared.push({ bodyText, headers: await session.signedHeaders('POST', '/api/echo', bodyText) });
  }
  const statuses = [];
  for (const request of prepared.reverse()) {
    statuses.push((await postJson('/api/echo', request.bodyText, request.headers)).status);
  }
  return statuses;
}

async function challenge(requestId) {
  const result = await session.post('/api/pending/challenge', { request_id: requestId });
  if (result.status !== 200) return { error: result.json.error };
  return { nonce: result.json.nonce, bytes: result.json.bytes };
}

// Signs challenge bytes only after checking they are a confirmation of `requestId` for this
// device; returns the signature (base64url) or the refusal.
async function signConfirmation(requestId, bytes) {
  const record = await loadRecord();
  const raw = unb64u(bytes);
  const verdict = checkConfirmation(raw, unb64u(requestId), unb64u(record.deviceId));
  if (verdict !== 'ok') return { refused: verdict };
  return { signature: b64u(await deviceSign(record, raw)) };
}

async function submit(requestId, nonce, signature) {
  const result = await session.post('/api/pending/approve', { request_id: requestId, nonce, signature });
  return { status: result.status, error: result.json.error ?? null };
}

// The honest path: check, sign, submit.
async function approveWith(requestId, nonce, bytes) {
  const signed = await signConfirmation(requestId, bytes);
  if (signed.refused) return { error: signed.refused };
  return submit(requestId, nonce, signed.signature);
}

// A client that skips its own check, to show what the Core refuses on its own.
async function approveUnchecked(requestId, nonce, bytes) {
  const record = await loadRecord();
  return submit(requestId, nonce, b64u(await deviceSign(record, unb64u(bytes))));
}

// AC3 on three pending requests of this device, A, B and C. Every signature goes through the
// client check; the attacks are on what is submitted.
async function confirmationAttacks(a, b, c) {
  const outcomes = {};
  const chA = await challenge(a);
  const sigA = (await signConfirmation(a, chA.bytes)).signature;
  outcomes.approve_a = await submit(a, chA.nonce, sigA);
  outcomes.replay_a = await submit(a, chA.nonce, sigA);
  outcomes.new_challenge_for_decided_a = await challenge(a);

  const chB = await challenge(b);
  const chC = await challenge(c);
  const sigC = (await signConfirmation(c, chC.bytes)).signature;
  outcomes.signature_of_c_on_b = await submit(b, chB.nonce, sigC);
  outcomes.nonce_of_c_on_b = await submit(b, chC.nonce, sigC);
  outcomes.nonce_of_a_on_b = await submit(b, chA.nonce, sigA);
  // One bit of the expiry flipped: still a well-formed confirmation of B, so the client
  // signs it, and the Core refuses it because it is not the bytes it issued.
  const tampered = unb64u(chB.bytes);
  tampered[tampered.length - 1] ^= 1;
  const tamperedSigned = await signConfirmation(b, b64u(tampered));
  outcomes.tampered_bytes_of_b = tamperedSigned.refused
    ? { error: tamperedSigned.refused }
    : await submit(b, chB.nonce, tamperedSigned.signature);
  outcomes.approve_b = await approveWith(b, chB.nonce, chB.bytes);
  outcomes.approve_c = await submit(c, chC.nonce, sigC);
  outcomes.reused_nonce_of_c = await submit(c, chC.nonce, sigC);
  return outcomes;
}

// The client check on bytes that are not this request's confirmation.
async function guardChecks(requestId, otherRequestId) {
  const ch = await challenge(requestId);
  const valid = unb64u(ch.bytes);
  const value = decodeCanonical(valid);
  const otherKind = new Map(value);
  otherKind.set('kind', 'vilicus/v1/pending-request');
  const digest = crypto.getRandomValues(new Uint8Array(32));
  return {
    valid: (await signConfirmation(requestId, ch.bytes)).refused ?? 'ok',
    request_digest: (await signConfirmation(requestId, b64u(digest))).refused ?? 'signed',
    other_kind: (await signConfirmation(requestId, b64u(encodeCanonical(otherKind)))).refused ?? 'signed',
    other_request: (await signConfirmation(otherRequestId, ch.bytes)).refused ?? 'signed',
    trailing_byte: (await signConfirmation(requestId, b64u(new Uint8Array([...valid, 0])))).refused ?? 'signed',
  };
}

// Probed from the module's own execution: code that a DevTools protocol evaluation runs
// synchronously may bypass the CSP's eval restriction in Chrome.
const loadProbe = probePage();

window.e22 = {
  probe: () => loadProbe,
  enroll,
  inspect: inspectKey,
  startSession,
  echo,
  requestAttacks,
  concurrentEchoes,
  outOfOrderEchoes,
  challenge,
  approveWith,
  approveUnchecked,
  confirmationAttacks,
  guardChecks,
  deviceId: async () => (await loadRecord())?.deviceId ?? null,
};
setStatus('ready');
