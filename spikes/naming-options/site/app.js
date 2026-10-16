// Browser half of the E24 spike. The test driver calls these functions; each returns a plain
// object with an `ok` flag and the browser's own error name and message when it refuses.
'use strict';

const toBytes = (b64url) => {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const toB64url = (buffer) => {
  let bin = '';
  for (const byte of new Uint8Array(buffer)) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
const failure = (stage, err) => ({ ok: false, stage, name: err && err.name, message: String(err && err.message) });
const CEREMONY_TIMEOUT_MS = 10000;

async function api(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  const json = await response.json();
  if (!response.ok) {
    throw Object.assign(new Error(json.error || `HTTP ${response.status}`), { name: `HTTP${response.status}` });
  }
  return json;
}

async function rpIdHashMatches(authenticatorData, rpId) {
  const expected = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
  const actual = new Uint8Array(authenticatorData).slice(0, 32);
  return expected.every((byte, i) => byte === actual[i]);
}

async function register(user) {
  let options;
  try {
    options = (await api('/api/register/start', { user })).publicKey;
  } catch (err) { return failure('server-start', err); }
  options.challenge = toBytes(options.challenge);
  options.user.id = toBytes(options.user.id);
  (options.excludeCredentials || []).forEach((c) => { c.id = toBytes(c.id); });
  options.timeout = CEREMONY_TIMEOUT_MS;
  let credential;
  try {
    credential = await navigator.credentials.create({ publicKey: options });
  } catch (err) { return failure('browser-create', err); }
  try {
    const result = await api('/api/register/finish', { user, credential: {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toB64url(credential.response.attestationObject),
        clientDataJSON: toB64url(credential.response.clientDataJSON),
      },
      extensions: {},
    } });
    return { ok: true, rpId: result.rp_id, credentialId: result.credential_id };
  } catch (err) { return failure('server-finish', err); }
}

async function login(user) {
  let options;
  try {
    options = (await api('/api/login/start', { user })).publicKey;
  } catch (err) { return failure('server-start', err); }
  options.challenge = toBytes(options.challenge);
  (options.allowCredentials || []).forEach((c) => { c.id = toBytes(c.id); });
  options.timeout = CEREMONY_TIMEOUT_MS;
  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: options });
  } catch (err) { return failure('browser-get', err); }
  try {
    const result = await api('/api/login/finish', { user, credential: {
      id: assertion.id,
      rawId: toB64url(assertion.rawId),
      type: assertion.type,
      response: {
        authenticatorData: toB64url(assertion.response.authenticatorData),
        clientDataJSON: toB64url(assertion.response.clientDataJSON),
        signature: toB64url(assertion.response.signature),
        userHandle: assertion.response.userHandle ? toB64url(assertion.response.userHandle) : null,
      },
      extensions: {},
    } });
    return { ok: true, rpId: result.rp_id, credentialId: result.credential_id, userVerified: result.user_verified };
  } catch (err) { return failure('server-finish', err); }
}

// A creation ceremony with client-side options only, the RP ID left to its default (the page's
// host). Used where the server cannot be a relying party (IP addresses) and over the temporary
// self-signed certificate: what is observed is whether the browser runs the ceremony at all.
// With `abortAfterMs`, a ceremony still waiting for an authenticator is cancelled then, so no
// request is left pending in the browser.
async function probeCreate(timeoutMs = CEREMONY_TIMEOUT_MS, abortAfterMs = 0) {
  const host = location.hostname;
  try {
    const credential = await navigator.credentials.create({
      ...(abortAfterMs ? { signal: AbortSignal.timeout(abortAfterMs) } : {}),
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: 'Vilicus E24 probe' },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'member01', displayName: 'Member 01' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
        timeout: timeoutMs,
      },
    });
    return {
      ok: true,
      host,
      credentialId: credential.id,
      boundToHost: await rpIdHashMatches(credential.response.getAuthenticatorData(), host),
    };
  } catch (err) { return { host, ...failure('browser-create', err) }; }
}

// An assertion for one credential ID, or a list of them, with an optional explicit RP ID.
async function probeGet(credentialIds, rpId) {
  const publicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    allowCredentials: [].concat(credentialIds).map((id) => ({ type: 'public-key', id: toBytes(id) })),
    userVerification: 'preferred',
    timeout: 5000,
  };
  if (rpId) publicKey.rpId = rpId;
  try {
    const assertion = await navigator.credentials.get({ publicKey });
    return { ok: true, credentialId: assertion.id };
  } catch (err) { return failure('browser-get', err); }
}

// Two credentials of this browser's authenticator for this host, then assertions whose allow
// lists name one, both, the matching one then an unknown one, and the reverse. A member with
// passkeys on several authenticators is listed this way.
async function probeAllowLists() {
  const first = await probeCreate();
  const second = await probeCreate();
  if (!first.ok || !second.ok) return { ok: false, stage: 'create', first, second };
  const unknown = toB64url(crypto.getRandomValues(new Uint8Array(32)));
  const timed = async (ids) => {
    const started = performance.now();
    const result = await probeGet(ids);
    return { ...result, ms: Math.round(performance.now() - started) };
  };
  return {
    ok: true,
    single: await timed(first.credentialId),
    ownBoth: await timed([first.credentialId, second.credentialId]),
    matchingFirst: await timed([first.credentialId, unknown]),
    matchingSecond: await timed([unknown, first.credentialId]),
  };
}

// Installability signals a browser can report from the page itself.
async function pwa() {
  const result = { secureContext: window.isSecureContext, serviceWorker: false, manifest: false };
  try {
    const href = document.querySelector('link[rel="manifest"]').href;
    const response = await fetch(href);
    const manifest = await response.json();
    result.manifest = response.ok && Boolean(manifest.name && manifest.icons && manifest.icons.length && manifest.display);
  } catch (err) { result.manifestError = String(err); }
  try {
    if (!('serviceWorker' in navigator)) throw new Error('navigator.serviceWorker is missing');
    await navigator.serviceWorker.register('/sw.js');
    const ready = await Promise.race([
      navigator.serviceWorker.ready,
      new Promise((_, reject) => setTimeout(() => reject(new Error('service worker not ready after 10 s')), 10000)),
    ]);
    result.serviceWorker = Boolean(ready.active);
  } catch (err) { result.serviceWorkerError = `${err.name}: ${err.message}`; }
  result.ok = result.secureContext && result.manifest && result.serviceWorker;
  return result;
}

window.e24 = { register, login, probeCreate, probeGet, probeAllowLists, pwa };
