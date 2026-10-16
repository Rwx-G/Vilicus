// Spike E22: what both pages share. The device key is a WebCrypto ECDSA P-256 key pair whose
// private half is created non-extractable and kept in IndexedDB as a CryptoKey object, so its
// bytes never reach script. Every API request after enrollment or pairing is signed over the
// AD-21 byte string (see `request_digest` in src/device.rs).

const encoder = new TextEncoder();

export function b64u(bytes) {
  let binary = '';
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}

export function unb64u(text) {
  const binary = atob(text.replaceAll('-', '+').replaceAll('_', '/'));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export function utf8(text) {
  return encoder.encode(text);
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function u32be(value) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value);
  return out;
}

function u64be(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value));
  return out;
}

function withLength(bytes) {
  return concat(u32be(bytes.length), bytes);
}

export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

// --- Device key in IndexedDB ------------------------------------------------------------

const DB_NAME = 'vilicus-e22';
const STORE = 'device';
const RECORD = 'device';

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function withStore(mode, action) {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const request = action(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(request.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export function loadRecord() {
  return withStore('readonly', (store) => store.get(RECORD));
}

export function saveRecord(record) {
  return withStore('readwrite', (store) => store.put(record, RECORD));
}

// Creates the device key pair: the private key is not extractable, its only usage is `sign`.
export async function createDeviceRecord() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const record = { privateKey: pair.privateKey, publicKey, deviceId: null };
  await saveRecord(record);
  return record;
}

export async function deviceSign(record, bytes) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, record.privateKey, bytes));
}

export function popMessage(context, publicKey) {
  return concat(utf8('vilicus/v1/device-pop'), withLength(context), publicKey);
}

// Inspects the stored key and tries every export format on its private half.
export async function inspectKey() {
  const record = await loadRecord();
  if (!record) return { found: false };
  const key = record.privateKey;
  const exportAttempts = {};
  for (const format of ['pkcs8', 'jwk', 'raw']) {
    try {
      await crypto.subtle.exportKey(format, key);
      exportAttempts[format] = 'exported';
    } catch (error) {
      exportAttempts[format] = `refused:${error.name}`;
    }
  }
  return {
    found: true,
    isCryptoKey: key instanceof CryptoKey,
    type: key.type,
    extractable: key.extractable,
    algorithm: key.algorithm.name,
    namedCurve: key.algorithm.namedCurve,
    usages: [...key.usages],
    publicKey: b64u(record.publicKey),
    deviceId: record.deviceId,
    exportAttempts,
  };
}

// --- Requests ---------------------------------------------------------------------------

export async function postJson(path, body, headers = {}) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...headers },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
  return { status: response.status, json: await response.json() };
}

export async function getJson(path) {
  const response = await fetch(path);
  return { status: response.status, json: await response.json() };
}

// The AD-21 byte string, hashed: SHA-256 of the label, the session id, the counter (8 bytes,
// big-endian), the method and the path (each after its 4-byte big-endian length), and
// SHA-256 of the raw body.
export async function requestDigest(sessionId, counter, method, path, body) {
  return sha256(
    concat(
      utf8('vilicus/v1/req'),
      sessionId,
      u64be(counter),
      withLength(utf8(method)),
      withLength(utf8(path)),
      await sha256(body),
    ),
  );
}

// A session bound to the device key: each request carries the session id, a counter that
// strictly increases, and the device signature over the AD-21 byte string.
export class Session {
  constructor(record, sessionId) {
    this.record = record;
    this.sessionId = unb64u(sessionId);
    this.counter = 0;
    this.queue = Promise.resolve();
  }

  // Builds the headers of one signed request. `sign` lets a test sign other bytes than those
  // sent.
  async signedHeaders(method, path, bodyText, sign = {}) {
    this.counter += 1;
    const counter = sign.counter ?? this.counter;
    const digest = await requestDigest(
      this.sessionId,
      counter,
      sign.method ?? method,
      sign.path ?? path,
      utf8(sign.body ?? bodyText),
    );
    return {
      'x-vilicus-session': b64u(this.sessionId),
      'x-vilicus-counter': String(counter),
      'x-vilicus-signature': b64u(await deviceSign(this.record, digest)),
    };
  }

  // Signed requests of one session are sent one at a time: the Core accepts a counter only
  // above the last accepted one, so two requests in flight could arrive out of order and the
  // later counter would refuse the earlier one.
  post(path, body, sign = {}) {
    const run = this.queue.then(async () => {
      const bodyText = JSON.stringify(body);
      const headers = await this.signedHeaders('POST', path, bodyText, sign);
      const result = await postJson(path, bodyText, headers);
      return { ...result, sent: { path, bodyText, headers } };
    });
    this.queue = run.catch(() => {});
    return run;
  }
}

// Opens a new session for a registered device by signing a fresh challenge.
export async function openSession(record) {
  const challenge = await postJson('/api/session/challenge', { device_id: record.deviceId });
  if (challenge.status !== 200) return { error: challenge.json.error };
  const nonce = unb64u(challenge.json.nonce);
  const message = concat(utf8('vilicus/v1/session'), unb64u(record.deviceId), nonce);
  const opened = await postJson('/api/session/open', {
    device_id: record.deviceId,
    nonce: challenge.json.nonce,
    signature: b64u(await deviceSign(record, message)),
  });
  if (opened.status !== 200) return { error: opened.json.error };
  return { session: new Session(record, opened.json.session_id) };
}

// --- CSP probes -------------------------------------------------------------------------

// Checks that the page runs in a secure context and that its CSP is enforced: WebAssembly
// compilation, string evaluation and an HTML string sink under Trusted Types.
export async function probePage() {
  const result = { secureContext: window.isSecureContext, userAgent: navigator.userAgent };
  try {
    await WebAssembly.compile(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    result.wasm = 'allowed';
  } catch (error) {
    result.wasm = `blocked:${error.name}`;
  }
  try {
    (0, eval)('1');
    result.eval = 'allowed';
  } catch (error) {
    result.eval = `blocked:${error.name}`;
  }
  try {
    document.createElement('div').innerHTML = '<b>x</b>';
    result.trustedTypes = 'not_enforced';
  } catch (error) {
    result.trustedTypes = `enforced:${error.name}`;
  }
  result.trustedTypesApi = typeof window.trustedTypes !== 'undefined';
  // `trusted-types lit-html` allows one policy name; any other name must be refused.
  if (result.trustedTypesApi) {
    try {
      window.trustedTypes.createPolicy('e22-unlisted', { createHTML: (text) => text });
      result.unlistedPolicy = 'created';
    } catch (error) {
      result.unlistedPolicy = `refused:${error.name}`;
    }
  }
  return result;
}

export function setStatus(text) {
  document.getElementById('status').textContent = text;
}

// Verifies an ECDSA P-256 SHA-256 signature (`r || s`) with a raw uncompressed public key.
export async function verifyEcdsa(publicKey, data, signature) {
  const key = await crypto.subtle.importKey('raw', publicKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'verify',
  ]);
  return crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, signature, data);
}

export function sameBytes(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array && a.length === b.length && a.every((v, i) => v === b[i]);
}
