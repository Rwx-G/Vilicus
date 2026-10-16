'use strict';

// The two PRF inputs: SHA-256 of fixed labels, so every device and run uses the same salts.
const SALT_LABELS = ['vilicus/prf-probe/v1/salt-a', 'vilicus/prf-probe/v1/salt-b'];

function b64uToBytes(text) {
  const b64 = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function toBytes(source) {
  if (source instanceof ArrayBuffer) return new Uint8Array(source);
  return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
}

function bytesToB64u(source) {
  const bytes = toBytes(source);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

function salts() {
  const encoder = new TextEncoder();
  return Promise.all(SALT_LABELS.map((l) => crypto.subtle.digest('SHA-256', encoder.encode(l))));
}

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || String(response.status));
  return value;
}

// Digests and lengths of the PRF outputs. The outputs themselves go out of scope here.
async function prfReport(extensions, transports) {
  const prf = extensions.prf;
  const results = prf && prf.results;
  const first = results && results.first ? toBytes(results.first) : null;
  const second = results && results.second ? toBytes(results.second) : null;
  return {
    prf_extension_output: prf !== undefined,
    prf_enabled: prf && typeof prf.enabled === 'boolean' ? prf.enabled : null,
    first_sha256: first ? await sha256Hex(first) : null,
    first_len: first ? first.byteLength : null,
    second_sha256: second ? await sha256Hex(second) : null,
    second_len: second ? second.byteLength : null,
    transports: transports.slice(0, 16),
    user_agent: navigator.userAgent.slice(0, 512),
    client_extension_keys: Object.keys(extensions).slice(0, 16),
  };
}

async function prfInputs() {
  const [first, second] = await salts();
  return { prf: { eval: { first, second } } };
}

async function probeRegister(label) {
  const started = await post('/api/register/start', { label });
  const options = started.options.publicKey;
  options.challenge = b64uToBytes(options.challenge);
  options.user.id = b64uToBytes(options.user.id);
  if (options.excludeCredentials) {
    options.excludeCredentials = options.excludeCredentials.map((c) => ({ type: c.type, id: b64uToBytes(c.id) }));
  }
  // A discoverable credential, as a Vilicus passkey is; webauthn-rs 0.5.5 does not ask for one.
  options.authenticatorSelection = Object.assign({}, options.authenticatorSelection, {
    residentKey: 'required',
    requireResidentKey: true,
  });
  options.extensions = Object.assign({}, options.extensions, await prfInputs());
  const credential = await navigator.credentials.create({ publicKey: options });
  const transports =
    typeof credential.response.getTransports === 'function' ? credential.response.getTransports() : [];
  const probe = await prfReport(credential.getClientExtensionResults(), transports);
  return post('/api/register/finish', {
    session: started.session,
    credential: {
      id: credential.id,
      rawId: bytesToB64u(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bytesToB64u(credential.response.attestationObject),
        clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
      },
      extensions: {},
    },
    probe,
  });
}

async function probeLogin(credentialKey) {
  const started = await post('/api/login/start', { credential: credentialKey });
  const options = started.options.publicKey;
  options.challenge = b64uToBytes(options.challenge);
  options.allowCredentials = (options.allowCredentials || []).map((c) => ({ type: c.type, id: b64uToBytes(c.id) }));
  options.extensions = Object.assign({}, options.extensions, await prfInputs());
  const credential = await navigator.credentials.get({ publicKey: options });
  const probe = await prfReport(credential.getClientExtensionResults(), []);
  const response = credential.response;
  return post('/api/login/finish', {
    session: started.session,
    credential: {
      id: credential.id,
      rawId: bytesToB64u(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bytesToB64u(response.authenticatorData),
        clientDataJSON: bytesToB64u(response.clientDataJSON),
        signature: bytesToB64u(response.signature),
        userHandle: response.userHandle ? bytesToB64u(response.userHandle) : null,
      },
      extensions: {},
    },
    probe,
  });
}

function show(value) {
  document.getElementById('output').textContent =
    value instanceof Error ? 'Error: ' + value.message : JSON.stringify(value, null, 2);
}

async function refreshCredentials() {
  const list = document.getElementById('credentials');
  const entries = await (await fetch('/api/credentials')).json();
  list.replaceChildren();
  for (const entry of entries) {
    const item = document.createElement('li');
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Log in';
    button.addEventListener('click', () => probeLogin(entry.credential).then(show, show));
    item.append(button, ' ' + entry.label + ' (' + entry.credential + ')');
    list.append(item);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('register').addEventListener('click', () => {
    probeRegister(document.getElementById('label').value)
      .then((record) => {
        show(record);
        return refreshCredentials();
      })
      .catch(show);
  });
  document.getElementById('refresh').addEventListener('click', () => refreshCredentials().catch(show));
  refreshCredentials().catch(show);
});
