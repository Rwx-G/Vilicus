// Page logic for the E2 spike. The functions on `window.vilicus` are what the browser driver
// calls; the buttons run the same functions for the manual procedure on real devices.
'use strict';

const vilicus = (() => {
  const toBytes = (b64url) => {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  };
  const toB64url = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let text = '';
    for (const byte of bytes) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  async function api(path, body) {
    const init = body === undefined
      ? { method: 'GET', credentials: 'same-origin' }
      : {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        };
    const response = await fetch(path, init);
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { json = { raw: text }; }
    return { status: response.status, body: json };
  }

  function creationOptions(json) {
    const options = structuredClone(json.publicKey);
    options.challenge = toBytes(options.challenge);
    options.user.id = toBytes(options.user.id);
    options.excludeCredentials = (options.excludeCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
    return options;
  }

  function requestOptions(json) {
    const options = structuredClone(json.publicKey);
    options.challenge = toBytes(options.challenge);
    options.allowCredentials = (options.allowCredentials || []).map((c) => ({ ...c, id: toBytes(c.id) }));
    return options;
  }

  function registrationJson(credential) {
    const response = credential.response;
    return {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: toB64url(response.attestationObject),
        clientDataJSON: toB64url(response.clientDataJSON),
        transports: typeof response.getTransports === 'function' ? response.getTransports() : undefined,
      },
      extensions: credential.getClientExtensionResults(),
    };
  }

  function assertionJson(credential) {
    const response = credential.response;
    return {
      id: credential.id,
      rawId: toB64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: toB64url(response.authenticatorData),
        clientDataJSON: toB64url(response.clientDataJSON),
        signature: toB64url(response.signature),
        userHandle: response.userHandle ? toB64url(response.userHandle) : null,
      },
      extensions: credential.getClientExtensionResults(),
    };
  }

  function expectOk(step, result) {
    if (result.status !== 200) {
      throw new Error(`${step}: HTTP ${result.status} ${JSON.stringify(result.body)}`);
    }
    return result.body;
  }

  async function register(username) {
    const options = expectOk('register/start', await api('/api/register/start', { username }));
    const credential = await navigator.credentials.create({ publicKey: creationOptions(options) });
    const result = expectOk('register/finish', await api('/api/register/finish', registrationJson(credential)));
    return { ...result, credentialId: credential.id };
  }

  async function login(username) {
    const options = expectOk('login/start', await api('/api/login/start', { username }));
    const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
    return expectOk('login/finish', await api('/api/login/finish', assertionJson(credential)));
  }

  // Creates a pending request on the server; the returned options carry the derived challenge.
  async function startStepUp(action) {
    return api('/api/step-up/start', action);
  }

  // Runs the assertion only, so the driver can present it for another request or replay it.
  async function assert(options) {
    const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
    const json = assertionJson(credential);
    const clientData = JSON.parse(new TextDecoder().decode(toBytes(json.response.clientDataJSON)));
    return { credential: json, signedChallenge: clientData.challenge };
  }

  async function finishStepUp(requestId, requestHash, credential) {
    return api('/api/step-up/finish', { request_id: requestId, request_hash: requestHash, credential });
  }

  async function session() {
    return (await api('/api/session')).body;
  }

  return { api, register, login, startStepUp, assert, finishStepUp, session, toB64url, toBytes };
})();
window.vilicus = vilicus;

document.addEventListener('DOMContentLoaded', () => {
  const status = document.getElementById('status');
  const username = () => document.getElementById('username').value;
  const show = (value) => { status.textContent = typeof value === 'string' ? value : JSON.stringify(value, null, 2); };
  const run = (action) => async () => {
    try { show(await action()); } catch (error) { show(`${error.name}: ${error.message}`); }
  };
  document.getElementById('register').addEventListener('click', run(() => vilicus.register(username())));
  document.getElementById('login').addEventListener('click', run(() => vilicus.login(username())));
  document.getElementById('step-up').addEventListener('click', run(async () => {
    const start = await vilicus.startStepUp({ kind: 'member.suspend', target: 'member-2', detail: 'manual check' });
    if (start.status !== 200) return start;
    const { credential } = await vilicus.assert(start.body.options);
    return vilicus.finishStepUp(start.body.request_id, start.body.request_hash, credential);
  }));
});
