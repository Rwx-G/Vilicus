// Drives one browser through registration, login and the step-up checks of story 1.5 against
// the spike server, with a virtual authenticator, and prints one `PASS <label>.<check>` or
// `FAIL <label>.<check>` line per check. Exits non-zero on any failure.
//
// Usage: node driver.mjs <chromium|firefox> <label> <origin> <ca.pem> <server-expiry-ms>
//
// The test CA is added to the browser's NSS trust store, so the page is a real secure context
// with a valid certificate: no certificate error is ignored. The virtual authenticator is CDP
// `WebAuthn.addVirtualAuthenticator` on Chromium and the WebDriver WebAuthn extension command
// (`WebAuthn:AddVirtualAuthenticator`) over Marionette on Firefox; the driver reads its
// credentials back (`WebAuthn.getCredentials`, `WebAuthn:GetCredentials`) to show the browser
// used that authenticator. Neither is a real authenticator: they prove the browser's WebAuthn
// client and the server, not a platform one.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync } from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { chromium, firefox } from 'playwright';

const [engineName, label, origin, caFile, expiryText] = process.argv.slice(2);
const serverExpiryMs = Number(expiryText);
if (!['chromium', 'firefox'].includes(engineName) || !label || !origin || !caFile || !(serverExpiryMs > 0)) {
  console.error('usage: node driver.mjs <chromium|firefox> <label> <origin> <ca.pem> <server-expiry-ms>');
  process.exit(2);
}

const CHECKS = [
  'secure_context',
  'foreign_rp_id_refused',
  'register',
  'authenticator_holds_credential',
  'login',
  'step_up_challenge_derived',
  'step_up_approved',
  'sign_count_advances',
  'approved_request_matches',
  'other_request_refused',
  'other_hash_refused',
  'other_request_own_assertion_approved',
  'replay_refused',
  'expired_refused',
  'user_verification_required',
  'other_session_refused',
  'other_session_same_action_refused',
];
const SESSION_COOKIE = '__Host-vilicus_sid';
const SESSION_HANDLE_LABEL = 'vilicus/v1/session-handle';
const STEP_UP_LABEL = 'vilicus/v1/step-up';
const MARIONETTE_PORT = 2828;
const results = new Map();

function record(check, ok, detail = '') {
  if (!CHECKS.includes(check)) throw new Error(`unknown check ${check}`);
  results.set(check, ok);
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}.${check}${detail ? ` (${detail})` : ''}`);
}

function expectRefusal(check, result, status, code) {
  const ok = result.status === status && result.body && result.body.error === code;
  record(check, ok, ok ? `HTTP ${status} ${code}` : `expected HTTP ${status} ${code}, got ${JSON.stringify(result)}`);
}

function trustCa(nssDir) {
  mkdirSync(nssDir, { recursive: true });
  execFileSync('certutil', ['-N', '--empty-password', '-d', `sql:${nssDir}`]);
  execFileSync('certutil', ['-A', '-n', 'vilicus-e2-test-ca', '-t', 'C,,', '-i', caFile, '-d', `sql:${nssDir}`]);
}

// Minimal Marionette client: length-prefixed JSON frames `[0, id, command, params]`.
function marionette(port) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1');
    let buffer = Buffer.alloc(0);
    let nextId = 0;
    let greeted = false;
    const waiting = new Map();
    const send = (command, params) => new Promise((res, rej) => {
      const id = ++nextId;
      const frame = JSON.stringify([0, id, command, params]);
      const timer = setTimeout(() => rej(new Error(`marionette ${command} timed out`)), 15000);
      waiting.set(id, (message) => { clearTimeout(timer); res(message); });
      socket.write(`${Buffer.byteLength(frame)}:${frame}`);
    });
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        const colon = buffer.indexOf(':');
        if (colon < 0) return;
        const length = Number(buffer.subarray(0, colon).toString());
        if (buffer.length < colon + 1 + length) return;
        const message = JSON.parse(buffer.subarray(colon + 1, colon + 1 + length).toString());
        buffer = buffer.subarray(colon + 1 + length);
        if (!greeted) {
          greeted = true;
          resolve({ send, close: () => socket.end() });
          continue;
        }
        const handler = waiting.get(message[1]);
        waiting.delete(message[1]);
        if (handler) handler(message);
      }
    });
    socket.on('error', reject);
  });
}

async function connectMarionette() {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      return await marionette(MARIONETTE_PORT);
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  throw new Error('marionette did not start');
}


const AUTHENTICATOR = {
  protocol: 'ctap2',
  transport: 'internal',
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
};

const toB64url = (text) => text.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

async function openChromium() {
  trustCa(path.join(os.homedir(), '.pki', 'nssdb'));
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { ...AUTHENTICATOR, automaticPresenceSimulation: true },
  });
  return {
    version: browser.version(),
    context,
    page,
    credentials: async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials
      .map((c) => ({ id: toB64url(c.credentialId), signCount: c.signCount })),
    setUserVerified: (isUserVerified) => cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified }),
    close: () => browser.close(),
  };
}

async function openFirefox() {
  const profile = mkdtempSync(path.join(os.tmpdir(), 'vilicus-e2-firefox-'));
  trustCa(profile);
  const context = await firefox.launchPersistentContext(profile, {
    headless: true,
    args: ['-marionette'],
    // The soft token pref routes WebAuthn to the test token manager that holds the virtual
    // authenticator; without it Firefox looks for a USB or platform authenticator.
    firefoxUserPrefs: {
      'marionette.port': MARIONETTE_PORT,
      'security.webauth.webauthn_enable_softtoken': true,
      'security.webauth.webauthn_enable_usbtoken': false,
    },
  });
  const page = context.pages()[0] || (await context.newPage());
  const driver = await connectMarionette();
  const command = async (name, params) => {
    const reply = await driver.send(name, params);
    if (reply[2]) throw new Error(`${name}: ${JSON.stringify(reply[2])}`);
    return reply[3];
  };
  const session = await command('WebDriver:NewSession', { capabilities: { alwaysMatch: {} } });
  const authenticatorId = (await command('WebAuthn:AddVirtualAuthenticator', AUTHENTICATOR)).value;
  return {
    version: session.capabilities.browserVersion,
    context,
    page,
    credentials: async () => (await command('WebAuthn:GetCredentials', { authenticatorId })).value
      .map((c) => ({ id: toB64url(c.credentialId), signCount: c.signCount })),
    setUserVerified: (isUserVerified) => command('WebAuthn:SetUserVerified', { authenticatorId, isUserVerified }),
    close: async () => { driver.close(); await context.close(); },
  };
}

async function sessionId(context) {
  const cookie = (await context.cookies(origin)).find((c) => c.name === SESSION_COOKIE);
  return cookie ? cookie.value : null;
}

function expectedChallenge(sessionHex, requestHashHex) {
  const handle = createHash('sha256')
    .update(Buffer.from(SESSION_HANDLE_LABEL))
    .update(Buffer.from(sessionHex, 'hex'))
    .digest();
  return createHash('sha256')
    .update(Buffer.from(STEP_UP_LABEL))
    .update(handle)
    .update(Buffer.from(requestHashHex, 'hex'))
    .digest('base64url');
}

const action = (detail) => ({ kind: 'member.suspend', target: 'member-2', detail });

async function run(browser) {
  const { page, context } = browser;
  const call = (fn, ...args) => page.evaluate(([name, values]) => window.vilicus[name](...values), [fn, args]);
  const startStepUp = async (detail) => {
    const started = await call('startStepUp', action(detail));
    if (started.status !== 200) throw new Error(`step-up start: ${JSON.stringify(started)}`);
    return started;
  };
  const username = `owner-${label}`.replace(/[^A-Za-z0-9-]/g, '-');

  await page.goto(`${origin}/`);
  const secure = await page.evaluate(() => window.isSecureContext && typeof PublicKeyCredential === 'function');
  const protocol = await page.evaluate(() => location.protocol);
  record('secure_context', secure && protocol === 'https:', `isSecureContext=${secure}, ${protocol}`);

  // The browser itself must refuse an RP ID that is not this origin's host.
  const foreign = await page.evaluate(async () => {
    try {
      await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), rpId: 'attacker.example', timeout: 5000 } });
      return 'resolved';
    } catch (error) {
      return error.name;
    }
  });
  record('foreign_rp_id_refused', foreign === 'SecurityError', foreign);

  const registered = await call('register', username).then((r) => r, (e) => ({ error: String(e) }));
  record('register', registered.registered === username, JSON.stringify(registered));
  const held = await browser.credentials();
  record('authenticator_holds_credential', held.length === 1 && held[0].id === registered.credentialId,
    `authenticator ${JSON.stringify(held)}, registered ${registered.credentialId}`);

  const loggedIn = await call('login', username).then((r) => r, (e) => ({ error: String(e) }));
  const sessionUser = (await call('session')).user;
  record('login', loggedIn.user === username && sessionUser === username, JSON.stringify(loggedIn));
  const countAfterLogin = (await browser.credentials())[0].signCount;

  // One request, its assertion, and the challenge the browser actually signed.
  const first = await startStepUp('first');
  const firstAssertion = await call('assert', first.body.options);
  const canonicalHash = createHash('sha256').update(Buffer.from(first.body.canonical_request, 'hex')).digest('hex');
  const derived = expectedChallenge(await sessionId(context), first.body.request_hash);
  record(
    'step_up_challenge_derived',
    canonicalHash === first.body.request_hash && firstAssertion.signedChallenge === derived,
    `signed=${firstAssertion.signedChallenge}`,
  );
  const approved = await call('finishStepUp', first.body.request_id, first.body.request_hash, firstAssertion.credential);
  record('step_up_approved', approved.status === 200 && approved.body.approved === first.body.request_id, JSON.stringify(approved.body));
  const countAfterStepUp = (await browser.credentials())[0].signCount;
  record('sign_count_advances', countAfterStepUp > countAfterLogin && countAfterLogin > 0,
    `after login ${countAfterLogin}, after step-up ${countAfterStepUp}`);
  record('approved_request_matches', approved.body.canonical_request === first.body.canonical_request,
    'approved canonical bytes equal the started request');

  // An assertion made for request A, presented for request B, and for A with B's hash.
  const requestA = await startStepUp('a');
  const requestB = await startStepUp('b');
  const assertionA = await call('assert', requestA.body.options);
  expectRefusal('other_request_refused',
    await call('finishStepUp', requestB.body.request_id, requestB.body.request_hash, assertionA.credential), 403, 'challenge_mismatch');
  expectRefusal('other_hash_refused',
    await call('finishStepUp', requestA.body.request_id, requestB.body.request_hash, assertionA.credential), 403, 'action_mismatch');
  const assertionB = await call('assert', requestB.body.options);
  const approvedB = await call('finishStepUp', requestB.body.request_id, requestB.body.request_hash, assertionB.credential);
  record('other_request_own_assertion_approved', approvedB.status === 200, JSON.stringify(approvedB.body));

  expectRefusal('replay_refused',
    await call('finishStepUp', first.body.request_id, first.body.request_hash, firstAssertion.credential), 409, 'already_used');

  const late = await startStepUp('late');
  const lateAssertion = await call('assert', late.body.options);
  await new Promise((r) => setTimeout(r, serverExpiryMs + 500));
  expectRefusal('expired_refused',
    await call('finishStepUp', late.body.request_id, late.body.request_hash, lateAssertion.credential), 410, 'expired');

  // An authenticator that cannot verify the user: the browser refuses to return an assertion
  // for `userVerification: required`, or the server refuses the one it gets.
  await browser.setUserVerified(false);
  const unverified = await startStepUp('unverified');
  const uvOutcome = await call('assert', unverified.body.options).then(
    async (assertion) => {
      const result = await call('finishStepUp', unverified.body.request_id, unverified.body.request_hash, assertion.credential);
      return result.status === 403 && result.body.error === 'assertion_rejected' ? 'server refused' : `server ${JSON.stringify(result)}`;
    },
    (error) => (String(error).includes('NotAllowedError') || String(error).includes('not allowed') ? 'browser refused' : `browser ${error}`),
  );
  await browser.setUserVerified(true);
  record('user_verification_required', uvOutcome === 'server refused' || uvOutcome === 'browser refused', uvOutcome);

  // An assertion made in this session, presented after logging in again (a new session).
  const crossing = await startStepUp('crossing');
  const crossingAssertion = await call('assert', crossing.body.options);
  const before = await sessionId(context);
  await call('login', username);
  const after = await sessionId(context);
  if (!before || before === after) throw new Error('login did not issue a new session');
  expectRefusal('other_session_refused',
    await call('finishStepUp', crossing.body.request_id, crossing.body.request_hash, crossingAssertion.credential), 404, 'unknown_request');
  const sameAction = await startStepUp('crossing');
  expectRefusal('other_session_same_action_refused',
    await call('finishStepUp', sameAction.body.request_id, sameAction.body.request_hash, crossingAssertion.credential), 403, 'challenge_mismatch');
}


let browser;
try {
  browser = engineName === 'chromium' ? await openChromium() : await openFirefox();
  const userAgent = await browser.page.evaluate(() => navigator.userAgent);
  console.log(`INFO ${label} engine=${engineName} version=${browser.version} ua="${userAgent}"`);
  await run(browser);
} catch (error) {
  console.log(`ERROR ${label} ${error && error.stack ? error.stack.split('\n').slice(0, 3).join(' | ') : error}`);
} finally {
  if (browser) await browser.close().catch(() => {});
}

let failed = false;
for (const check of CHECKS) {
  if (!results.has(check)) {
    console.log(`FAIL ${label}.${check} (not run)`);
    failed = true;
  } else if (!results.get(check)) {
    failed = true;
  }
}
process.exit(failed ? 1 : 0);
