// End-to-end check of the PRF probe with Chromium's CDP virtual authenticator (hasPrf).
// Prints one `PASS <name>`, `FAIL <name>` or `INFO <text>` line per item, then `E2E_DONE`.
// Exits non-zero on any failure.
//
// What this proves: the page, the server and webauthn-rs carry PRF digests end to end, the raw
// outputs never leave the page, and the report computes the verdicts. What it cannot prove:
// anything about a real authenticator, which is the point of the household run (RUNBOOK.md).
import { createHash, X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { chromium } from 'playwright';

const ORIGIN = 'https://prf-probe.test:8443';
let failed = false;
let checks = 0;
const pass = (name) => { checks++; console.log(`PASS ${name}`); };
const fail = (name) => { checks++; failed = true; console.log(`FAIL ${name}`); };
const check = (name, ok, detail = '') => (ok ? pass : fail)(detail ? `${name} (${detail})` : name);
const info = (text) => console.log(`INFO ${text}`);
const short = (hex) => (hex ? hex.slice(0, 12) : 'none');

// Chromium refuses WebAuthn on a page with a certificate error, so `ignoreHTTPSErrors` is not
// enough: the server's key is trusted by SPKI pin instead, which Chromium treats as valid.
const serverPem = readFileSync('/data/server.crt', 'utf8');
const spki = new X509Certificate(serverPem).publicKey.export({ type: 'spki', format: 'der' });
const spkiPin = createHash('sha256').update(spki).digest('base64');

// Runs in the page before its own script: wraps the credential calls to keep the raw PRF
// outputs in the page, so the check can compare them with what went over the wire.
function captureRawOutputs() {
  window.__rawPrf = [];
  const hex = (source) => {
    const bytes = source instanceof ArrayBuffer
      ? new Uint8Array(source)
      : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  };
  for (const name of ['create', 'get']) {
    const original = navigator.credentials[name].bind(navigator.credentials);
    navigator.credentials[name] = async (options) => {
      const credential = await original(options);
      const results = (credential.getClientExtensionResults().prf || {}).results;
      if (results) {
        for (const key of ['first', 'second']) if (results[key]) window.__rawPrf.push(hex(results[key]));
      }
      return credential;
    };
  }
}

const browser = await chromium.launch({
  headless: true,
  args: [`--ignore-certificate-errors-spki-list=${spkiPin}`],
});
info(`browser chromium ${browser.version()}`);
const postBodies = [];

async function openSession() {
  const context = await browser.newContext();
  await context.addInitScript(captureRawOutputs);
  const page = await context.newPage();
  page.on('request', (request) => {
    if (request.method() === 'POST') postBodies.push({ url: request.url(), body: request.postData() || '' });
  });
  for (let attempt = 0; ; attempt++) {
    try {
      await page.goto(`${ORIGIN}/`);
      break;
    } catch (error) {
      if (attempt >= 20) throw error;
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
  return { context, page, cdp, authenticatorId };
}

// A later session in the same tab: cookies cleared and the page reloaded, so no page state
// survives; only the virtual authenticator (bound to the tab) keeps the credential.
async function freshLoad(session) {
  await session.context.clearCookies();
  await session.page.goto('about:blank');
  await session.page.goto(`${ORIGIN}/`);
}

const run = (page, fn, arg) => page.evaluate(([f, a]) => window[f](a), [fn, arg]);
const rawOutputs = (page) => page.evaluate(() => window.__rawPrf.slice());
const hasExtension = (record, prefix) => record.authenticator_extensions.some((e) => e.startsWith(prefix));
const sha256Hex = (hex) => createHash('sha256').update(Buffer.from(hex, 'hex')).digest('hex');

async function summaryOf(page, credential) {
  const all = await page.evaluate(() => fetch('/api/summary').then((r) => r.json()));
  return all.find((s) => s.credential === credential);
}

try {
  const a = await openSession();

  // Registration.
  const reg = await run(a.page, 'probeRegister', 'virtual-1');
  const cred = reg.credential;
  check('register.verified_by_webauthn_rs', typeof cred === 'string' && cred.length === 16, cred);
  info(`register: prf_extension_output=${reg.prf_extension_output} prf.enabled=${reg.prf_enabled} outputs=${reg.first_sha256 !== null} authenticator_extensions=${reg.authenticator_extensions.join(',')} aaguid=${reg.aaguid} transports=${reg.transports.join(',')}`);
  check('register.prf_enabled', reg.prf_enabled === true);
  if (reg.first_sha256 !== null) {
    check('register.outputs_32_bytes', reg.first_len === 32 && reg.second_len === 32);
  } else {
    info('register: no outputs at registration (evaluation at creation not supported here)');
  }

  // Two later sessions, each with a fresh page load and a new server session.
  const logins = [];
  for (const n of [1, 2]) {
    await freshLoad(a);
    const login = await run(a.page, 'probeLogin', cred);
    logins.push(login);
    check(`login${n}.verified_by_webauthn_rs`, login.phase === 'login' && login.credential === cred);
    check(`login${n}.outputs_32_bytes`, login.first_len === 32 && login.second_len === 32, `first ${short(login.first_sha256)} second ${short(login.second_sha256)}`);
    info(`login${n}: authenticator_extensions=${login.authenticator_extensions.join(',') || 'none'} (signed hmac-secret output ${hasExtension(login, 'hmac-secret') ? 'present' : 'absent'})`);
  }
  const [l1, l2] = logins;
  check('same_salt_same_digest.first', l1.first_sha256 !== null && l1.first_sha256 === l2.first_sha256);
  check('same_salt_same_digest.second', l1.second_sha256 !== null && l1.second_sha256 === l2.second_sha256);
  if (reg.first_sha256 !== null) {
    check('registration_matches_login', reg.first_sha256 === l1.first_sha256 && reg.second_sha256 === l1.second_sha256);
  }
  check('different_salts_differ', l1.first_sha256 !== l1.second_sha256);

  // The raw outputs stay in the page: what went over the wire are their digests only.
  const raw = await rawOutputs(a.page);
  check('raw_outputs_captured', raw.length === 2 && raw.every((h) => h.length === 64), `${raw.length} in the last session`);
  check('posted_digest_is_sha256_of_output', raw.length === 2 && sha256Hex(raw[0]) === l2.first_sha256 && sha256Hex(raw[1]) === l2.second_sha256);
  const before = (await summaryOf(a.page, cred)).verdict;
  check('report.verdict_after_two_logins', before === 'stable', before);

  // A second credential on the same authenticator has its own secret.
  const reg2 = await run(a.page, 'probeRegister', 'virtual-2');
  await freshLoad(a);
  const other = await run(a.page, 'probeLogin', reg2.credential);
  check('per_credential_secret', other.first_sha256 !== null && other.first_sha256 !== l1.first_sha256, `${short(other.first_sha256)} vs ${short(l1.first_sha256)}`);
  const allRaw = [...raw, ...(await rawOutputs(a.page))];

  // Replaying a finished login is refused: a session is used once.
  const lastFinish = postBodies.filter((p) => p.url.endsWith('/api/login/finish')).at(-1);
  const replay = await a.page.evaluate((body) => fetch('/api/login/finish', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body,
  }).then((r) => r.status), lastFinish.body);
  check('replayed_login_refused', replay === 400, `status ${replay}`);

  // Another browser context, with the credential exported from the first authenticator and
  // imported into a new one. The CDP credential carries the private key, not the PRF secret.
  const { credentials } = await a.cdp.send('WebAuthn.getCredentials', { authenticatorId: a.authenticatorId });
  const exported = credentials.find((c) => c.rpId === 'prf-probe.test' && Buffer.from(c.credentialId, 'base64').length > 0
    && createHash('sha256').update(Buffer.from(c.credentialId, 'base64')).digest('hex').slice(0, 16) === cred);
  info(`CDP credential fields: ${Object.keys(exported).sort().join(',')}`);
  const b = await openSession();
  await b.cdp.send('WebAuthn.addCredential', { authenticatorId: b.authenticatorId, credential: exported });
  const crossContext = await run(b.page, 'probeLogin', cred);
  check('other_context.verified_by_webauthn_rs', crossContext.phase === 'login' && crossContext.credential === cred);
  if (crossContext.first_sha256 !== null) {
    check('other_context.same_digest', crossContext.first_sha256 === l1.first_sha256 && crossContext.second_sha256 === l1.second_sha256);
  } else {
    info(`other context: no PRF outputs (prf_extension_output=${crossContext.prf_extension_output}, authenticator_extensions=${crossContext.authenticator_extensions.join(',') || 'none'}); the virtual authenticator does not carry the PRF secret through a CDP export`);
    const after = (await summaryOf(b.page, cred)).verdict;
    check('report.flags_session_without_outputs', after === 'intermittent', after);
  }
  allRaw.push(...(await rawOutputs(b.page)));

  // No POST body holds any raw output, in hex, base64 or base64url.
  const forms = allRaw.flatMap((hex) => {
    const bytes = Buffer.from(hex, 'hex');
    return [hex, bytes.toString('base64').replace(/=+$/, ''), bytes.toString('base64url')];
  });
  const leaks = postBodies.filter((p) => forms.some((f) => p.body.includes(f)));
  check('no_raw_output_in_any_request', allRaw.length >= 4 && leaks.length === 0, `${allRaw.length} outputs, ${postBodies.length} requests, ${leaks.length} leaks`);

  const report = await a.page.evaluate(() => fetch('/api/report').then((r) => r.text()));
  for (const line of report.trim().split('\n')) info(`report ${line}`);
} catch (error) {
  fail(`e2e_exception (${String(error && error.message ? error.message : error).split('\n')[0]})`);
} finally {
  await browser.close();
}

console.log(`E2E_DONE checks=${checks}`);
process.exit(failed ? 1 : 0);
