// Spike E22 browser driver: runs AC1 to AC3 in one browser against the server of the compose
// network and prints one `PASS <browser>.<check>` or `FAIL <browser>.<check>` line per check,
// `INFO` lines with the evidence, and exits non-zero on any failure.
//
// Usage: node driver.mjs <label> <chromium|firefox> <executable>
// Chrome for Testing builds are driven over CDP; stock Firefox builds over WebDriver BiDi (the
// `moz-firefox` channel of Playwright), so neither is a Playwright-patched browser. Both run
// headless. Each "browser" of the story (the enrolled one, a new one, another new one, one
// behind the relay) is a separate persistent profile; closing and relaunching a profile is a
// browser restart.
//
// Certificates are validated: the test CA is added to the NSS database Chrome reads, and
// Firefox installs it from its enterprise policy (browser/firefox-policies.json). A name
// whose certificate comes from another CA must fail to load.

import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, firefox } from 'playwright-core';

const [label, kind, executablePath] = process.argv.slice(2);
if (!label || !['chromium', 'firefox'].includes(kind) || !executablePath) {
  console.error('usage: node driver.mjs <label> <chromium|firefox> <executable>');
  process.exit(2);
}

const CORE = 'https://core.vilicus.test:8443';
const RELAY = 'https://relay.vilicus.test:8443';
const ROGUE = 'https://rogue.vilicus.test:8443';
const CODE_PATTERN = /^[0-9]{3}-[0-9]{4}-[0-9]{4}$/;

let failed = false;
function check(name, ok, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}.${name}${ok ? '' : ` ${JSON.stringify(detail)}`}`);
  if (!ok) failed = true;
}
function info(name, detail) {
  console.log(`INFO ${label}.${name} ${typeof detail === 'string' ? detail : JSON.stringify(detail)}`);
}

// The harness stands for the host CLI and the assistant; Node trusts the test CA through
// NODE_EXTRA_CA_CERTS.
async function harness(base, path, body) {
  const response = await fetch(base + path, {
    method: body === undefined ? 'GET' : 'POST',
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, ...(await response.json()) };
}

if (kind === 'chromium') {
  const nssdb = `sql:${join(homedir(), '.pki', 'nssdb')}`;
  mkdirSync(join(homedir(), '.pki', 'nssdb'), { recursive: true });
  execFileSync('certutil', ['-d', nssdb, '-N', '--empty-password']);
  execFileSync('certutil', ['-d', nssdb, '-A', '-t', 'C,,', '-n', 'vilicus-e22-test-ca', '-i', '/pki/ca.pem']);
}

const engine = kind === 'chromium' ? chromium : firefox;
const launchOptions = {
  executablePath,
  headless: true,
  ...(kind === 'firefox' ? { channel: 'moz-firefox' } : {}),
};

const profiles = {};
function profile(name) {
  profiles[name] ??= mkdtempSync(join(tmpdir(), `e22-${name}-`));
  return profiles[name];
}

async function launch(name) {
  return engine.launchPersistentContext(profile(name), launchOptions);
}

async function open(context, url, api) {
  const page = context.pages()[0] ?? (await context.newPage());
  const response = await page.goto(url);
  await page.waitForFunction((name) => Boolean(window[name]), api);
  return { page, response };
}

const call = (page, expression, arg) => page.evaluate(expression, arg);
const refusedAll = (attempts) => Object.values(attempts).every((value) => value.startsWith('refused:'));

async function main() {
  // ---- TLS and CSP ---------------------------------------------------------------------------
  let browser1 = await launch('enrolled');
  let { page, response } = await open(browser1, `${CORE}/`, 'e22');
  const appCsp = response.headers()['content-security-policy'] ?? '';
  info('app_page_csp', appCsp);
  check(
    'csp.app_page_header',
    appCsp.includes("require-trusted-types-for 'script'") && !appCsp.includes('wasm-unsafe-eval'),
    appCsp,
  );
  const appProbe = await call(page, () => window.e22.probe());
  info('user_agent', appProbe.userAgent);
  info('app_page_probe', appProbe);
  check('https.core_name_loads_with_certificate_validation', appProbe.secureContext === true, appProbe);
  check('csp.app_page_blocks_wasm', appProbe.wasm.startsWith('blocked:'), appProbe);
  check('csp.app_page_blocks_eval', appProbe.eval.startsWith('blocked:'), appProbe);
  check('csp.app_page_enforces_trusted_types', appProbe.trustedTypes.startsWith('enforced:'), appProbe);
  check('csp.app_page_refuses_unlisted_policy', (appProbe.unlistedPolicy ?? '').startsWith('refused:'), appProbe);

  const roguePage = await browser1.newPage();
  let rogueError = null;
  try {
    await roguePage.goto(`${ROGUE}/`);
  } catch (error) {
    rogueError = String(error.message).split('\n')[0];
  }
  // Over BiDi, Firefox reports a failed navigation as "unknown error"; its error page names
  // the cause, so the document address is read as well.
  const rogueDocument = await roguePage.evaluate(() => document.documentURI).catch((error) => `unreadable:${error.message}`);
  info('untrusted_ca_error', { rogueError, rogueDocument });
  check(
    'https.untrusted_ca_refused',
    rogueError !== null && /CERT|SEC_ERROR|certificate|about:certerror/i.test(`${rogueError} ${rogueDocument}`),
    { rogueError, rogueDocument },
  );
  await roguePage.close();

  const controlPage = await browser1.newPage();
  await controlPage.goto(`${CORE}/control`);
  await controlPage.waitForFunction(() => Boolean(window.e22control));
  const controlProbe = await call(controlPage, () => window.e22control.probe());
  info('control_page_probe', controlProbe);
  check(
    'csp.control_page_shows_probes_detect_weaker_policy',
    controlProbe.eval === 'allowed' && controlProbe.trustedTypes === 'not_enforced' && controlProbe.unlistedPolicy === 'created',
    controlProbe,
  );
  await controlPage.close();

  // ---- AC1: the key, its export, its signatures, reload and restart -----------------------
  const { token } = await harness(CORE, '/__test/enrollment-token', {});
  const enrolled = await call(page, (t) => window.e22.enroll(t), token);
  check('ac1.enroll_registers_key', Boolean(enrolled.deviceId), enrolled);

  const isNonExtractable = (k) =>
    k.found &&
    k.isCryptoKey &&
    k.type === 'private' &&
    k.extractable === false &&
    k.algorithm === 'ECDSA' &&
    k.namedCurve === 'P-256' &&
    k.usages.length === 1 &&
    k.usages[0] === 'sign';
  let key = await call(page, () => window.e22.inspect());
  info('key_after_creation', key);
  check('ac1.key_non_extractable', isNonExtractable(key), key);
  check('ac1.export_refused', refusedAll(key.exportAttempts), key.exportAttempts);

  check('ac1.session_opened', (await call(page, () => window.e22.startSession())).ok === true);
  let echo = await call(page, () => window.e22.echo({ hello: 'world' }));
  check('ac1.signed_request_verifies', echo.status === 200 && echo.deviceId === enrolled.deviceId, echo);

  const attacks = await call(page, () => window.e22.requestAttacks());
  info('request_attacks', attacks);
  const is = (o, status, error) => o.status === status && o.error === error;
  check('ac1.valid_request_accepted', is(attacks.valid, 200, null) && is(attacks.after, 200, null), attacks);
  check('ac1.replayed_request_refused', is(attacks.replay, 401, 'counter_not_increasing'), attacks.replay);
  check('ac1.lower_counter_refused', is(attacks.lower_counter, 401, 'counter_not_increasing'), attacks.lower_counter);
  check('ac1.tampered_body_refused', is(attacks.tampered_body, 401, 'bad_request_signature'), attacks.tampered_body);
  check('ac1.tampered_path_refused', is(attacks.tampered_path, 401, 'bad_request_signature'), attacks.tampered_path);
  check('ac1.tampered_method_refused', is(attacks.tampered_method, 401, 'bad_request_signature'), attacks.tampered_method);
  check(
    'ac1.session_id_without_signature_refused',
    is(attacks.session_without_signature, 401, 'missing_signature'),
    attacks.session_without_signature,
  );

  const concurrent = await call(page, () => window.e22.concurrentEchoes(10));
  info('concurrent_statuses', concurrent);
  check('ac1.concurrent_signed_requests_serialized', concurrent.length === 10 && concurrent.every((s) => s === 200), concurrent);
  const outOfOrder = await call(page, () => window.e22.outOfOrderEchoes(10));
  info('out_of_order_statuses', outOfOrder);
  check(
    'ac1.control.out_of_order_requests_refused',
    outOfOrder[0] === 200 && outOfOrder.slice(1).every((s) => s === 401),
    outOfOrder,
  );

  await page.reload();
  await page.waitForFunction(() => Boolean(window.e22));
  key = await call(page, () => window.e22.inspect());
  check(
    'ac1.key_survives_reload',
    isNonExtractable(key) && key.publicKey === enrolled.publicKey && key.deviceId === enrolled.deviceId,
    key,
  );
  check('ac1.export_refused_after_reload', refusedAll(key.exportAttempts), key.exportAttempts);
  await call(page, () => window.e22.startSession());
  echo = await call(page, () => window.e22.echo({ after: 'reload' }));
  check('ac1.signed_request_after_reload', echo.status === 200 && echo.deviceId === enrolled.deviceId, echo);

  await browser1.close();
  browser1 = await launch('enrolled');
  ({ page } = await open(browser1, `${CORE}/`, 'e22'));
  key = await call(page, () => window.e22.inspect());
  info('key_after_restart', key);
  check(
    'ac1.key_survives_restart',
    isNonExtractable(key) && key.publicKey === enrolled.publicKey && key.deviceId === enrolled.deviceId,
    key,
  );
  check('ac1.export_refused_after_restart', refusedAll(key.exportAttempts), key.exportAttempts);
  await call(page, () => window.e22.startSession());
  echo = await call(page, () => window.e22.echo({ after: 'restart' }));
  check('ac1.signed_request_after_restart', echo.status === 200 && echo.deviceId === enrolled.deviceId, echo);

  // ---- AC2: pairing codes ------------------------------------------------------------------
  const issuerPage = await browser1.newPage();
  const pairResponse = await issuerPage.goto(`${CORE}/pair`);
  await issuerPage.waitForFunction(() => Boolean(window.e22pair));
  const pairCsp = pairResponse.headers()['content-security-policy'] ?? '';
  info('pair_page_csp', pairCsp);
  check(
    'csp.pair_page_header',
    pairCsp.includes("'wasm-unsafe-eval'") && pairCsp.includes("require-trusted-types-for 'script'"),
    pairCsp,
  );
  const pairProbe = await call(issuerPage, () => window.e22pair.probe());
  info('pair_page_probe', pairProbe);
  check('csp.pair_page_runs_opaque_wasm', pairProbe.opaque === 'ready' && pairProbe.wasm === 'allowed', pairProbe);
  check('csp.pair_page_blocks_eval', pairProbe.eval.startsWith('blocked:'), pairProbe);
  check('csp.pair_page_enforces_trusted_types', pairProbe.trustedTypes.startsWith('enforced:'), pairProbe);
  check('csp.pair_page_refuses_unlisted_policy', (pairProbe.unlistedPolicy ?? '').startsWith('refused:'), pairProbe);

  const issue = () => call(issuerPage, () => window.e22pair.issue());
  const deviceByKey = (publicKey) => harness(CORE, '/__test/device-by-key', { public_key: publicKey });
  const pairingState = (code) => harness(CORE, '/__test/pairing-state', { handle: code.slice(0, 3) });
  // Every redeem below is one login start from this container; the per-source limit is reset
  // first so the matrix stays under it. The limit itself is checked at the end of AC2.
  const resetRate = () => harness(CORE, '/__test/reset-login-rate', {});

  let started = Date.now();
  const issued1 = await issue();
  info('issue_ms', String(Date.now() - started));
  info('issued_code', issued1);
  check('ac2.paired_browser_issues_code', CODE_PATTERN.test(issued1.code ?? ''), issued1);

  const browser2 = await launch('new');
  const { page: page2 } = await open(browser2, `${CORE}/pair`, 'e22pair');
  await resetRate();
  started = Date.now();
  const redeemed = await call(page2, (c) => window.e22pair.redeem(c), issued1.code);
  info('redeem_ms', String(Date.now() - started));
  info('redeemed', redeemed);
  const registered2 = await deviceByKey(redeemed.publicKey);
  check(
    'ac2.code_binds_new_browser_key',
    !redeemed.error && redeemed.echoStatus === 200 && registered2.registered && registered2.origin === 'pairing',
    { redeemed, registered2 },
  );
  await page2.goto(`${CORE}/`);
  await page2.waitForFunction(() => Boolean(window.e22));
  const key2 = await call(page2, () => window.e22.inspect());
  check(
    'ac2.paired_key_non_extractable',
    isNonExtractable(key2) && refusedAll(key2.exportAttempts) && key2.publicKey === redeemed.publicKey,
    key2,
  );

  const browser3 = await launch('other');
  const { page: page3 } = await open(browser3, `${CORE}/pair`, 'e22pair');
  const redeem3 = async (c) => {
    await resetRate();
    return call(page3, (code) => window.e22pair.redeem(code), c);
  };
  const reused = await redeem3(issued1.code);
  const reusedState = await pairingState(issued1.code);
  check('ac2.code_single_use', reused.error === 'opaque_client_rejected' && reusedState.used === true, { reused, reusedState });

  const issued2 = await issue();
  const secretDigit = issued2.code.at(-1);
  const wrongCode = issued2.code.slice(0, -1) + (secretDigit === '0' ? '1' : '0');
  const wrongAttempts = [];
  for (let i = 0; i < 3; i += 1) wrongAttempts.push((await redeem3(wrongCode)).error);
  const afterWrong = await redeem3(issued2.code);
  const lockedState = await pairingState(issued2.code);
  check(
    'ac2.three_wrong_attempts_lock_the_code',
    wrongAttempts.every((e) => e === 'opaque_client_rejected') &&
      afterWrong.error === 'opaque_client_rejected' &&
      lockedState.attempts === 3,
    { wrongAttempts, afterWrong, lockedState },
  );

  const issued3 = await issue();
  await harness(CORE, '/__test/advance-clock', { seconds: 121 });
  const expired = await redeem3(issued3.code);
  const expiredState = await pairingState(issued3.code);
  check(
    'ac2.expired_code_refused',
    expired.error === 'opaque_client_rejected' && expiredState.expired === true && expiredState.attempts === 0,
    { expired, expiredState },
  );

  // A handle with no pending pairing gets the same answer as a wrong secret.
  let unknownHandle = null;
  for (let n = 0; n < 1000 && unknownHandle === null; n += 1) {
    const handle = String(n).padStart(3, '0');
    if (!(await harness(CORE, '/__test/pairing-state', { handle })).exists) unknownHandle = handle;
  }
  const unknown = await redeem3(`${unknownHandle}-1234-5678`);
  check('ac2.unknown_handle_answered_like_a_wrong_code', unknown.error === 'opaque_client_rejected', unknown);

  const hostCode = await harness(CORE, '/__test/host-pair', {});
  const hostRedeemed = await redeem3(hostCode.code);
  const hostRegistered = await deviceByKey(hostRedeemed.publicKey ?? '');
  check(
    'ac2.host_issued_code_binds_new_browser_key',
    !hostRedeemed.error && hostRedeemed.echoStatus === 200 && hostRegistered.registered,
    { hostRedeemed, hostRegistered },
  );

  // The relay on the issuing browser's path, substituting the registration response.
  await harness(RELAY, '/__relay/mode', { mode: 'substitute-registration' });
  const substitutedIssue = await issue();
  await harness(RELAY, '/__relay/mode', { mode: 'pass' });
  check(
    'ac2.substituted_registration_response_refused_by_issuer',
    substitutedIssue.error === 'registration_response_not_authenticated',
    substitutedIssue,
  );

  // The relay on the new browser's path.
  const relayKey = (await harness(RELAY, '/__relay/key')).public_key;
  await harness(RELAY, '/__relay/mode', { mode: 'substitute-key' });
  const issued5 = await issue();
  const browser4 = await launch('relayed');
  const { page: page4 } = await open(browser4, `${RELAY}/pair`, 'e22pair');
  const relayProbe = await call(page4, () => window.e22pair.probe());
  check('https.relay_name_loads_with_certificate_validation', relayProbe.secureContext === true, relayProbe);
  const redeem4 = async (c) => {
    await resetRate();
    return call(page4, (code) => window.e22pair.redeem(code), c);
  };
  const substituted = await redeem4(issued5.code);
  const relayRegistered = await deviceByKey(relayKey);
  const browser4Registered = await deviceByKey(substituted.publicKey ?? '');
  check(
    'ac2.relay_key_substitution_refused',
    substituted.error === 'binding_mismatch' && !relayRegistered.registered && !browser4Registered.registered,
    { substituted, relayRegistered, browser4Registered },
  );
  const burned = await redeem4(issued5.code);
  const burnedState = await pairingState(issued5.code);
  check(
    'ac2.substituted_run_uses_up_the_code',
    burned.error === 'opaque_client_rejected' && burnedState.used === true,
    { burned, burnedState },
  );

  await harness(RELAY, '/__relay/mode', { mode: 'pass' });
  const issued6 = await issue();
  const relayed = await redeem4(issued6.code);
  const relayedRegistered = await deviceByKey(relayed.publicKey ?? '');
  const relayKeyAfter = await deviceByKey(relayKey);
  check(
    'ac2.relayed_run_binds_browser_key_only',
    !relayed.error && relayedRegistered.registered && !relayKeyAfter.registered,
    { relayed, relayedRegistered, relayKeyAfter },
  );
  await resetRate();
  const replayed = await harness(RELAY, '/__relay/replay', {});
  const replayedState = await pairingState(issued6.code);
  check(
    'ac2.recorded_messages_replay_refused',
    replayed.finish === 'unknown_pairing' && replayed.start === 'accepted' && replayedState.used === true && replayedState.attempts === 1,
    { replayed, replayedState },
  );

  // The per-source limit on login starts: garbage starts count too.
  await resetRate();
  const rateStatuses = [];
  for (let i = 0; i < 11; i += 1) {
    rateStatuses.push((await harness(CORE, '/api/pair/login/start', { handle: '000', credential_request: 'AA' })).status);
  }
  await resetRate();
  info('login_start_rate_statuses', rateStatuses);
  check(
    'ac2.login_starts_rate_limited_per_source',
    rateStatuses.slice(0, 10).every((s) => s === 400) && rateStatuses[10] === 429,
    rateStatuses,
  );

  // ---- AC3: light confirmations ------------------------------------------------------------
  await page.goto(`${CORE}/`);
  await page.waitForFunction(() => Boolean(window.e22));
  await call(page, () => window.e22.startSession());
  const deviceId = await call(page, () => window.e22.deviceId());
  const pending = async (title) => (await harness(CORE, '/__test/pending', { device_id: deviceId, title })).request_id;
  const [a, b, c, d, e] = [await pending('A'), await pending('B'), await pending('C'), await pending('D'), await pending('E')];
  const outcomes = await call(page, ([x, y, z]) => window.e22.confirmationAttacks(x, y, z), [a, b, c]);
  info('confirmation_outcomes', outcomes);
  check(
    'ac3.device_signature_approves_its_request',
    outcomes.approve_a.status === 200 && outcomes.approve_b.status === 200 && outcomes.approve_c.status === 200,
    outcomes,
  );
  check('ac3.replayed_approval_refused', outcomes.replay_a.error === 'nonce_used', outcomes.replay_a);
  check(
    'ac3.decided_request_takes_no_new_challenge',
    outcomes.new_challenge_for_decided_a.error === 'request_decided',
    outcomes.new_challenge_for_decided_a,
  );
  check(
    'ac3.signature_over_other_request_refused',
    outcomes.signature_of_c_on_b.error === 'bad_confirmation_signature',
    outcomes.signature_of_c_on_b,
  );
  check(
    'ac3.nonce_of_other_request_refused',
    outcomes.nonce_of_c_on_b.error === 'nonce_for_other_request',
    outcomes.nonce_of_c_on_b,
  );
  check(
    'ac3.reused_nonce_refused',
    outcomes.nonce_of_a_on_b.error === 'nonce_used' && outcomes.reused_nonce_of_c.error === 'nonce_used',
    outcomes,
  );
  check(
    'ac3.tampered_bytes_refused',
    outcomes.tampered_bytes_of_b.error === 'bad_confirmation_signature',
    outcomes.tampered_bytes_of_b,
  );

  const guard = await call(page, ([x, y]) => window.e22.guardChecks(x, y), [e, d]);
  info('client_guard', guard);
  check(
    'ac3.client_signs_only_this_requests_confirmation',
    guard.valid === 'ok' &&
      guard.request_digest.startsWith('refused:') &&
      guard.other_kind === 'refused:wrong_kind' &&
      guard.other_request === 'refused:other_request' &&
      guard.trailing_byte === 'refused:not_canonical_cbor',
    guard,
  );

  const challengeD = await call(page, (id) => window.e22.challenge(id), d);
  await call(page2, () => window.e22.startSession());
  const otherChallenge = await call(page2, (id) => window.e22.challenge(id), d);
  check('ac3.other_device_gets_no_challenge', otherChallenge.error === 'unknown_request', otherChallenge);
  const guarded = await call(page2, ([id, ch]) => window.e22.approveWith(id, ch.nonce, ch.bytes), [d, challengeD]);
  const byOther = await call(page2, ([id, ch]) => window.e22.approveUnchecked(id, ch.nonce, ch.bytes), [d, challengeD]);
  const byOwner = await call(page, ([id, ch]) => window.e22.approveWith(id, ch.nonce, ch.bytes), [d, challengeD]);
  check(
    'ac3.other_device_refused',
    guarded.error === 'refused:other_device' && byOther.error === 'nonce_for_other_device' && byOwner.status === 200,
    { guarded, byOther, byOwner },
  );

  for (const context of [browser1, browser2, browser3, browser4]) await context.close();
}

try {
  await main();
} catch (error) {
  check('driver_completed', false, String(error?.stack ?? error));
}
process.exit(failed ? 1 : 0);
