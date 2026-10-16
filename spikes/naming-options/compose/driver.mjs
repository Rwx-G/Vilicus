// E24 browser driver: runs every naming option and the self-signed ceremony attempt in one
// browser, and prints `PLAN <n>`, then one `PASS <name>` or `FAIL <name>` line per check,
// `INFO` lines with the evidence, and one `ROW <option> <browser> <summary>` line per option for
// the matrix. Usage: node driver.mjs <browser key>.
//
// Chrome is driven by Playwright over CDP, with the CDP virtual authenticator; Firefox by
// geckodriver over WebDriver, with the WebDriver virtual authenticator. Neither is a real
// authenticator, and neither run is on Android.
import { chromium } from 'playwright';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';

const BROWSERS = {
  'chrome-155': { engine: 'chrome', binary: '/opt/chrome-155/chrome-linux64/chrome' },
  'chrome-154': { engine: 'chrome', binary: '/opt/chrome-154/chrome-linux64/chrome' },
  'firefox-158': { engine: 'firefox', binary: '/opt/firefox-158/firefox/firefox' },
  'firefox-157': { engine: 'firefox', binary: '/opt/firefox-157/firefox/firefox' },
};
// Roots added to the browser's own store (user-added roots, one trust path for every row): the
// stand-in for a public CA, and the local CA. Neither is a built-in root, so Chrome applies no
// Certificate Transparency requirement to either.
const TRUSTED_ROOTS = [
  ['E24 stand-in public CA', '/pki/public-ca.crt'],
  ['E24 local CA', '/pki/local-ca.crt'],
];
// Options a household can be told to use: passkeys and installation must work on each.
const NAMED_OPTIONS = [
  { id: 'dyndns', url: 'https://household.dyn.example/' },
  { id: 'private-network', url: 'https://household.tailnet.example/' },
  { id: 'local-ca', url: 'https://vilicus.home.arpa/', extraChecks: ['allow_list_of_two'] },
  // Resolved by unicast DNS in this test bed, never by mDNS.
  { id: 'local-ca-dot-local', url: 'https://vilicus.local/', note: 'unicast-DNS-not-mDNS' },
];
// A valid certificate on a private IP address: TLS works, WebAuthn must not.
const IP_OPTION = { id: 'local-ca-ip', url: 'https://10.88.0.24/' };
// The instance name a temporary credential would have to work on afterwards.
const INSTANCE_URL = 'https://vilicus.home.arpa/';
// The temporary self-signed certificate of the wizard (AC2). `instance` is the name the instance
// gets afterwards. `expect` is what each engine does with its virtual authenticator:
// 'refused' (SecurityError at creation), 'unusable' (created, bound to the temporary host, not
// usable on `instance`), 'reusable' (created, and usable on `instance`, because the temporary
// certificate named the same host). `bare` and `bareOnInstance` are what Chrome does from a tab
// without a virtual authenticator, on the target and then on `instance`: a refusal message given
// within 1 s, or WAITS (the ceremony was accepted and waits for an authenticator for at least
// 2.5 s, which is also the control that such a tab can tell a refusal from a timeout).
const LOCALHOST_PORT = 8444;
const TLS_ERROR_REFUSAL = 'WebAuthn is not supported on sites with TLS certificate errors.';
const WAITS = 'waits';
const SELF_SIGNED = [
  { id: 'selfsigned-ip', url: 'https://10.88.0.25/', instance: INSTANCE_URL,
    expect: { chrome: 'refused', firefox: 'refused' }, bare: 'This is an invalid domain.', bareOnInstance: WAITS },
  { id: 'selfsigned-name', url: 'https://host01.home.arpa/', instance: INSTANCE_URL,
    expect: { chrome: 'unusable', firefox: 'refused' }, bare: TLS_ERROR_REFUSAL, bareOnInstance: WAITS },
  // After a person passed the warning for this host, Chrome refuses WebAuthn on the same host
  // with its real certificate too, for the rest of the browser session.
  { id: 'selfsigned-same-name', url: 'https://same.home.arpa:8443/', instance: 'https://same.home.arpa/',
    expect: { chrome: 'reusable', firefox: 'refused' }, bare: TLS_ERROR_REFUSAL, bareOnInstance: TLS_ERROR_REFUSAL },
  // The wizard reached through a port forward to localhost (an SSH tunnel, for example): both
  // browsers accept the ceremony on localhost despite the certificate error.
  { id: 'selfsigned-localhost', url: `https://localhost:${LOCALHOST_PORT}/`, instance: INSTANCE_URL,
    expect: { chrome: 'unusable', firefox: 'unusable' }, bare: WAITS, bareOnInstance: WAITS },
];
const BARE_REFUSAL_MAX_MS = 1000;
const BARE_CONTROL_MIN_MS = 2500;

const NAMED_CHECKS = ['tls', 'secure_context', 'pwa_signals', 'register', 'login'];
// Only Chrome reports installability (CDP); installation is not measured on Firefox for Linux.
const namedChecks = (browser, option) => [
  ...NAMED_CHECKS,
  ...(browser.installability ? ['installable'] : []),
  ...(option.extraChecks || []),
];
const IP_CHECKS = ['tls', 'secure_context', 'webauthn_refused'];
// Chrome adds the two checks of a tab without a virtual authenticator.
const selfSignedChecks = (browser) => [
  'cert_rejected', 'positive_control_on_instance', 'virtual_authenticator_outcome',
  ...(browser.probeWithoutAuthenticator ? ['no_authenticator_outcome', 'no_authenticator_on_instance'] : []),
];
const planFor = (browser) => NAMED_OPTIONS.reduce((n, option) => n + namedChecks(browser, option).length, 0)
  + IP_CHECKS.length + SELF_SIGNED.length * selfSignedChecks(browser).length;
// Firefox's virtual authenticator refuses allow lists of more than one credential (an open item,
// see the story); Chrome's accepts them.
const ALLOW_LIST_OF_TWO_EXPECTED = { chrome: 'ok', firefox: 'NotAllowedError' };

const firstLine = (text) => String(text).split('\n')[0].slice(0, 200);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const brief = (value) => JSON.stringify(value);

// Prints one line per declared check, and a FAIL for any declared check the run never reached.
function recorder(prefix, names) {
  const results = new Map();
  return {
    set(name, ok, detail) {
      if (!names.includes(name) || results.has(name)) throw new Error(`undeclared or repeated check ${name}`);
      results.set(name, ok);
      console.log(`${ok ? 'PASS' : 'FAIL'} ${prefix}.${name}${detail ? ` (${detail})` : ''}`);
    },
    finish(reason) {
      for (const name of names) {
        if (!results.has(name)) this.set(name, false, `not run: ${reason || 'aborted'}`);
      }
      return names.filter((name) => !results.get(name));
    },
  };
}

function nssDb(dir) {
  fs.mkdirSync(dir, { recursive: true });
  execFileSync('certutil', ['-N', '-d', `sql:${dir}`, '--empty-password']);
  for (const [nickname, file] of TRUSTED_ROOTS) {
    execFileSync('certutil', ['-A', '-d', `sql:${dir}`, '-n', nickname, '-t', 'C,,', '-i', file]);
  }
}

// Loads `url` in a Chrome page; with `clickThrough`, proceeds past a certificate warning the way
// a person does: "Advanced", then "Proceed to ... (unsafe)".
// page.goto, retried while an earlier navigation (Chrome's certificate error page commits after
// the failed navigation has returned) interrupts it.
async function chromeGoto(page, url) {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await page.goto(url, { waitUntil: 'load', timeout: 20000 });
    } catch (err) {
      if (attempt >= 5 || !/is interrupted by another navigation/.test(err.message)) throw err;
      await sleep(300);
    }
  }
}

async function chromeOpen(page, url, clickThrough) {
  await chromeGoto(page, 'about:blank');
  try {
    await chromeGoto(page, url);
    return { loaded: true, certRejected: false };
  } catch (err) {
    const certRejected = /ERR_CERT_/.test(err.message);
    const error = firstLine(err.message);
    if (!clickThrough || !certRejected) return { loaded: false, certRejected, error };
    try {
      await page.click('#details-button', { timeout: 5000 });
      await Promise.all([
        page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }),
        page.click('#proceed-link', { timeout: 5000 }),
      ]);
      const loaded = new URL(page.url()).origin === new URL(url).origin;
      return { loaded, certRejected, error, mode: 'interstitial proceed link' };
    } catch (clickErr) {
      return { loaded: false, certRejected, error: `click-through failed: ${firstLine(clickErr.message)}` };
    }
  }
}

async function chromeAdapter(config, key) {
  const home = `/tmp/${key}-home`;
  nssDb(`${home}/.pki/nssdb`);
  // A persistent profile: Chrome reports an off-the-record context as not installable.
  const context = await chromium.launchPersistentContext(`/tmp/${key}-profile`, {
    executablePath: config.binary,
    headless: true,
    env: { ...process.env, HOME: home },
  });
  const page = context.pages()[0] || (await context.newPage());
  let bareContext = null;
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const addAuthenticator = async () => (await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  })).authenticatorId;
  let authenticatorId = await addAuthenticator();
  return {
    engine: 'chrome',
    async resetAuthenticator() {
      await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
      authenticatorId = await addAuthenticator();
    },
    version: firstLine(execFileSync(config.binary, ['--version'], { encoding: 'utf8' })).trim(),
    trustNote: 'roots added to the NSS database in $HOME/.pki/nssdb',
    open: (url, clickThrough) => chromeOpen(page, url, clickThrough),
    // WebAuthn needs the document to have focus: bring the main tab back after a control tab.
    async call(fn, ...args) {
      await page.bringToFront();
      return page.evaluate(([name, list]) => window.e24[name](...list), [fn, args]);
    },
    // The same creation attempt from a tab with no virtual authenticator, so the CDP test
    // environment cannot be what lets the ceremony through. Returns the outcome and its delay.
    // It runs in a second Chrome profile: a control tab in the main profile broke the main tab's
    // later ceremonies (NotAllowedError) in this spike, which would have spoiled the record.
    async probeWithoutAuthenticator(url, clickThrough) {
      bareContext ||= await chromium.launchPersistentContext(`/tmp/${key}-bare-profile`, {
        executablePath: config.binary,
        headless: true,
        env: { ...process.env, HOME: home },
      });
      const bare = await bareContext.newPage();
      try {
        const nav = await chromeOpen(bare, url, clickThrough);
        if (!nav.loaded) return { nav };
        const started = Date.now();
        // With no authenticator, a ceremony the browser accepts waits for one: abort it after
        // 5 s, so no request stays pending (a pending one broke later ceremonies in other tabs).
        const result = await bare.evaluate(() => window.e24.probeCreate(3000, 5000));
        return { nav, result, ms: Date.now() - started };
      } finally {
        await bare.close();
      }
    },
    async installability() {
      // Chrome evaluates installability on request; give the service worker a moment to activate.
      let errors = [];
      for (let attempt = 0; attempt < 10; attempt += 1) {
        const result = await cdp.send('Page.getInstallabilityErrors');
        errors = result.installabilityErrors.map((e) => e.errorId);
        if (errors.length === 0) break;
        await sleep(1000);
      }
      return errors;
    },
    async close() {
      if (bareContext) await bareContext.close();
      await context.close();
    },
  };
}

async function firefoxAdapter(config, key) {
  const profile = `/tmp/${key}-profile`;
  nssDb(profile);
  // The WebDriver virtual authenticator answers only with Firefox's software token enabled.
  const prefs = {
    'security.webauth.webauthn_enable_softtoken': true,
    'security.webauth.webauthn_enable_usbtoken': false,
  };
  fs.writeFileSync(`${profile}/user.js`, Object.entries(prefs).map(([k, v]) => `user_pref(${brief(k)}, ${brief(v)});\n`).join(''));
  const port = 4444;
  const driver = spawn('geckodriver', ['--port', String(port)], { stdio: 'ignore' });
  const wd = async (method, path, body) => {
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method,
      headers: { 'content-type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = await response.json();
    if (json.value && json.value.error) {
      throw Object.assign(new Error(`${json.value.error}: ${json.value.message}`), { wdError: json.value.error });
    }
    return json.value;
  };
  for (let attempt = 0; ; attempt += 1) {
    try { await wd('GET', '/status'); break; } catch (err) {
      if (attempt > 50) throw err;
      await sleep(200);
    }
  }
  const session = await wd('POST', '/session', {
    capabilities: {
      alwaysMatch: {
        browserName: 'firefox',
        acceptInsecureCerts: false,
        'moz:firefoxOptions': { binary: config.binary, args: ['-headless', '-profile', profile], prefs },
      },
    },
  });
  const base = `/session/${session.sessionId}`;
  await wd('POST', `${base}/timeouts`, { script: 60000, pageLoad: 20000 });
  const addAuthenticator = () => wd('POST', `${base}/webauthn/authenticator`, {
    protocol: 'ctap2',
    transport: 'internal',
    hasResidentKey: true,
    hasUserVerification: true,
    isUserConsenting: true,
    isUserVerified: true,
  });
  let authenticatorId = await addAuthenticator();
  const exec = (script, args = []) => wd('POST', `${base}/execute/sync`, { script, args });
  const elementId = (found) => Object.values(found)[0];
  // The warning page's buttons: in the document on older releases, in the shadow root of
  // <net-error-card> on newer ones. Returns the first selector that matches.
  const warningButton = async (selectors) => {
    for (const css of selectors) {
      try { return elementId(await wd('POST', `${base}/element`, { using: 'css selector', value: css })); } catch { /* next */ }
    }
    const card = elementId(await wd('POST', `${base}/element`, { using: 'css selector', value: 'net-error-card' }));
    const root = elementId(await wd('GET', `${base}/element/${card}/shadow`));
    for (const css of selectors) {
      try { return elementId(await wd('POST', `${base}/shadow/${root}/element`, { using: 'css selector', value: css })); } catch { /* next */ }
    }
    throw new Error(`no warning page button among ${selectors.join(', ')}`);
  };
  const waitForApp = async (origin) => {
    for (let attempt = 0; attempt < 50; attempt += 1) {
      try {
        if (await exec('return location.origin === arguments[0] && typeof window.e24 === "object";', [origin])) return true;
      } catch { /* the page is still navigating */ }
      await sleep(200);
    }
    return false;
  };
  return {
    engine: 'firefox',
    async resetAuthenticator() {
      await wd('DELETE', `${base}/webauthn/authenticator/${authenticatorId}`);
      authenticatorId = await addAuthenticator();
    },
    version: session.capabilities.browserVersion,
    trustNote: 'roots added to the NSS database of the Firefox profile',
    async open(url, clickThrough) {
      try {
        await wd('POST', `${base}/url`, { url });
        return { loaded: await waitForApp(new URL(url).origin), certRejected: false };
      } catch (err) {
        const certRejected = err.wdError === 'insecure certificate';
        const error = firstLine(err.message);
        if (!clickThrough || !certRejected) return { loaded: false, certRejected, error };
        try {
          // What a person does on the warning page: "Advanced...", then "Accept the Risk and Continue".
          await wd('POST', `${base}/element/${await warningButton(['#advancedButton', '#advanced-button'])}/click`, {});
          // Firefox keeps the exception button disabled for a moment after it appears.
          await sleep(2000);
          await wd('POST', `${base}/element/${await warningButton(['#exceptionDialogButton', '#exception-button'])}/click`, {});
          const loaded = await waitForApp(new URL(url).origin);
          return { loaded, certRejected, error, mode: 'warning page exception button' };
        } catch (clickErr) {
          return { loaded: false, certRejected, error: `click-through failed: ${firstLine(clickErr.message)}` };
        }
      }
    },
    call: (fn, ...args) => wd('POST', `${base}/execute/async`, {
      script: 'const done = arguments[arguments.length - 1];'
        + 'window.e24[arguments[0]](...arguments[1]).then(done, (e) => done({ ok: false, stage: "driver", name: e.name, message: String(e.message) }));',
      args: [fn, args],
    }),
    installability: null,
    async close() {
      await wd('DELETE', base).catch(() => {});
      driver.kill();
    },
  };
}

async function runNamedOption(browser, key, option) {
  const host = new URL(option.url).hostname;
  const checks = recorder(`${key}.${option.id}`, namedChecks(browser, option));
  const cells = [];
  try {
    const nav = await browser.open(option.url, false);
    checks.set('tls', nav.loaded && !nav.certRejected, nav.error);
    if (!nav.loaded) return { failed: checks.finish('page did not load'), cells: ['tls=fail'] };
    const pwa = await browser.call('pwa');
    console.log(`INFO ${key}.${option.id}.pwa ${brief(pwa)}`);
    checks.set('secure_context', pwa.secureContext === true);
    checks.set('pwa_signals', pwa.ok === true, pwa.serviceWorkerError || pwa.manifestError);
    if (browser.installability) {
      const errors = await browser.installability();
      checks.set('installable', errors.length === 0, `installability errors: ${errors.join(',') || 'none'}`);
      cells.push(`install=${errors.length === 0 ? 'ok' : 'fail'}`);
    } else {
      cells.push('install=not-measured-on-linux-desktop');
    }
    const registration = await browser.call('register', key);
    console.log(`INFO ${key}.${option.id}.register ${brief(registration)}`);
    checks.set('register', registration.ok === true && registration.rpId === host, `rp_id ${registration.rpId}`);
    const login = await browser.call('login', key);
    console.log(`INFO ${key}.${option.id}.login ${brief(login)}`);
    checks.set('login', login.ok === true && login.credentialId === registration.credentialId,
      `same credential: ${login.credentialId === registration.credentialId}`);
    cells.unshift(`passkey=${registration.ok && login.ok ? 'ok' : 'fail'}${option.note ? `(${option.note})` : ''}`);
    if ((option.extraChecks || []).includes('allow_list_of_two')) {
      cells.push(`allow-list-of-two=${await runAllowListOfTwo(browser, key, option, checks)}`);
    }
  } catch (err) {
    console.log(`INFO ${key}.${option.id}.error ${firstLine(err.message)}`);
  }
  return { failed: checks.finish(), cells };
}

// A member with two passkeys gets an allow list naming both. Client side: two credentials of
// this authenticator, then allow lists of both, of the matching one first, and of the matching
// one second; server side: two passkeys registered for one user, then a webauthn-rs login.
async function runAllowListOfTwo(browser, key, option, checks) {
  const client = await browser.call('probeAllowLists');
  const user = `${key}-two-passkeys`;
  const first = await browser.call('register', user);
  const second = await browser.call('register', user);
  const started = Date.now();
  const server = await browser.call('login', user);
  server.ms = Date.now() - started;
  console.log(`INFO ${key}.${option.id}.allow_list_of_two client=${brief(client)}`);
  console.log(`INFO ${key}.${option.id}.allow_list_of_two server registrations=${first.ok},${second.ok} login=${brief(server)}`);
  const name = (result) => (result && result.ok ? 'ok' : result && result.name);
  const outcomes = {
    single: name(client.single),
    both: name(client.ownBoth),
    matchingFirst: name(client.matchingFirst),
    matchingSecond: name(client.matchingSecond),
    server: name(server),
  };
  const expected = ALLOW_LIST_OF_TWO_EXPECTED[browser.engine];
  const listsOfTwo = [outcomes.both, outcomes.matchingFirst, outcomes.matchingSecond, outcomes.server];
  const asExpected = outcomes.single === 'ok' && first.ok && second.ok && listsOfTwo.every((o) => o === expected);
  const timings = ['single', 'ownBoth', 'matchingFirst', 'matchingSecond']
    .map((k) => `${k} ${client[k] && client[k].ms} ms`).join(', ');
  checks.set('allow_list_of_two', asExpected,
    `expected ${expected} for every list of two; got ${brief(outcomes)}; ${timings}, server ${server.ms} ms; ${client.ownBoth && client.ownBoth.message}`);
  return listsOfTwo.every((o) => o === 'ok') ? 'ok' : listsOfTwo.join('/');
}

async function runIpOption(browser, key, option) {
  const checks = recorder(`${key}.${option.id}`, IP_CHECKS);
  const cells = [];
  try {
    const nav = await browser.open(option.url, false);
    checks.set('tls', nav.loaded && !nav.certRejected, nav.error);
    if (!nav.loaded) return { failed: checks.finish('page did not load'), cells: ['tls=fail'] };
    const pwa = await browser.call('pwa');
    console.log(`INFO ${key}.${option.id}.pwa ${brief(pwa)}`);
    checks.set('secure_context', pwa.secureContext === true);
    if (browser.installability) {
      const errors = await browser.installability();
      console.log(`INFO ${key}.${option.id}.installability errors: ${errors.join(',') || 'none'}`);
    }
    const probe = await browser.call('probeCreate');
    console.log(`INFO ${key}.${option.id}.probeCreate ${brief(probe)}`);
    checks.set('webauthn_refused', probe.ok === false, `${probe.name}: ${probe.message}`);
    cells.push(probe.ok ? 'passkey=CREATED' : `passkey=refused(${probe.name})`);
  } catch (err) {
    console.log(`INFO ${key}.${option.id}.error ${firstLine(err.message)}`);
  }
  return { failed: checks.finish(), cells };
}

async function runSelfSigned(browser, key, target) {
  const checks = recorder(`${key}.${target.id}`, selfSignedChecks(browser));
  const expected = target.expect[browser.engine];
  const cells = [];
  try {
    // A fresh authenticator per target: Chrome's stopped creating credentials partway through
    // the run in this spike (cause not established), which the positive control caught.
    await browser.resetAuthenticator();
    const first = await browser.open(target.url, false);
    checks.set('cert_rejected', first.certRejected === true, first.error || 'loaded without a warning');
    // Positive control: the same browser and authenticator create a credential on the instance.
    const instance = await browser.open(target.instance, false);
    const control = instance.loaded ? await browser.call('probeCreate') : { ok: false, message: instance.error };
    checks.set('positive_control_on_instance', control.ok === true,
      `${target.instance}: ${control.ok ? 'created' : control.message}`);
    const nav = await browser.open(target.url, true);
    console.log(`INFO ${key}.${target.id}.click_through ${brief(nav)}`);
    if (nav.loaded) {
      const pwa = await browser.call('pwa');
      console.log(`INFO ${key}.${target.id}.pwa_after_warning ${brief(pwa)}`);
      if (browser.installability) {
        const errors = await browser.installability();
        console.log(`INFO ${key}.${target.id}.installability_after_warning errors: ${errors.join(',') || 'none'}`);
      }
    }
    const probe = nav.loaded ? await browser.call('probeCreate') : { ok: false, name: 'NoPage', message: nav.error };
    console.log(`INFO ${key}.${target.id}.probeCreate ${brief(probe)}`);
    if (browser.probeWithoutAuthenticator) {
      const bare = await browser.probeWithoutAuthenticator(target.url, true);
      const bareInstance = await browser.probeWithoutAuthenticator(target.instance, false);
      console.log(`INFO ${key}.${target.id}.no_authenticator ${brief(bare)}`);
      console.log(`INFO ${key}.${target.id}.no_authenticator_on_instance ${brief(bareInstance)}`);
      checks.set('no_authenticator_outcome', ...bareVerdict(bare, target.bare));
      checks.set('no_authenticator_on_instance', ...bareVerdict(bareInstance, target.bareOnInstance));
      cells.push(`no-authenticator=${bare.result ? bare.result.name || 'created' : 'no page'}`);
    }
    let outcome;
    let detail;
    if (!probe.ok) {
      outcome = probe.name === 'SecurityError' ? 'refused' : `failed(${probe.name})`;
      detail = `${probe.name}: ${probe.message}`;
    } else {
      // Created over the temporary certificate, so bound to the temporary host: try it on the instance.
      const later = await browser.open(target.instance, false);
      if (!later.loaded) {
        outcome = 'instance-not-loaded';
        detail = later.error;
      } else {
        const reuse = await browser.call('probeGet', probe.credentialId);
        const explicit = await browser.call('probeGet', probe.credentialId, probe.host);
        console.log(`INFO ${key}.${target.id}.reuse_on_instance implicit=${brief(reuse)} explicit_rp_id=${brief(explicit)}`);
        // Control for 'unusable': the same credential still works on the host it was made on.
        const home = await browser.open(target.url, true);
        const onHome = home.loaded ? await browser.call('probeGet', probe.credentialId) : { ok: false, name: 'NoPage' };
        if (!probe.boundToHost) outcome = 'not-bound-to-host';
        else if (reuse.ok) outcome = 'reusable';
        else outcome = onHome.ok ? 'unusable' : `unusable-but-also-on-its-host(${onHome.name})`;
        detail = `created, rpIdHash of ${probe.host}: ${probe.boundToHost}; on ${target.instance}: ${reuse.ok ? 'usable' : reuse.name}, with rpId ${probe.host}: ${explicit.ok ? 'usable' : explicit.name}; back on ${probe.host}: ${onHome.ok ? 'usable' : onHome.name}`;
      }
    }
    checks.set('virtual_authenticator_outcome', outcome === expected, `${outcome}, expected ${expected}: ${detail}`);
    cells.unshift(`virtual=${outcome}`);
  } catch (err) {
    console.log(`INFO ${key}.${target.id}.error ${firstLine(err.message)}`);
  }
  return { failed: checks.finish(), cells };
}

// [ok, detail] for an attempt from a tab without a virtual authenticator against its expectation.
function bareVerdict(bare, expected) {
  const got = bare.result ? `${bare.result.name}: ${bare.result.message}` : `no page: ${bare.nav && bare.nav.error}`;
  if (expected === WAITS) {
    const ok = Boolean(bare.result) && bare.result.ok === false && bare.ms >= BARE_CONTROL_MIN_MS;
    return [ok, `${got} after ${bare.ms} ms; expected a wait of at least ${BARE_CONTROL_MIN_MS} ms`];
  }
  const ok = Boolean(bare.result) && bare.result.ok === false && bare.result.message === expected && bare.ms < BARE_REFUSAL_MAX_MS;
  return [ok, `${got} after ${bare.ms} ms; expected "${expected}" within ${BARE_REFUSAL_MAX_MS} ms`];
}

// The wizard reached on localhost: a TCP forward from this container to the self-signed instance.
function forwardLocalhost() {
  const servers = ['127.0.0.1', '::1'].map((host) => {
    const server = net.createServer((socket) => {
      const upstream = net.connect(443, '10.88.0.25');
      socket.pipe(upstream).pipe(socket);
      socket.on('error', () => upstream.destroy());
      upstream.on('error', () => socket.destroy());
    });
    server.on('error', () => {});
    server.listen(LOCALHOST_PORT, host);
    return server;
  });
  return () => servers.forEach((server) => server.close());
}

const key = process.argv[2];
const config = BROWSERS[key];
if (!config) {
  console.error(`usage: node driver.mjs <${Object.keys(BROWSERS).join('|')}>`);
  process.exit(2);
}
const stopForward = forwardLocalhost();
const browser = config.engine === 'chrome' ? await chromeAdapter(config, key) : await firefoxAdapter(config, key);
console.log(`PLAN ${planFor(browser)}`);
console.log(`INFO ${key} version=${browser.version} trust=${brief(browser.trustNote)}`);
let failures = 0;
const row = (id, outcome) => {
  failures += outcome.failed.length;
  console.log(`ROW ${id} ${key} ${outcome.failed.length ? 'FAIL:' : ''}${outcome.cells.join(',') || 'none'}`);
};
try {
  for (const option of NAMED_OPTIONS) row(option.id, await runNamedOption(browser, key, option));
  row(IP_OPTION.id, await runIpOption(browser, key, IP_OPTION));
  for (const target of SELF_SIGNED) row(target.id, await runSelfSigned(browser, key, target));
} finally {
  await browser.close();
  stopForward();
}
process.exit(failures ? 1 : 0);
