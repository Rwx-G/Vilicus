// E26 browser harness: drives one Playwright browser through every instance name of the layout,
// loads hostile external content in the client's sandboxed iframe, and judges each attempt from
// what the Gateway, the attacker's sink and the DNS server observed.
// Usage: node harness.mjs <chromium|firefox> <label> <run id prefix>
// Prints `PASS <label>.<check>` or `FAIL <label>.<check>` per check and `INFO` lines; exits 1 on
// any failure.
import { chromium, firefox } from 'playwright';
import { readFileSync } from 'node:fs';

const [engineName, label, runPrefix] = process.argv.slice(2);
const engine = { chromium, firefox }[engineName];
if (!engine || !label || !/^[a-z]{2}$/.test(runPrefix || '')) {
  console.error('usage: node harness.mjs <chromium|firefox> <label> <two-letter run prefix>');
  process.exit(2);
}

// ------------------------------------------------------------------------------------------
// Layout and catalogue: the instance names come from network/instances.txt, the fixtures, the
// cookie name and the expected content CSP from the Gateway's catalogue.
const layout = { deployments: {}, servers: {}, instances: [], wildcards: [] };
for (const line of readFileSync('/layout/instances.txt', 'utf8').split('\n')) {
  const words = line.trim().split(/\s+/);
  if (words[0] === 'deployment') layout.deployments[words[1]] = words[2];
  if (words[0] === 'server') layout.servers[words[1]] = words[2];
  if (words[0] === 'instance') layout.instances.push({ option: words[1], deployment: words[2], name: words[3] });
  if (words[0] === 'wildcard') layout.wildcards.push(words[1]);
}
const control = {
  gateway: `http://${layout.deployments.direct}:9000`,
  sink: `http://${layout.servers.sink}:9000`,
  dns: `http://${layout.servers.dns}:9000`,
};
const attackerSuffix = layout.wildcards[0];

const getJson = async (url) => (await fetch(url)).json();
const catalogue = await getJson(`${control.gateway}/catalogue`);
const passive = catalogue.fixtures.passive;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
// Some Playwright calls never settle on plugin frames (`<object>`, `<embed>` in Firefox).
const within = (promise, ms, fallback) => Promise.race([promise.catch(() => fallback), sleep(ms).then(() => fallback)]);

let failed = 0;
const out = (line) => console.log(line);
function check(name, ok, detail = '') {
  if (!ok) failed = 1;
  out(`${ok ? 'PASS' : 'FAIL'} ${label}.${name}${detail ? ` (${detail})` : ''}`);
}
const info = (name, detail) => out(`INFO ${label}.${name} ${detail}`);

let counter = 0;
const nextRun = () => `${runPrefix}${String(++counter).padStart(4, '0')}`;
const hostOf = (run, vector) => `${run}-${vector}.${attackerSuffix}`;

// ------------------------------------------------------------------------------------------
// Observations.
async function observe(run) {
  const q = `log?contains=${run}`;
  const [gw, sink, dns] = await Promise.all([
    getJson(`${control.gateway}/${q}`),
    getJson(`${control.sink}/${q}`),
    getJson(`${control.dns}/${q}`),
  ]);
  return { gw, sink, dns };
}

// Waits until no server has logged anything new for the run for three polls in a row.
async function settle(run, minimumMs) {
  await sleep(minimumMs);
  let last = -1;
  let stable = 0;
  for (let i = 0; i < 20 && stable < 3; i += 1) {
    const o = await observe(run);
    const size = o.gw.length + o.sink.length + o.dns.length;
    stable = size === last ? stable + 1 : 0;
    last = size;
    await sleep(300);
  }
  return observe(run);
}

const mutations = async () => (await getJson(`${control.gateway}/state`)).mutations;
const sinkHits = (o, host) => o.sink.filter((e) => e.host.split(':')[0] === host);
const sinkRequests = (o, host) => sinkHits(o, host).filter((e) => e.kind === 'http');
const dnsHits = (o, host) => o.dns.filter((e) => e.host === host);
const gwRequests = (o, prefix) => o.gw.filter((e) => e.kind === 'http' && e.target.startsWith(prefix));
// Every CSP report of the run, whichever origin received it.
function reports(o) {
  return gwRequests(o, '/csp-report').map((e) => {
    try {
      const r = JSON.parse(e.body)['csp-report'] || {};
      return {
        listener: e.listener,
        document: String(r['document-uri'] || ''),
        blocked: String(r['blocked-uri'] || ''),
        directive: String(r['effective-directive'] || r['violated-directive'] || ''),
      };
    } catch {
      return { listener: e.listener, document: '', blocked: '', directive: 'unparsable' };
    }
  });
}

function printReports(prefix, o) {
  for (const r of reports(o)) {
    info(`${prefix}.csp_report`, `listener=${r.listener} directive=${r.directive} blocked=${r.blocked || '(empty)'} document=${r.document.split('?')[0]}`);
  }
}

// Requests the external content started toward the client's API (the client page itself only
// posts /api/login).
const contentStarted = (o) => o.gw.filter((e) => e.kind === 'http' && e.listener.startsWith('app')
  && e.target.startsWith('/api/') && !e.target.startsWith('/api/login'));
const describe = (list) => list.map((e) => `${e.method} ${e.target.split('?')[0]} cookie=${e.session_cookie} site=${e.sec_fetch_site}`).join(';');
const cookielessCrossSite = (list) => list.every((e) => !e.session_cookie && e.sec_fetch_site === 'cross-site');

const PWNED_VECTORS = [
  ...passive.filter((v) => v.kind === 'script').map((v) => v.name),
  'click-javascript',
];

// Loads the client page for one instance, mode and fixture, optionally clicks `#go` in the
// iframe, and gathers everything the checks need. A visit whose client page never reached
// DOMContentLoaded (a Playwright navigation timeout, seen with Firefox 155 under load) is retried
// with a new run id, at most twice; every retry is printed. Nothing else is retried.
async function visit(inst, mode, fixture, options = {}) {
  for (let attempt = 1; ; attempt += 1) {
    const result = await visitOnce(inst, mode, fixture, options);
    const navigationTimeout = result.gotoError.startsWith('page.goto: Timeout');
    if (!navigationTimeout || attempt === 3) return result;
    info('retry', `${inst.name} ${mode} ${fixture} run=${result.run} attempt=${attempt}: ${result.gotoError}`);
    await restartBrowser();
  }
}

async function visitOnce(inst, mode, fixture, { click = false, waitMs = 0, relax = false } = {}) {
  const run = nextRun();
  const app = `https://${inst.name}`;
  const page = await ctx.newPage();
  const popups = [];
  const onPage = (p) => { if (p !== page) popups.push(p); };
  ctx.on('page', onPage);
  const responses = [];
  page.on('response', (r) => responses.push(r));
  const consoleMessages = [];
  page.on('console', (m) => consoleMessages.push(m.text()));
  const before = await mutations();
  let gotoError = '';
  let main = null;
  try {
    const relaxParam = relax ? '&relax=1' : '';
    main = await page.goto(`${app}/?mode=${mode}&fixture=${fixture}&run=${run}${relaxParam}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  } catch (e) {
    gotoError = e.message.split('\n')[0];
  }
  // Ready: the client page ran and the hostile content rendered in the iframe. A check on a visit
  // that is not ready fails rather than passing because nothing happened.
  const frame = page.frameLocator('#external');
  let markerText = null;
  if (!gotoError) {
    const clientReady = await page.waitForSelector('html[data-ready="1"]', { state: 'attached', timeout: 15000 })
      .then(() => true, () => false);
    if (clientReady) {
      markerText = await frame.locator('#marker').textContent({ timeout: 15000 }).catch(() => null);
    }
  }
  const rendered = (markerText || '').includes(`external content ${fixture}`);
  const served = fixture === 'meta-refresh' && !gotoError
    && responses.some((r) => r.url().includes(`/${fixture}?run=${run}`) && r.status() === 200);
  const ready = rendered || served;
  let clickError = '';
  if (ready && click) {
    await frame.locator('#go').click({ timeout: 5000 }).catch((e) => { clickError = e.message.split('\n')[0]; });
  }
  const observed = await settle(run, 1000 + waitMs);
  const attrs = {};
  for (const name of ['nonce-ran', 'unnonced-ran', 'tt', 'tt-policy', 'login', 'cookie-visible', 'messages', 'message-origin']) {
    attrs[name] = await page.locator('html').getAttribute(`data-${name}`, { timeout: 2000 }).catch(() => null);
  }
  const pwned = [];
  if (ready) {
    for (const v of PWNED_VECTORS) {
      const value = await frame.locator('body').getAttribute(`data-pwned-${v}`, { timeout: 1000 }).catch(() => null);
      if (value !== null) pwned.push(v);
    }
  }
  const frames = [];
  for (const f of page.frames()) {
    frames.push({ url: f.url(), content: await within(f.content(), 3000, '') });
  }
  const contentPrefix = `${app}:${catalogue.content_port}/`;
  const contentResponse = responses.find((r) => r.url().startsWith(contentPrefix) && r.url().includes(`run=${run}`));
  const visitResult = {
    run, app, inst, mode, fixture, gotoError, ready, clickError, observed, attrs, markerText, pwned, frames,
    mainStatus: main ? main.status() : 0,
    mainHeaders: main ? await main.allHeaders() : {},
    contentHeaders: contentResponse ? await contentResponse.allHeaders() : null,
    // null when the cookie jar could not be read: every check that needs it then fails.
    cookies: await within(ctx.cookies(), 5000, null),
    consoleMessages,
    topUrl: page.url(),
    popups: popups.length,
    before,
    after: await mutations(),
  };
  ctx.off('page', onPage);
  for (const p of popups) await within(p.close(), 5000, null);
  await within(page.close(), 5000, null);
  await within(ctx.clearCookies(), 5000, null);
  return visitResult;
}

// ------------------------------------------------------------------------------------------
// Judgements shared by the modes.
function passiveAttempted(o, run, v) {
  const host = hostOf(run, v.name);
  switch (v.kind) {
    case 'app': return gwRequests(o, `/api/probe/${v.name}?`).length > 0;
    case 'dns': return dnsHits(o, host).length > 0;
    case 'preconnect': return dnsHits(o, host).length > 0 || sinkHits(o, host).length > 0;
    default: return sinkHits(o, host).length > 0 || dnsHits(o, host).length > 0;
  }
}

function passiveBlocked(visitResult, v) {
  const { observed: o, run, pwned, cookies, ready } = visitResult;
  if (!ready) return false;
  if (v.kind === 'cookie') return cookies !== null && !cookies.some((c) => c.name === `injected_${run}`);
  const quiet = !passiveAttempted(o, run, v);
  return v.kind === 'script' ? quiet && !pwned.includes(v.name) : quiet;
}

function seen(visitResult, v) {
  const { observed: o, run } = visitResult;
  const host = hostOf(run, v.name);
  if (!visitResult.ready) return 'visit not ready';
  const http = sinkRequests(o, host).length;
  const tls = sinkHits(o, host).length - http;
  return `seen: dns=${dnsHits(o, host).length} tls=${tls} http=${http} probe=${gwRequests(o, `/api/probe/${v.name}?`).length}`;
}

function passiveReported(visitResult, v) {
  if (!visitResult.ready) return false;
  const r = reports(visitResult.observed);
  const directiveMatches = (x) => x.directive.split(' ')[0] === v.directive
    || (v.directive === 'default-src' && x.directive === 'prefetch-src');
  switch (v.kind) {
    case 'remote': return r.some((x) => x.blocked.includes(hostOf(visitResult.run, v.name)));
    case 'app': return r.some((x) => (x.blocked === visitResult.app || x.blocked.startsWith(`${visitResult.app}/`)) && directiveMatches(x));
    case 'data': return r.some((x) => (x.blocked === '' || x.blocked.startsWith('data')) && directiveMatches(x));
    case 'base': return r.some((x) => directiveMatches(x));
    default: return null;
  }
}

const REPORTABLE = new Set(['remote', 'app', 'data', 'base']);

// `attemptedInControl`: the vectors the browser attempts in the matching control (the same
// sandbox without any CSP); a vector it never attempts there cannot be blocked or reported here,
// and its PASS says so (vacuous).
function judgePassive(prefix, visitResult, attemptedInControl, { strictKinds = null } = {}) {
  for (const v of passive) {
    const blocked = passiveBlocked(visitResult, v);
    const vacuous = attemptedInControl && !attemptedInControl.has(v.name) ? 'vacuous: not attempted without defences' : '';
    if (strictKinds && !strictKinds.has(v.kind)) {
      info(`${prefix}.blocked.${v.name}`, blocked ? 'blocked' : 'NOT blocked (layer does not govern it)');
    } else {
      check(`${prefix}.blocked.${v.name}`, blocked, blocked ? vacuous : seen(visitResult, v));
    }
    // CSP reports are monitoring only: a browser may block a speculative load without reporting
    // it, so a missing report is recorded, not failed.
    if (REPORTABLE.has(v.kind)) {
      info(`${prefix}.reported.${v.name}`, passiveReported(visitResult, v) ? 'reported' : `not reported (${seen(visitResult, v)})`);
    }
  }
  printReports(prefix, visitResult.observed);
}

function visitInfo(prefix, v) {
  if (v.gotoError || !v.ready || v.clickError) info(`${prefix}.load`, `goto=${v.gotoError || 'ok'} ready=${v.ready} click=${v.clickError || 'ok'}`);
}

// ------------------------------------------------------------------------------------------
// Controls (one instance): no CSP and a permissive sandbox show that each detector fires; the
// CSP-only and inline-style ablations show what each layer blocks on its own; the scripts mode
// tests the sandbox's origin isolation with scripts running.
async function controls(inst) {
  const p = 'control';
  const open = await visit(inst, 'open', 'passive', { relax: true });
  visitInfo(`${p}.passive`, open);
  const attempted = new Set(passive.filter((v) => passiveAttempted(open.observed, open.run, v) || (v.kind === 'cookie' && !passiveBlocked(open, v)) || open.pwned.includes(v.name)).map((v) => v.name));
  for (const v of passive) info(`${p}.attempted.${v.name}`, attempted.has(v.name) ? 'yes' : 'no');
  // The production sandbox (no allow-* flag) without any CSP: what the browser still attempts
  // when scripts cannot run, the baseline for the production and inline-style checks.
  const bare = await visit(inst, 'sandbox-only', 'passive', { relax: true });
  visitInfo(`${p}.sandbox_only`, bare);
  const attemptedSandboxed = new Set(passive.filter((v) => passiveAttempted(bare.observed, bare.run, v) || (v.kind === 'cookie' && !passiveBlocked(bare, v))).map((v) => v.name));
  for (const v of passive) info(`${p}.attempted_in_sandbox.${v.name}`, attemptedSandboxed.has(v.name) ? 'yes' : 'no');
  check(`${p}.sandbox_only.no_script_ran`, bare.pwned.length === 0, bare.pwned.join(','));
  const core = passive.filter((v) => ['remote', 'inline-style', 'script'].includes(v.kind) && ['img', 'iframe', 'link-stylesheet', 'script-src', 'style-background', 'css-exfil', 'script-inline', 'handler-onerror'].includes(v.name));
  for (const v of core) check(`${p}.detector_fires.${v.name}`, attempted.has(v.name));

  const singlesOpen = {};
  for (const name of ['meta-refresh', 'click-top', 'click-blank', 'click-javascript', 'click-ping', 'click-base', 'click-link', 'form-get', 'form-post-app', 'click-app-get']) {
    singlesOpen[name] = await visit(inst, 'open', name, { click: name !== 'meta-refresh', waitMs: name === 'meta-refresh' ? 1500 : 500, relax: true });
    visitInfo(`${p}.${name}`, singlesOpen[name]);
  }
  const hit = (v, vector) => sinkRequests(v.observed, hostOf(v.run, vector)).length > 0;
  for (const [name, v] of Object.entries(singlesOpen)) check(`${p}.rendered.${name}`, v.ready);
  check(`${p}.detector_fires.meta-refresh`, hit(singlesOpen['meta-refresh'], 'meta-refresh'));
  check(`${p}.detector_fires.click-top`, hit(singlesOpen['click-top'], 'click-top') && singlesOpen['click-top'].topUrl.includes(attackerSuffix));
  check(`${p}.detector_fires.click-blank`, singlesOpen['click-blank'].popups > 0);
  info(`${p}.attempted.click-javascript_in_frame`, singlesOpen['click-javascript'].pwned.includes('click-javascript')
    ? 'yes' : 'no (a javascript: link did not run in the framed document even with allow-scripts and no content CSP)');
  check(`${p}.detector_fires.click-javascript_top_level`, await javascriptLinkRunsTopLevel(inst));
  info(`${p}.attempted.click-ping`, hit(singlesOpen['click-ping'], 'click-ping') ? 'yes' : 'no (hyperlink auditing off in this browser)');
  check(`${p}.detector_fires.click-base`, hit(singlesOpen['click-base'], 'click-base'));
  check(`${p}.detector_fires.click-link`, hit(singlesOpen['click-link'], 'click-link'));
  check(`${p}.detector_fires.form-get`, hit(singlesOpen['form-get'], 'form-get'));
  const post = singlesOpen['form-post-app'];
  const postEntries = gwRequests(post.observed, '/api/action?');
  check(`${p}.form-post-app.reaches_api_without_side_effect`, postEntries.length > 0 && post.after === post.before,
    postEntries.map((e) => `cookie=${e.session_cookie} site=${e.sec_fetch_site} outcome=${e.outcome}`).join(';'));
  const appGet = singlesOpen['click-app-get'];
  const appGetEntries = gwRequests(appGet.observed, '/api/state?');
  check(`${p}.click-app-get.detector_fires`, appGetEntries.length > 0,
    appGetEntries.map((e) => `cookie=${e.session_cookie} site=${e.sec_fetch_site} dest=${e.sec_fetch_dest}`).join(';'));
  for (const name of ['form-post-app', 'click-app-get']) {
    const started = contentStarted(singlesOpen[name].observed);
    check(`${p}.${name}.content_started_requests_cookieless_cross_site`, started.length > 0 && cookielessCrossSite(started), describe(started));
  }

  // Scripts running in the sandbox without allow-same-origin: origin isolation on its own.
  const iso = await visit(inst, 'scripts', 'isolation', { waitMs: 1500 });
  visitInfo('isolation', iso);
  check('isolation.rendered', iso.ready);
  const results = {};
  for (const e of sinkRequests(iso.observed, hostOf(iso.run, 'isolation'))) {
    const query = e.target.split('?')[1] || '';
    for (const pair of query.split('&')) {
      const [k, val] = pair.split('=');
      if (k) results[decodeURIComponent(k)] = decodeURIComponent(val || '');
    }
  }
  info('isolation.results', JSON.stringify(results));
  const denied = (k) => String(results[k] || '').startsWith('denied');
  check('isolation.script_ran', results.script === 'ran');
  for (const k of ['parent_dom', 'parent_storage', 'own_storage', 'own_cookie', 'top_location_read']) {
    check(`isolation.${k}_denied`, denied(k), results[k] || 'no result');
  }
  check('isolation.window_open_denied', denied('window_open') && iso.popups === 0
    && sinkHits(iso.observed, `${iso.run}-popup.${attackerSuffix}`).length === 0, results.window_open || 'no result');
  check('isolation.top_navigation_denied', !iso.topUrl.includes(attackerSuffix)
    && sinkHits(iso.observed, `${iso.run}-topnav.${attackerSuffix}`).length === 0, results.top_navigate || 'no result');
  check('isolation.credentialed_read_denied', denied('fetch_read'), results.fetch_read || 'no result');
  const isoAction = gwRequests(iso.observed, '/api/action?');
  check('isolation.cross_origin_post_has_no_side_effect', iso.after === iso.before && !isoAction.some((e) => e.outcome === 'mutated'),
    isoAction.map((e) => `cookie=${e.session_cookie} site=${e.sec_fetch_site} outcome=${e.outcome}`).join(';'));
  const isoState = gwRequests(iso.observed, '/api/state?');
  const isoStarted = contentStarted(iso.observed);
  check('isolation.content_started_requests_cookieless_cross_site', isoStarted.length >= 2 && cookielessCrossSite(isoStarted), describe(isoStarted));
  info('isolation.fetch_requests', [...isoState, ...isoAction].map((e) => `${e.method} ${e.target.split('?')[0]} cookie=${e.session_cookie} site=${e.sec_fetch_site} mode=${e.sec_fetch_mode}`).join('; ') || 'none reached the Gateway');
  check('isolation.postmessage_arrives_from_opaque_origin', iso.attrs['message-origin'] === 'null', `origin=${iso.attrs['message-origin']}`);

  // CSP alone (no sandbox).
  const cspOnly = await visit(inst, 'csp-only', 'passive');
  visitInfo('csp_layer.passive', cspOnly);
  judgePassive('csp_layer', cspOnly, attempted, { strictKinds: new Set(['remote', 'app', 'inline-style', 'script', 'data', 'base']) });
  const cspScriptReports = reports(cspOnly.observed).filter((x) => x.blocked === 'inline' && x.directive.startsWith('script-src'));
  info('csp_layer.inline_script_reports', String(cspScriptReports.length));
  for (const name of ['form-get', 'click-javascript']) {
    const v = await visit(inst, 'csp-only', name, { click: true, waitMs: 500 });
    visitInfo(`csp_layer.${name}`, v);
    const blocked = v.ready && (name === 'form-get' ? !hit(v, 'form-get') : !v.pwned.includes('click-javascript'));
    check(`csp_layer.blocked.${name}`, blocked);
    if (name === 'form-get') info('csp_layer.reported.form-get', reports(v.observed).some((x) => x.directive.startsWith('form-action')) ? 'reported' : 'not reported');
  }
  // Without the sandbox the content has a real origin, same-site with the client: what a
  // navigation the content starts toward the client's API carries.
  const cspGet = await visit(inst, 'csp-only', 'click-app-get', { click: true, waitMs: 500, relax: true });
  const cspStarted = contentStarted(cspGet.observed);
  check('csp_layer.click-app-get.content_started_request_same_site_with_cookie', cspGet.ready && cspStarted.length > 0
    && cspStarted.every((e) => e.session_cookie && e.sec_fetch_site === 'same-site'), describe(cspStarted));
  for (const name of ['meta-refresh', 'click-top', 'click-blank']) {
    const v = await visit(inst, 'csp-only', name, { click: name !== 'meta-refresh', waitMs: name === 'meta-refresh' ? 1500 : 500 });
    const escaped = hit(v, name) || v.popups > 0;
    info(`csp_layer.navigation.${name}`, escaped ? 'NOT blocked by CSP alone (the sandbox is needed)' : 'blocked');
  }

  // The vectors left unreported in the passive fixture, served alone, in the production sandbox
  // without CSP and then in production: what is fetched and what is reported, per origin.
  for (const vector of ['script-src', 'link-preload-font']) {
    const fixture = `${catalogue.fixtures.only_prefix}${vector}`;
    const vdef = passive.find((x) => x.name === vector);
    for (const mode of ['sandbox-only', 'unsanitized', 'prod']) {
      const one = await visit(inst, mode, fixture, { relax: true });
      check(`single.${mode}.${vector}.rendered`, one.ready);
      info(`single.${mode}.${vector}.observed`, seen(one, vdef));
      printReports(`single.${mode}.${vector}`, one.observed);
      if (mode !== 'sandbox-only') check(`single.${mode}.${vector}.blocked`, passiveBlocked(one, vdef), seen(one, vdef));
    }
  }

  // Production CSP with inline styles allowed.
  const styled = await visit(inst, 'inline-style', 'passive');
  visitInfo('inline_style.passive', styled);
  judgePassive('inline_style', styled, attemptedSandboxed, { strictKinds: new Set(['remote', 'app', 'inline-style', 'script', 'data', 'base']) });

  // The production sandbox and content CSP without the client's frame-src: navigations the frame
  // itself starts (meta refresh, links, forms) are then up to the sandbox and the content CSP.
  const layer = {};
  for (const name of ['meta-refresh', 'click-link', 'click-base', 'form-get', 'form-post-app', 'click-app-get']) {
    layer[name] = await visit(inst, 'unsanitized', name, { click: name !== 'meta-refresh', waitMs: name === 'meta-refresh' ? 1500 : 500, relax: true });
    visitInfo(`sandbox_layer.${name}`, layer[name]);
  }
  const navigated = (s, vector) => sinkRequests(s.observed, hostOf(s.run, vector)).length > 0;
  for (const [name, v] of Object.entries(layer)) check(`sandbox_layer.rendered.${name}`, v.ready);
  info('sandbox_layer.meta-refresh', navigated(layer['meta-refresh'], 'meta-refresh') ? 'frame navigated to the attacker' : 'blocked');
  info('sandbox_layer.click-link', navigated(layer['click-link'], 'click-link') ? 'frame navigated to the attacker on a click' : 'blocked');
  check('sandbox_layer.click-link.stays_sandboxed', sinkHits(layer['click-link'].observed, hostOf(layer['click-link'].run, 'sink-script')).length === 0,
    `attacker page image loaded: ${sinkRequests(layer['click-link'].observed, hostOf(layer['click-link'].run, 'sink-img')).length > 0}`);
  check('sandbox_layer.blocked.click-base', !navigated(layer['click-base'], 'click-base'));
  check('sandbox_layer.blocked.form-get', !navigated(layer['form-get'], 'form-get'));
  const layerPost = layer['form-post-app'];
  check('sandbox_layer.blocked.form-post-app', gwRequests(layerPost.observed, '/api/action?').length === 0 && layerPost.after === layerPost.before);
  const layerGet = layer['click-app-get'];
  const layerGetRequests = gwRequests(layerGet.observed, '/api/state?');
  check('sandbox_layer.click-app-get.no_side_effect', layerGet.after === layerGet.before,
    layerGetRequests.map((e) => `reached the API: cookie=${e.session_cookie} site=${e.sec_fetch_site} dest=${e.sec_fetch_dest}`).join(';') || 'did not reach the API');
  const layerStarted = contentStarted(layerGet.observed);
  check('sandbox_layer.click-app-get.content_started_requests_cookieless_cross_site', layerStarted.length > 0 && cookielessCrossSite(layerStarted), describe(layerStarted));
  check('sandbox_layer.click-app-get.not_rendered', !layerGet.frames.some((f) => f.url.startsWith(`${layerGet.app}/api/state`) && f.content.includes('"mutations"')));
  return attemptedSandboxed;
}

// The raw click-javascript fixture opened as a top-level document: shows that the marker detector
// sees a javascript: link that runs.
async function javascriptLinkRunsTopLevel(inst) {
  const page = await ctx.newPage();
  try {
    await page.goto(`https://${inst.name}:${catalogue.content_port}/raw/click-javascript?run=${nextRun()}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.locator('#go').click({ timeout: 5000 });
    await sleep(1000);
    return (await page.locator('body').getAttribute('data-pwned-click-javascript', { timeout: 2000 })) === '1';
  } catch {
    return false;
  } finally {
    await within(page.close(), 5000, null);
    await within(ctx.clearCookies(), 5000, null);
  }
}

// ------------------------------------------------------------------------------------------
// Production configuration on one instance name.
async function production(inst, attempted) {
  const p = `${inst.option}.${inst.deployment}`;
  const passiveVisit = await visit(inst, 'prod', 'passive');
  visitInfo(`${p}.passive`, passiveVisit);
  const v = passiveVisit;
  check(`${p}.ac1.tls_trusted`, !v.gotoError && v.mainStatus === 200, v.gotoError || `status ${v.mainStatus}`);
  const appCsp = v.mainHeaders['content-security-policy'] || '';
  check(`${p}.ac1.app_csp_strict`, /'nonce-[0-9a-f]{32}'/.test(appCsp) && appCsp.includes("require-trusted-types-for 'script'")
    && appCsp.includes('trusted-types lit-html') && appCsp.includes("frame-ancestors 'none'")
    && appCsp.includes(`frame-src https://${inst.name}:${catalogue.content_port}`) && !appCsp.includes('unsafe'));
  check(`${p}.ac1.app_nonce_script_ran`, v.attrs['nonce-ran'] === '1');
  check(`${p}.ac1.app_unnonced_script_blocked`, v.attrs['unnonced-ran'] === null);
  check(`${p}.ac1.app_trusted_types_enforced`, String(v.attrs.tt).startsWith('enforced') && String(v.attrs['tt-policy']).startsWith('refused'),
    `tt=${v.attrs.tt} policy=${v.attrs['tt-policy']}`);
  const session = await sessionCookie(inst);
  check(`${p}.ac1.session_cookie_attributes`, session.ok, session.detail);
  check(`${p}.ac1.session_cookie_hidden_from_script`, v.attrs['cookie-visible'] === 'no');
  const expectedCsp = catalogue.content_csp.replace('NAME', inst.name);
  const contentHeaders = v.contentHeaders || {};
  check(`${p}.ac1.content_csp_header`, contentHeaders['content-security-policy'] === expectedCsp
    && catalogue.content_headers.every((h) => contentHeaders[h.name] === h.value),
  v.contentHeaders ? '' : 'no content response seen');
  const fixtureRequests = gwRequests(v.observed, '/content/passive?');
  const viaExpected = inst.deployment === 'direct'
    ? fixtureRequests.every((e) => e.listener === 'content-tls')
    : fixtureRequests.every((e) => e.listener === 'content-plain' && e.peer === layout.deployments[inst.deployment]);
  check(`${p}.ac3.served_via_${inst.deployment}`, fixtureRequests.length > 0 && viaExpected,
    fixtureRequests.map((e) => `${e.listener} from ${e.peer}`).join(';'));
  check(`${p}.ac1.iframe_renders`, (v.markerText || '').includes('external content passive'));
  const doc = fixtureRequests.find((e) => e.sec_fetch_dest === 'iframe') || fixtureRequests[0];
  check(`${p}.ac1.content_request_same_site_with_cookie`, Boolean(doc) && doc.session_cookie && doc.sec_fetch_site === 'same-site',
    doc ? `cookie=${doc.session_cookie} site=${doc.sec_fetch_site} dest=${doc.sec_fetch_dest}` : 'no request');
  check(`${p}.ac1.no_script_ran`, v.pwned.length === 0, v.pwned.join(','));
  check(`${p}.ac1.content_sets_no_cookie`, Boolean(v.contentHeaders) && !('set-cookie' in v.contentHeaders));
  check(`${p}.ac2.cookie_jar_read`, v.cookies !== null);
  judgePassive(`${p}.ac2`, v, attempted);
  // The same content without the sanitizer (control): what CSP and the sandbox alone let through.
  const raw = await visit(inst, 'unsanitized', 'passive');
  visitInfo(`${p}.unsanitized`, raw);
  check(`${p}.unsanitized.rendered`, raw.ready);
  judgePassive(`${p}.unsanitized.ac2`, raw, attempted);

  const singles = {};
  for (const name of ['meta-refresh', 'click-top', 'click-blank', 'click-javascript', 'click-ping', 'click-base', 'click-link', 'form-get', 'form-post-app', 'click-app-get', 'isolation']) {
    singles[name] = await visit(inst, 'prod', name, { click: !['meta-refresh', 'isolation'].includes(name), waitMs: ['meta-refresh', 'isolation'].includes(name) ? 1500 : 500 });
    visitInfo(`${p}.${name}`, singles[name]);
  }
  for (const [name, s] of Object.entries(singles)) check(`${p}.ac1.rendered.${name}`, s.ready);
  const quiet = (s, vector) => sinkRequests(s.observed, hostOf(s.run, vector)).length === 0;
  const notAt = (s) => s.frames.every((f) => !f.url.includes(attackerSuffix));
  check(`${p}.ac2.blocked.meta-refresh`, quiet(singles['meta-refresh'], 'meta-refresh') && notAt(singles['meta-refresh']));
  check(`${p}.ac1.blocked.click-top`, quiet(singles['click-top'], 'click-top') && !singles['click-top'].topUrl.includes(attackerSuffix));
  check(`${p}.ac1.blocked.click-blank`, quiet(singles['click-blank'], 'click-blank') && singles['click-blank'].popups === 0);
  check(`${p}.ac1.blocked.click-javascript`, !singles['click-javascript'].pwned.includes('click-javascript'));
  check(`${p}.ac2.blocked.click-ping`, quiet(singles['click-ping'], 'click-ping'));
  check(`${p}.ac2.blocked.click-base`, quiet(singles['click-base'], 'click-base'));
  check(`${p}.ac2.blocked.form-get`, quiet(singles['form-get'], 'form-get'));
  const post = singles['form-post-app'];
  check(`${p}.ac1.blocked.form-post-app`, gwRequests(post.observed, '/api/action?').length === 0 && post.after === post.before);
  const link = singles['click-link'];
  check(`${p}.ac1.click-link.stays_sandboxed`, sinkHits(link.observed, hostOf(link.run, 'sink-script')).length === 0);
  info(`${p}.click-link.navigation`, `frame navigated to the attacker: ${sinkRequests(link.observed, hostOf(link.run, 'click-link')).length > 0}, attacker page image loaded: ${sinkRequests(link.observed, hostOf(link.run, 'sink-img')).length > 0}`);
  const appGet = singles['click-app-get'];
  check(`${p}.ac1.click-app-get.no_side_effect`, appGet.after === appGet.before);
  check(`${p}.ac1.click-app-get.not_rendered`, !appGet.frames.some((f) => f.url.startsWith(`${v.app}/api/state`) && f.content.includes('"mutations"')));
  info(`${p}.click-app-get.requests`, gwRequests(appGet.observed, '/api/state?').map((e) => `cookie=${e.session_cookie} site=${e.sec_fetch_site} dest=${e.sec_fetch_dest}`).join(';') || 'none');
  const iso = singles.isolation;
  check(`${p}.ac1.blocked.isolation-script`, sinkHits(iso.observed, hostOf(iso.run, 'isolation')).length === 0
    && gwRequests(iso.observed, '/api/').length === 0);
  const nolink = await visit(inst, 'unsanitized', catalogue.fixtures.without_links.fixture);
  visitInfo(`${p}.nolink`, nolink);
  check(`${p}.ac2.nolink.rendered`, nolink.ready);
  check(`${p}.ac2.nolink.no_attacker_dns_tls_or_request`, nolink.ready && nolink.observed.dns.length === 0 && nolink.observed.sink.length === 0,
    `dns=${nolink.observed.dns.length} sink=${nolink.observed.sink.length}`);
  const all = [v, ...Object.values(singles), raw, nolink];
  const started = all.flatMap((s) => contentStarted(s.observed));
  check(`${p}.ac1.content_started_requests_cookieless_cross_site`, cookielessCrossSite(started), started.length ? describe(started) : 'none reached the API');
  check(`${p}.ac1.no_postmessage`, all.every((s) => s.attrs.messages === null));
  check(`${p}.ac1.no_state_change`, all.every((s) => s.after === s.before));
}

// Retried like `visit`, on a navigation timeout only.
async function sessionCookie(inst) {
  for (let attempt = 1; ; attempt += 1) {
    const result = await sessionCookieOnce(inst);
    if (!result.detail.startsWith('page.goto: Timeout') || attempt === 3) return result;
    info('retry', `${inst.name} session cookie attempt=${attempt}: ${result.detail}`);
    await restartBrowser();
  }
}

async function sessionCookieOnce(inst) {
  // A fresh page logs in; the cookie jar is read before the page is closed.
  const page = await ctx.newPage();
  try {
    await page.goto(`https://${inst.name}/?mode=prod&fixture=passive&run=${nextRun()}`, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForSelector('html[data-login]', { state: 'attached', timeout: 15000 });
    const c = (await ctx.cookies(`https://${inst.name}/`)).find((x) => x.name === catalogue.session_cookie);
    if (!c) return { ok: false, detail: 'no session cookie' };
    const detail = `domain=${c.domain} path=${c.path} secure=${c.secure} httpOnly=${c.httpOnly} sameSite=${c.sameSite}`;
    return { ok: c.domain === inst.name && c.path === '/' && c.secure && c.httpOnly && c.sameSite === 'Strict', detail };
  } catch (e) {
    return { ok: false, detail: e.message.split('\n')[0] };
  } finally {
    await within(page.close(), 5000, null);
    await within(ctx.clearCookies(), 5000, null);
  }
}

// ------------------------------------------------------------------------------------------
const launch = () => engine.launchPersistentContext(`/profiles/${engineName}`, { headless: true });
let ctx = await launch();
// After a navigation timeout the browser is restarted on the same profile before the retry: with
// Firefox 155 a timed-out navigation left later navigations hanging too.
async function restartBrowser() {
  await within(ctx.close(), 10000, null);
  ctx = await launch();
}
try {
  const probe = await ctx.newPage();
  info('user_agent', await probe.evaluate(() => navigator.userAgent));
  await probe.close();
  const controlInstance = layout.instances.find((i) => i.deployment === 'direct');
  info('controls_instance', controlInstance.name);
  const attempted = await controls(controlInstance);
  for (const inst of layout.instances) {
    await production(inst, attempted);
  }
} finally {
  await ctx.close();
}
process.exit(failed);
