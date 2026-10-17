// E26 rerun of the passive fixtures on Mozilla's own Firefox builds (not Playwright's), driven by
// geckodriver over WebDriver. For every instance name of the layout it loads the production
// `passive` fixture and the link-free variant, and judges each vector only from what the sink,
// the Gateway and the DNS server observed for the run (the browser's DOM is read only to know
// that the content rendered).
// Usage: node branded.mjs <label> <firefox binary> <geckodriver port> <two-letter run prefix>
// Prints `PASS <label>.<check>` or `FAIL <label>.<check>` per check and `INFO` lines.
import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, readFileSync, readdirSync } from 'node:fs';

const [label, binary, port, runPrefix] = process.argv.slice(2);
if (!label || !binary || !port || !/^[a-z]{2}$/.test(runPrefix || '')) {
  console.error('usage: node branded.mjs <label> <firefox binary> <geckodriver port> <run prefix>');
  process.exit(2);
}

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
const getJson = async (url) => (await fetch(url)).json();
const catalogue = await getJson(`${control.gateway}/catalogue`);
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let failed = 0;
function check(name, ok, detail = '') {
  if (!ok) failed = 1;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${label}.${name}${detail ? ` (${detail})` : ''}`);
}
const info = (name, detail) => console.log(`INFO ${label}.${name} ${detail}`);
let counter = 0;
const nextRun = () => `${runPrefix}${String(++counter).padStart(4, '0')}`;

async function observe(run) {
  const q = `log?contains=${run}`;
  const [gw, sink, dns] = await Promise.all([control.gateway, control.sink, control.dns].map((c) => getJson(`${c}/${q}`)));
  return { gw, sink, dns };
}
async function settle(run) {
  await sleep(1500);
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

// A Firefox profile whose NSS database trusts every test CA, as for the Playwright browsers.
const profile = `/tmp/${label}-profile`;
mkdirSync(profile, { recursive: true });
execFileSync('certutil', ['-d', `sql:${profile}`, '-N', '--empty-password']);
for (const file of readdirSync('/pki').filter((f) => /^ca-.*\.crt$/.test(f))) {
  execFileSync('certutil', ['-d', `sql:${profile}`, '-A', '-t', 'C,,', '-n', file, '-i', `/pki/${file}`]);
}

const driver = spawn('geckodriver', ['--port', port], { stdio: 'ignore' });
const wd = async (method, path, body) => {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  if (json.value && json.value.error) throw new Error(`${json.value.error}: ${json.value.message}`);
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
      'moz:firefoxOptions': { binary, args: ['-headless', '-profile', profile] },
    },
  },
});
const base = `/session/${session.sessionId}`;
await wd('POST', `${base}/timeouts`, { pageLoad: 30000 });
info('browser', `${session.capabilities.browserName} ${session.capabilities.browserVersion}`);

const elementId = (found) => Object.values(found)[0];
// Waits until the iframe's marker reads `external content <fixture>`.
async function rendered(fixture) {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    try {
      await wd('POST', `${base}/frame/parent`, {});
      const frame = await wd('POST', `${base}/element`, { using: 'css selector', value: '#external' });
      await wd('POST', `${base}/frame`, { id: frame });
      const marker = await wd('POST', `${base}/element`, { using: 'css selector', value: '#marker' });
      const text = await wd('GET', `${base}/element/${elementId(marker)}/text`);
      await wd('POST', `${base}/frame/parent`, {});
      if (String(text).includes(`external content ${fixture}`)) return true;
    } catch { /* not there yet */ }
    await sleep(250);
  }
  return false;
}

async function visit(inst, mode, fixture) {
  const run = nextRun();
  let error = '';
  try {
    await wd('POST', `${base}/url`, { url: `https://${inst.name}/?mode=${mode}&fixture=${fixture}&run=${run}` });
  } catch (e) {
    error = e.message.split('\n')[0];
  }
  const ready = !error && await rendered(fixture);
  return { run, ready, error, observed: await settle(run) };
}

const hostOf = (run, vector) => `${run}-${vector}.${layout.wildcards[0]}`;
try {
  for (const inst of layout.instances) {
    // `prod` serves the content through the sanitizer; `unsanitized` is the control without it.
    for (const [mode, prefix] of [['prod', `${inst.option}.${inst.deployment}`], ['unsanitized', `${inst.option}.${inst.deployment}.unsanitized`]]) {
      const v = await visit(inst, mode, 'passive');
      check(`${prefix}.rendered.passive`, v.ready, v.error);
      for (const vector of catalogue.fixtures.passive) {
        if (vector.kind === 'cookie' || vector.kind === 'script') continue;
        const host = hostOf(v.run, vector.name);
        const dns = v.observed.dns.filter((e) => e.host === host).length;
        const sink = v.observed.sink.filter((e) => e.host.split(':')[0] === host).length;
        const probe = v.observed.gw.filter((e) => e.target.startsWith(`/api/probe/${vector.name}?`)).length;
        check(`${prefix}.ac2.blocked.${vector.name}`, v.ready && dns + sink + probe === 0, `dns=${dns} sink=${sink} probe=${probe}`);
      }
      const scriptVectors = catalogue.fixtures.passive.filter((x) => x.kind === 'script');
      const scriptContact = scriptVectors.filter((x) => v.observed.sink.some((e) => e.host.startsWith(`${v.run}-${x.name}.`)));
      check(`${prefix}.ac1.no_script_beacon`, v.ready && scriptContact.length === 0, scriptContact.map((x) => x.name).join(','));
    }
    const p = `${inst.option}.${inst.deployment}`;
    const n = await visit(inst, 'unsanitized', catalogue.fixtures.without_links.fixture);
    check(`${p}.rendered.nolink`, n.ready, n.error);
    check(`${p}.ac2.nolink.no_attacker_dns_tls_or_request`, n.ready && n.observed.dns.length === 0 && n.observed.sink.length === 0,
      `dns=${n.observed.dns.length} sink=${n.observed.sink.length}`);
  }
} finally {
  await wd('DELETE', base).catch(() => {});
  driver.kill();
}
process.exit(failed);
