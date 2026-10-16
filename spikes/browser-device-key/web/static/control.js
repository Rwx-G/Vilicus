// Spike E22, test-only control page: its CSP allows `eval` and requires no Trusted Types, so
// the probes that report "blocked" and "enforced" on the real pages are shown to report
// "allowed" and "not enforced" when the policy is weaker.

import { probePage, setStatus } from './common.js';

const loadProbe = probePage();
window.e22control = { probe: () => loadProbe };
setStatus('ready');
