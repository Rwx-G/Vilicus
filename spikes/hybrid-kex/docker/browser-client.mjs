// Loads https://server:8443/client/<name> in one Playwright browser and prints the browser
// version and the server's record of the connection.
// Usage: node browser-client.mjs <chromium|firefox|webkit> <client-name>
import { chromium, firefox, webkit } from 'playwright';

const engines = { chromium, firefox, webkit };
const [engineName, clientName] = process.argv.slice(2);
const engine = engines[engineName];
if (!engine || !clientName) {
  console.error('usage: node browser-client.mjs <chromium|firefox|webkit> <client-name>');
  process.exit(2);
}

const browser = await engine.launch({ headless: true });
try {
  // The test CA is not in the browser's trust store; skipping the certificate check does not
  // change the key exchange, which completes before certificate validation matters.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const response = await page.goto(`https://server:8443/client/${clientName}`);
  const body = await response.text();
  const userAgent = await page.evaluate(() => navigator.userAgent);
  console.log(`BROWSER engine=${engineName} version=${browser.version()} ua="${userAgent}"`);
  process.stdout.write(body);
} finally {
  await browser.close();
}
