// Node's own TLS stack (its bundled OpenSSL) with default options, against the test server.
// Usage: node node-client.mjs <client-name>
import fs from 'node:fs';
import https from 'node:https';

const clientName = process.argv[2];
let keyInfo = null;
const request = https.get(
  {
    host: 'server',
    port: 8443,
    path: `/client/${clientName}`,
    ca: fs.readFileSync('/pki/ca.pem'),
    headers: { 'User-Agent': `node/${process.version}` },
    agent: false,
  },
  (response) => {
    let body = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => {
      body += chunk;
    });
    response.on('end', () => {
      console.log(
        `NODE version=${process.version} openssl=${process.versions.openssl} client_side_key_info=${JSON.stringify(keyInfo)}`,
      );
      process.stdout.write(body);
    });
  },
);
request.on('socket', (socket) => {
  socket.on('secureConnect', () => {
    keyInfo = socket.getEphemeralKeyInfo();
  });
});
request.on('error', (error) => {
  console.error(error);
  process.exit(1);
});
