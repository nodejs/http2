'use strict';

const { fixturesDir, mustCall } = require('../common');
const { strictEqual } = require('assert');
const { join } = require('path');
const { readFileSync } = require('fs');
const { createSecureContext } = require('tls');
const { createSecureServer } = require('http2');
const { get } = require('https');
const { parse } = require('url');

const key = loadKey('agent8-key.pem');
const cert = loadKey('agent8-cert.pem');
const ca = loadKey('fake-startcom-root-cert.pem');

function loadKey(keyname) {
  return readFileSync(
    join(fixturesDir, 'keys', keyname), 'binary');
}

const server = createSecureServer(
  { cert, key },
  mustCall((request, response) => {
    response.writeHead(200, 'OK', { 'content-type': 'application/json' });
    response.end(JSON.stringify({ alpnProtocol: request.socket.alpnProtocol }));
  })
);

server.listen(0);

server.on('listening', mustCall(() => {
  const clientOptions = Object.assign(
    { secureContext: createSecureContext({ ca }) },
    parse(`https://localhost:${server.address().port}`)
  );

  get(clientOptions, (response) => {
    strictEqual(response.statusCode, 200);
    strictEqual(response.statusMessage, 'OK');
    strictEqual(response.headers['content-type'], 'application/json');

    response.setEncoding('utf8');
    let raw = '';
    response.on('data', (chunk) => { raw += chunk; });
    response.on('end', mustCall(() => {
      const data = JSON.parse(raw);
      strictEqual(data.alpnProtocol, false);

      server.close();
    }));
  });
}));
