'use strict';

// Tests the basic operation of creating a plaintext or TLS
// HTTP2 server. The server does not do anything at this point
// other than start listening.

const common = require('../common');
const assert = require('assert');
const http2 = require('http2');
const path = require('path');
const tls = require('tls');
const net = require('net');
const fs = require('fs');

const options = {
  key: fs.readFileSync(
    path.resolve(common.fixturesDir, 'keys/agent2-key.pem')),
  cert: fs.readFileSync(
    path.resolve(common.fixturesDir, 'keys/agent2-cert.pem'))
};

// There should not be any throws
assert.doesNotThrow(() => {

  const serverTLS = http2.createSecureServer(options, () => {});

  serverTLS.listen(0, common.mustCall(() => serverTLS.close()));

  // There should not be an error event reported either
  serverTLS.on('error', common.mustCall(() => {}, 0));
});

// There should not be any throws
assert.doesNotThrow(() => {
  const server = http2.createServer(options, () => {});

  server.listen(0, common.mustCall(() => server.close()));

  // There should not be an error event reported either
  server.on('error', common.mustCall(() => {}, 0));
});

// createServer and createSecureServer each throw if the
// handler is invalid (is not a function)
const reg = /handler must be a function/;
assert.throws(() => http2.createServer(), reg);
assert.throws(() => http2.createServer({}), reg);
assert.throws(() => http2.createServer({}, ''), reg);
assert.throws(() => http2.createServer({}, true), reg);
assert.throws(() => http2.createServer({}, 1), reg);
assert.throws(() => http2.createServer({}, {}), reg);
assert.throws(() => http2.createServer({}, []), reg);

assert.throws(() => http2.createSecureServer(), reg);
assert.throws(() => http2.createSecureServer({}), reg);
assert.throws(() => http2.createSecureServer({}, ''), reg);
assert.throws(() => http2.createSecureServer({}, true), reg);
assert.throws(() => http2.createSecureServer({}, 1), reg);
assert.throws(() => http2.createSecureServer({}, {}), reg);
assert.throws(() => http2.createSecureServer({}, []), reg);


// Test the plaintext server socket timeout
{
  let client;
  let timer;
  const server = http2.createServer({}, () => {});
  server.on('timeout', common.mustCall(() => {
    clearTimeout(timer);
    server.close();
    if (client)
      client.end();
  }));
  server.setTimeout(common.platformTimeout(1000));
  server.listen(0, common.mustCall(() => {
    const port = server.address().port;
    client = net.connect(port, common.mustCall(() => {}));
  }));
  timer = setTimeout(() => common.fail('server timeout failed'),
                     common.platformTimeout(1100));
}

// Test the secure server socket timeout
{
  let client;
  let timer;
  const server = http2.createSecureServer(options, () => {});
  server.on('timeout', common.mustCall(() => {
    clearTimeout(timer);
    server.close();
    if (client)
      client.end();
  }));
  server.setTimeout(common.platformTimeout(1000));
  server.listen(0, common.mustCall(() => {
    const port = server.address().port;
    client = tls.connect({port: port, rejectUnauthorized: false},
                         common.mustCall(() => {}));
  }));
  timer = setTimeout(() => common.fail('server timeout failed'),
                     common.platformTimeout(1100));
}
