'use strict';
const common = require('../common');
const assert = require('assert');
const fs = require('fs');

// Tests that calling disableRenegotiation on a TLSSocket stops renegotiation.

if (!common.hasCrypto) {
  common.skip('missing crypto');
  return;
}

const h2 = require('http2');

const options = {
  key: fs.readFileSync(`${common.fixturesDir}/keys/agent1-key.pem`),
  cert: fs.readFileSync(`${common.fixturesDir}/keys/agent1-cert.pem`),

};

const server = h2.createSecureServer(options);

const code = 'ERR_HTTP2_SOCKET_TLS_RENEGOTIATION_FORBIDDEN';
const msg = 'TLS Socket renegotiation is forbidden on HTTP/2 connections';

server.listen(0, common.mustCall(() => {

  const client =
    h2.connect(`https://localhost:${server.address().port}`,
               {rejectUnauthorized: false},
               common.mustCall(() => {
                 client.socket.renegotiate(common.mustCall((err) => {
                   assert(err instanceof Error);
                   assert.strictEqual(err.code, code);
                   assert.strictEqual(err.message, msg);
                   server.close();
                   client.destroy();
                 }));
               }));
}));
