'use strict';

const common = require('../common');
const assert = require('assert');
const path = require('path');
const fs = require('fs');
const tls = require('tls');
const h2 = require('http2');
const body =
  '<html><head></head><body><h1>this is some data</h2></body></html>';

const key = loadKey('agent8-key.pem');
const cert = loadKey('agent8-cert.pem');
const ca = loadKey('fake-startcom-root-cert.pem');

function loadKey(keyname) {
  return fs.readFileSync(path.join(common.fixturesDir, 'keys', keyname), 'binary');
}

const server = h2.createSecureServer({cert, key});

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream) {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  const socket = stream.session.socket;
  stream.end(JSON.stringify({
    servername: socket.servername,
    alpnProtocol: socket.alpnProtocol
  }));
}

server.listen(0);

server.on('listening', common.mustCall(function() {

  const headers = { ':path': '/' };

  const clientOptions = {secureContext: tls.createSecureContext({ca})};
  const client = h2.connect(`https://localhost:${this.address().port}`, clientOptions, function() {
    const req = client.request(headers);

    req.on('response', common.mustCall(function(headers) {
      assert.strictEqual(headers[':status'], '200', 'status code is set');
      assert.strictEqual(headers['content-type'], 'text/html',
                        'content type is set');
      assert(headers['date'], 'there is a date');
    }));

    let data = '';
    req.setEncoding('utf8');
    req.on('data', (d) => data += d);
    req.on('end', common.mustCall(() => {
      const jsonData = JSON.parse(data);
      assert.strictEqual(jsonData.servername, 'localhost');
      assert(jsonData.alpnProtocol === 'h2' || jsonData.alpnProtocol === 'hc');
      server.close();
      client.socket.destroy();
    }));
    req.end();
  });
}));
