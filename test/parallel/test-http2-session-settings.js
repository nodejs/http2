'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

server.on('stream', common.mustCall(onStream));

function assertSettings(settings) {
  assert.strictEqual(typeof settings, 'object');
  assert.strictEqual(typeof settings.headerTableSize, 'number');
  assert.strictEqual(typeof settings.enablePush, 'boolean');
  assert.strictEqual(typeof settings.initialWindowSize, 'number');
  assert.strictEqual(typeof settings.maxFrameSize, 'number');
  assert.strictEqual(typeof settings.maxConcurrentStreams, 'number');
  assert.strictEqual(typeof settings.maxHeaderListSize, 'number');
}

function onStream(stream, headers, flags) {

  assertSettings(stream.session.localSettings);
  assertSettings(stream.session.remoteSettings);

  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('hello world');
}

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const headers = { ':path': '/' };

  const req = client.request(headers);

  // State will only be valid after connect event is emitted
  req.on('connect', common.mustCall(() => {
    assertSettings(client.localSettings);
    assertSettings(client.remoteSettings);
  }));

  req.on('response', common.mustCall());
  req.on('data', common.noop);
  req.on('end', common.mustCall(() => {
    server.close();
    client.destroy();
  }));
  req.end();

}));
