'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');
const NGHTTP2_INTERNAL_ERROR = h2.constants.NGHTTP2_INTERNAL_ERROR;

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall((stream) => {
  stream.on('aborted', common.mustCall());
}));

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });
  const err = new Error('test');
  req.destroy(err);

  req.on('error', common.mustCall((e) => {
    assert.strictEqual(e, err);
  }));

  req.on('streamClosed', common.mustCall((code) => {
    assert.strictEqual(req.rstCode, NGHTTP2_INTERNAL_ERROR);
    assert.strictEqual(code, NGHTTP2_INTERNAL_ERROR);
    server.close();
    client.destroy();
  }));

  req.on('response', common.mustNotCall());
  req.resume();
  req.on('end', common.mustCall());
}));
