// Flags: --expose-http2
'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');
const NGHTTP2_INTERNAL_ERROR = h2.constants.NGHTTP2_INTERNAL_ERROR;

const server = h2.createServer();

// Do not mustCall the server side callbacks, they may or may not be called
// depending on the OS. The determination is based largely on operating
// system specific timings
server.on('stream', (stream) => {
  stream.on('error', common.expectsError({
    code: 'ERR_HTTP2_STREAM_ERROR',
    type: Error,
    message: 'Stream closed with error code 2'
  }));
  stream.respond({});
  stream.end();
});

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });
  const err = new Error('test');
  req.destroy(err);

  req.on('error', common.mustCall((e) => {
    if (e.code === 'ERR_HTTP2_STREAM_ERROR') {
      common.expectsError({
        code: 'ERR_HTTP2_STREAM_ERROR',
        type: Error,
        message: 'Stream closed with error code 2'
      });
    } else {
      common.expectsError({
        type: Error,
        message: 'test'
      });
    }
  }, 2));

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
