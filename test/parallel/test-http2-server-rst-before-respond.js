'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream, headers, flags) {
  stream.rstWithCancel();
  stream.additionalHeaders({
    ':status': 123,
    abc: 123
  });
  setImmediate(() => {
    stream.respond({':status': 200});
    stream.end('data');
  });
}

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });

  req.on('headers', common.mustNotCall());

  req.on('streamClosed', common.mustCall((code) => {
    assert.strictEqual(h2.constants.NGHTTP2_CANCEL, code);
    server.close();
    client.destroy();
  }));

  req.on('response', common.mustNotCall());

}));
