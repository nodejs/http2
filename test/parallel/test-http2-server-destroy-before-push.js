'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream, headers, flags) {
  stream.session.destroy();
  assert.throws(() => stream.pushStream({}, common.mustNotCall()),
                common.expectsError({
                  code: 'ERR_HTTP2_INVALID_SESSION',
                  message: /^The session has been destroyed$/
                }));
}

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });

  req.on('response', common.mustNotCall());
  req.resume();
  req.on('end', common.mustCall(() => {
    server.close();
    client.destroy();
  }));
  req.end();

}));
