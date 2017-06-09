'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

// Only allow one stream to be open at a time
const server = h2.createServer({ settings: { maxConcurrentStreams: 1 }});

// The stream handler must be called only once
server.on('stream', common.mustCall((stream) => {
  stream.respond({ ':status': 200 });
  stream.end('hello world');
}));
server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  let reqs = 2;
  function onEnd() {
    if (--reqs === 0) {
      server.close();
      client.destroy();
    }
  }

  client.on('remoteSettings', common.mustCall((settings) => {
    assert.strictEqual(settings.maxConcurrentStreams, 1);
  }));

  // This one should go through with no problems
  const req1 = client.request({ ':path': '/' });
  req1.on('aborted', common.mustNotCall());
  req1.on('response', common.mustCall());
  req1.resume();
  req1.on('end', onEnd);
  req1.end();

  // This one should be aborted
  const req2 = client.request({ ':path': '/' });
  req2.on('aborted', common.mustCall());
  req2.on('response', common.mustNotCall());
  req2.resume();
  req2.on('end', onEnd);

}));
