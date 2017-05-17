'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream, headers, flags) {
  let data = '';
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => data += chunk);
  stream.on('end', common.mustCall(() => {
    assert.strictEqual(data, 'some data more data');
  }));
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('hello world');
}

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });
  req.write('some data ');
  req.write('more data');

  req.on('response', common.mustCall());
  req.resume();
  req.on('end', common.mustCall(() => {
    server.close();
    client.destroy();
  }));
  req.end();

}));
