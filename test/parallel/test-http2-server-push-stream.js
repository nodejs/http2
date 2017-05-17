'use strict';

const common = require('../common');
const assert = require('assert');
const http2 = require('http2');

const server = http2.createServer();
server.on('stream', common.mustCall((stream, headers, flags) => {
  const port = server.address().port;
  if (headers[':path'] === '/') {
    stream.pushStream({
      ':scheme': 'http',
      ':path': '/foobar',
      ':authority': `localhost:${port}`,
    }, (stream, headers) => {
      stream.respond({
        'content-type': 'text/html',
        ':status': 200,
        'x-push-data': 'pushed by server',
      });
      stream.end('pushed by server data');
    });
  }
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('test');
}));

server.listen(0, common.mustCall(() => {
  const port = server.address().port;
  const headers = { ':path': '/' };
  const client = http2.connect(`http://localhost:${port}`);
  const req = client.request(headers);

  client.on('stream', common.mustCall((stream, headers, flags) => {
    assert.strictEqual(headers[':scheme'], 'http');
    assert.strictEqual(headers[':path'], '/foobar');
    assert.strictEqual(headers[':authority'], `localhost:${port}`);
    stream.on('push', common.mustCall((headers, flags) => {
      assert.strictEqual(headers[':status'], 200);
      assert.strictEqual(headers['content-type'], 'text/html');
      assert.strictEqual(headers['x-push-data'], 'pushed by server');
    }));
  }));

  let data = '';

  req.on('data', common.mustCall((d) => data += d));
  req.on('end', common.mustCall(() => {
    assert.strictEqual(data, 'test');
    server.close();
    client.destroy();
  }));
  req.end();
}));
