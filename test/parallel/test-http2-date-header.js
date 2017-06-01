'use strict';

const common = require('../common');
const assert = require('assert');
const http2 = require('http2');

const testResBody = 'other stuff!\n';

const server = http2.createServer(common.mustCall((req, res) => {
  assert.ok(!('date' in req.headers),
            'Request headers did not contain a date.');
  res.writeHead(200, {
    'Content-Type': 'text/plain'
  });
  res.end(testResBody);
}));
server.listen(0);

server.on('listening', common.mustCall(function() {
  const client = http2.connect(`http://localhost:${this.address().port}`);

  const headers = { ':path': '/' };
  const req = client.request(headers).setEncoding('utf8');

  req.on('response', common.mustCall((headers) => {
    assert.ok('date' in headers,
              'Response headers contain a date.');

    req.resume();
  }));

  req.on('end', common.mustCall(() => {
    server.close();
    process.exit();
  }));

  req.end();
}));
