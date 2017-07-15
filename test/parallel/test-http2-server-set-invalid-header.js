// Flags: --expose-http2
'use strict';

const common = require('../common');
const assert = require('assert');
const http2 = require('http2');
const body =
  'Cannot set HTTP/2 pseudo-headers';

const invalidHeaders = [
  { key: ':status', value: 200 }, 
  { key: ':method', value: 'GET' }, 
  { key: ':path', value: '/' }, 
  { key: ':authority', value: 'example.com' }, 
  { key: ':scheme', value: 'http' }
];

const checkServer = (invalidHeader, value) => {
  const server = http2.createServer((req, res) => {
    res.setHeader('foobar', 'baz');
    res.setHeader('X-POWERED-BY', 'node-test');
    try {
      res.setHeader(invalidHeader, value);
    } catch (e) {
      res.statusCode = 500;
      res.end(e.message);
    }
  });
  
  server.listen(0, common.mustCall(() => {
    const client = http2.connect(`http://localhost:${server.address().port}`);
    const headers = { ':path': '/' };
    const req = client.request(headers);
    req.on('response', common.mustCall((headers) => {
      assert.strictEqual(headers[':status'], 500);
      assert.strictEqual(headers['foobar'], 'baz');
      assert.strictEqual(headers['x-powered-by'], 'node-test');
    }));
  
    let data = '';
    req.on('data', (d) => data += d);
    req.on('end', common.mustCall(() => {
      assert.strictEqual(body, data);
      server.close();
      client.destroy();
    }));
    req.end();
  }));
  server.on('error', common.mustNotCall());
};

invalidHeaders.forEach(({ key, value }) => {
  checkServer(key, value);
});
