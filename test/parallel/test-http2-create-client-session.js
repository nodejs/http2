'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');
const net = require('net');
const body =
  '<html><head></head><body><h1>this is some data</h2></body></html>';
let pathname;

const server = h2.createServer(common.mustCall(requestListener));

function requestListener(request, response) {
  assert.equal(pathname, request.path);
  assert.equal(pathname, request.url);
  assert.equal(pathname, request.headers[':path']);
}

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream) {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end(body);
}

server.listen(0);

server.on('listening', common.mustCall(function() {
  const socket = net.connect(this.address());

  // TODO mcollina remove on('connect')
  socket.on('connect', function() {
    const client = h2.createClientSession(socket);
    
    pathname = `/${Math.random()}`;

    const headers = {
      ':method': 'GET',
      ':scheme': 'http',
      ':authority': `localhost:${this.address().port}`,
      ':path': pathname
    };

    const req = client.request(headers);

    req.on('response', common.mustCall(function(headers) {
      assert.strictEqual(headers[':status'], '200', 'status code is set');
      assert.strictEqual(headers['content-type'], 'text/html',
                         'content type is set');
      assert(headers['date'], 'there is a date');
    }));

    let data = '';
    req.setEncoding('utf8');
    req.on('data', (d) => data += d);
    req.on('end', common.mustCall(function() {
      assert.strictEqual(body, data);
      server.close();
      socket.destroy();
    }));
    req.end();
  });
}));
