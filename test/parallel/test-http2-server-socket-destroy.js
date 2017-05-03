'use strict';

const common = require('../common');
const h2 = require('http2');
const assert = require('assert');
const body =
  '<html><head></head><body><h1>this is some data</h2></body></html>';

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall(onStream));

function onStream(stream) {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.write(body);
  stream.end();

  const socket = stream.session.socket;

  // When the socket is destroyed, the close events must be triggered
  // on the socket, server and session.
  socket.on('close', common.mustCall());
  server.on('close', common.mustCall());
  stream.session.on('close', common.mustCall(() => server.close()));

  // Also, the aborted event must be triggered on the stream
  stream.on('aborted', common.mustCall());

  assert.notStrictEqual(stream.session, undefined);
  socket.destroy();
  assert.strictEqual(stream.session, undefined);
}

server.listen(0);

server.on('listening', common.mustCall(function() {
  const client = h2.connect(`http://localhost:${this.address().port}`);

  const req = client.request({ ':path': '/' });

  // On the request, aborted and end must be called, response and data must not
  req.on('aborted', common.mustCall());
  req.on('end', common.mustCall());
  req.on('response', common.mustNotCall());
  req.on('data', common.mustNotCall());

  // On the client, the close event must call
  client.on('close', common.mustCall());
  req.end();
}));
