'use strict';

const { fixturesDir, mustCall, mustNotCall } = require('../common');
const { strictEqual } = require('assert');
const { join } = require('path');
const { readFileSync } = require('fs');
const { createSecureContext } = require('tls');
const { createSecureServer, connect } = require('http2');
const { get } = require('https');
const { parse } = require('url');

const countdown = (count, done) => () => --count === 0 && done();

function loadKey(keyname) {
  return readFileSync(join(fixturesDir, 'keys', keyname));
}

const key = loadKey('agent8-key.pem');
const cert = loadKey('agent8-cert.pem');
const ca = loadKey('fake-startcom-root-cert.pem');

const clientOptions = { secureContext: createSecureContext({ ca }) };

function onRequest(request, response) {
  const { socket: { alpnProtocol } } = request.httpVersion === '2.0' ?
    request.stream.session : request;
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({
    alpnProtocol,
    httpVersion: request.httpVersion
  }));
}

function onSession(session) {
  const headers = {
    ':path': '/',
    ':method': 'GET',
    ':scheme': 'https',
    ':authority': `localhost:${this.server.address().port}`
  };

  const request = session.request(headers);
  request.on('response', mustCall((headers) => {
    strictEqual(headers[':status'], '200');
    strictEqual(headers['content-type'], 'application/json');
  }));
  request.setEncoding('utf8');
  let raw = '';
  request.on('data', (chunk) => { raw += chunk; });
  request.on('end', mustCall(() => {
    const { alpnProtocol, httpVersion } = JSON.parse(raw);
    strictEqual(alpnProtocol, 'h2');
    strictEqual(httpVersion, '2.0');

    session.destroy();
    this.cleanup();
  }));
  request.end();
}

// HTTP/2 & HTTP/1.1 server
{
  const server = createSecureServer(
    { cert, key, allowHTTP1: true },
    mustCall(onRequest, 2)
  );

  server.listen(0);

  server.on('listening', mustCall(() => {
    const port = server.address().port;
    const origin = `https://localhost:${port}`;

    const cleanup = countdown(2, () => server.close());

    // HTTP/2 client
    connect(
      origin,
      clientOptions,
      mustCall(onSession.bind({ cleanup, server }))
    );

    // HTTP/1.1 client
    get(
      Object.assign(parse(origin), clientOptions),
      mustCall((response) => {
        strictEqual(response.statusCode, 200);
        strictEqual(response.statusMessage, 'OK');
        strictEqual(response.headers['content-type'], 'application/json');

        response.setEncoding('utf8');
        let raw = '';
        response.on('data', (chunk) => { raw += chunk; });
        response.on('end', mustCall(() => {
          const { alpnProtocol, httpVersion } = JSON.parse(raw);
          strictEqual(alpnProtocol, false);
          strictEqual(httpVersion, '1.1');

          cleanup();
        }));
      })
    );
  }));
}

// HTTP/2-only server
{
  const server = createSecureServer(
    { cert, key },
    mustCall(onRequest)
  );

  server.listen(0);

  server.on('listening', mustCall(() => {
    const port = server.address().port;
    const origin = `https://localhost:${port}`;

    const cleanup = countdown(2, () => server.close());

    // HTTP/2 client
    connect(
      origin,
      clientOptions,
      mustCall(onSession.bind({ cleanup, server }))
    );

    // HTTP/1.1 client
    get(Object.assign(parse(origin), clientOptions), mustNotCall())
      .on('error', mustCall(cleanup));
  }));
}
