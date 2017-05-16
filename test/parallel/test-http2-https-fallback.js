'use strict';

const { fixturesDir, mustCall, mustNotCall } = require('../common');
const { strictEqual } = require('assert');
const { join } = require('path');
const { readFileSync } = require('fs');
const { createSecureContext } = require('tls');
const { createSecureServer, connect } = require('http2');
const { get } = require('https');
const { parse } = require('url');

const key = loadKey('agent8-key.pem');
const cert = loadKey('agent8-cert.pem');
const ca = loadKey('fake-startcom-root-cert.pem');

function loadKey(keyname) {
  return readFileSync(
    join(fixturesDir, 'keys', keyname), 'binary');
}

// HTTP/2 & HTTP/1.1 server
{
  const server = createSecureServer(
    { cert, key },
    mustCall((request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({
        alpnProtocol: request.socket.alpnProtocol,
        httpVersion: request.httpVersion
      }));
    }, 2)
  );

  server.listen(0);

  server.on('listening', mustCall(() => {
    const port = server.address().port;
    const origin = `https://localhost:${port}`;
    const clientOptions = { secureContext: createSecureContext({ ca }) };

    let count = 2;

    // HTTP/2 client
    connect(
      origin,
      { secureContext: createSecureContext({ ca }) },
      mustCall((session) => {
        const headers = {
          ':path': '/',
          ':method': 'GET',
          ':scheme': 'https',
          ':authority': `localhost:${port}`
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
          const data = JSON.parse(raw);
          strictEqual(data.alpnProtocol, 'h2');
          strictEqual(data.httpVersion, '2.0');

          session.destroy();
          if (--count === 0) server.close();
        }));
        request.end();
      })
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
          const data = JSON.parse(raw);
          strictEqual(data.alpnProtocol, false);
          strictEqual(data.httpVersion, '1.1');

          if (--count === 0) server.close();
        }));
      })
    );
  }));
}

// HTTP/2-only server
{
  const server = createSecureServer({ cert, key, allowHTTP1: false });

  server.listen(0);

  server.on('listening', mustCall(() => {
    const port = server.address().port;
    const origin = `https://localhost:${port}`;
    const clientOptions = { secureContext: createSecureContext({ ca }) };

    let count = 2;

    // HTTP/2 client
    connect(
      origin,
      { secureContext: createSecureContext({ ca }) },
      mustCall((session) => {
        session.destroy();
        if (--count === 0) server.close();
      })
    );

    // HTTP/1.1 client
    get(Object.assign(parse(origin), clientOptions), mustNotCall())
      .on('error', mustCall(() => {
        if (--count === 0) server.close();
      }));
  }));
}
