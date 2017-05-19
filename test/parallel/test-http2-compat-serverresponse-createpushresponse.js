'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

// Push a request & response

const server = h2.createServer();
server.listen(0, common.mustCall(function() {
  const port = server.address().port;
  server.once('request', common.mustCall(function(request, response) {
    assert.ok(response.stream.id % 2 === 1);

    response.write('This is a client-initiated response');
    response.stream.on('finish', common.mustCall(function() {
      server.close();
    }));

    const headers = {
      ':path': '/pushed',
      ':method': 'GET',
      ':scheme': 'http',
      ':authority': `localhost:${port}`
    };

    response.createPushResponse(
      headers,
      common.mustCall(function(error, pushResponse) {
        assert.strictEqual(error, null);
        assert.ok(pushResponse.stream.id % 2 === 0);

        pushResponse.write('This is a server-initiated response');

        pushResponse.end();
        response.end();
      })
    );
  }));

  const url = `http://localhost:${port}`;
  const client = h2.connect(url, common.mustCall(function() {
    const headers = {
      ':path': '/',
      ':method': 'GET',
      ':scheme': 'http',
      ':authority': `localhost:${port}`
    };

    const requestStream = client.request(headers);

    function onStream(pushStream, headers, flags) {
      assert.strictEqual(headers[':path'], '/pushed');
      assert.strictEqual(headers[':method'], 'GET');
      assert.strictEqual(headers[':scheme'], 'http');
      assert.strictEqual(headers[':authority'], `localhost:${port}`);
      assert.strictEqual(flags, h2.constants.NGHTTP2_FLAG_END_HEADERS);

      pushStream.on('data', common.mustCall(function(data) {
        assert.strictEqual(
          data.toString(),
          'This is a server-initiated response'
        );
      }));
    }

    requestStream.session.on('stream', common.mustCall(onStream));

    requestStream.on('response', common.mustCall(function(headers, flags) {
      assert.strictEqual(headers[':status'], 200);
      assert.ok(headers['date']);
      assert.strictEqual(flags, h2.constants.NGHTTP2_FLAG_END_HEADERS);
    }));

    requestStream.on('data', common.mustCall(function(data) {
      assert.strictEqual(
        data.toString(),
        'This is a client-initiated response'
      );
    }));

    requestStream.on('end', common.mustCall(function() {
      client.destroy();
    }));
    requestStream.end();
  }));
}));
