'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

// Http2ServerResponse should have a statusCode property

const server = h2.createServer();
server.listen(0, common.mustCall(function() {
  const port = server.address().port;
  server.once('request', common.mustCall(function(request, response) {
    const expectedDefaultStatusCode = 200;
    const realStatusCodes = {
      continue: 100,
      ok: 200,
      multipleChoices: 300,
      badRequest: 400,
      internalServerError: 500
    };
    const fakeStatusCodes = {
      tooLow: 99,
      tooHigh: 1000,
      backwardsCompatibility: 999
    };

    assert.strictEqual(response.statusCode, expectedDefaultStatusCode);

    assert.doesNotThrow(function() {
      response.statusCode = realStatusCodes.ok;
      response.statusCode = realStatusCodes.multipleChoices;
      response.statusCode = realStatusCodes.badRequest;
      response.statusCode = realStatusCodes.internalServerError;
      response.statusCode = fakeStatusCodes.backwardsCompatibility;
    });

    assert.throws(function() {
      response.statusCode = realStatusCodes.continue;
    }, RangeError);
    assert.throws(function() {
      response.statusCode = fakeStatusCodes.tooLow;
    }, RangeError);
    assert.throws(function() {
      response.statusCode = fakeStatusCodes.tooHigh;
    }, RangeError);

    response.stream.on('finish', common.mustCall(function() {
      server.close();
    }));
    response.end(' ');
  }));

  const url = `http://localhost:${port}`;
  const client = h2.connect(url, common.mustCall(function() {
    const headers = {
      ':path': '/',
      ':method': 'GET',
      ':scheme': 'http',
      ':authority': `localhost:${port}`
    };
    const request = client.request(headers);
    request.on('end', common.mustCall(function() {
      client.destroy();
    }));
    request.end();
    request.resume();
  }));
}));
