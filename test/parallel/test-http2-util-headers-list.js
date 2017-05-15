// Flags: --expose-internals
'use strict';

// Tests the internal utility function that is used to prepare headers
// to pass to the internal binding layer.

const common = require('../common');
const assert = require('assert');
const { mapToHeaders } = require('internal/http2/util');

{
  const headers = {
    'abc': 1,
    ':status': 200,
    ':path': 'abc',
    'xyz': [1, '2', { toString() { return '3'; } }, 4]
  };

  assert.deepStrictEqual(mapToHeaders(headers), [
    [ ':path', 'abc' ],
    [ ':status', '200' ],
    [ 'abc', '1' ],
    [ 'xyz', '1' ],
    [ 'xyz', '2' ],
    [ 'xyz', '3' ],
    [ 'xyz', '4' ]
  ]);
}

{
  const headers = {
    'abc': 1,
    ':path': 'abc',
    ':status': 200,
    'xyz': [1, 2, 3, 4]
  };

  assert.deepStrictEqual(mapToHeaders(headers), [
    [ ':status', '200' ],
    [ ':path', 'abc' ],
    [ 'abc', '1' ],
    [ 'xyz', '1' ],
    [ 'xyz', '2' ],
    [ 'xyz', '3' ],
    [ 'xyz', '4' ]
  ]);
}

{
  const headers = {
    'abc': 1,
    ':path': 'abc',
    'xyz': [1, 2, 3, 4],
    '': 1,
    ':status': 200,
    [Symbol('test')]: 1 // Symbol keys are ignored
  };

  assert.deepStrictEqual(mapToHeaders(headers), [
    [ ':status', '200' ],
    [ ':path', 'abc' ],
    [ 'abc', '1' ],
    [ 'xyz', '1' ],
    [ 'xyz', '2' ],
    [ 'xyz', '3' ],
    [ 'xyz', '4' ]
  ]);
}

{
  // Only own properties are used
  const base = { 'abc': 1 };
  const headers = Object.create(base);
  headers[':path'] = 'abc';
  headers.xyz = [1, 2, 3, 4];
  headers.foo = [];
  headers[':status'] = 200;

  assert.deepStrictEqual(mapToHeaders(headers), [
    [ ':status', '200' ],
    [ ':path', 'abc' ],
    [ 'xyz', '1' ],
    [ 'xyz', '2' ],
    [ 'xyz', '3' ],
    [ 'xyz', '4' ]
  ]);
}

assert.throws(() => mapToHeaders({':status': [1, 2, 3]}),
              common.expectsError({
                code: 'ERR_HTTP2_PSEUDO_HEADERS_SINGLE_VALUE',
                message: /^HTTP\/2 pseudo-headers must have a single value$/
              }));

assert.throws(() => mapToHeaders({':path': [1, 2, 3]}),
              common.expectsError({
                code: 'ERR_HTTP2_PSEUDO_HEADERS_SINGLE_VALUE',
                message: /^HTTP\/2 pseudo-headers must have a single value$/
              }));

['connection', 'upgrade', 'http2-settings', 'te'].forEach((i) => {
  assert.throws(() => mapToHeaders({[i]: 'abc'}),
                common.expectsError({
                  code: 'ERR_HTTP2_INVALID_CONNECTION_HEADERS',
                  message: /^HTTP\/1 Connection specific headers are forbidden$/
                }));
});

assert.doesNotThrow(() => mapToHeaders({ te: 'trailers' }));
