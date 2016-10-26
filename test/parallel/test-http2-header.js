'use strict';

require('../common');
const assert = require('assert');
const HTTP2 = require('http').HTTP2;

assert.throws(() => new HTTP2.Http2Header(),
              /First argument must be a string/);

assert.throws(() => new HTTP2.Http2Header('a'),
              /Second argument must be a string/);

assert.throws(() => new HTTP2.Http2Header('', 'b'),
              /First argument must not be an empty string/);

assert.doesNotThrow(() => new HTTP2.Http2Header('a', ''));

const header = new HTTP2.Http2Header('a', 'b');
assert.strictEqual(header.name, 'a');
assert.strictEqual(header.value, 'b');
assert.strictEqual(header.flags, 0);

header.flags |= HTTP2.constants.NGHTTP2_NV_FLAG_NO_INDEX;

assert.strictEqual(header.flags, HTTP2.constants.NGHTTP2_NV_FLAG_NO_INDEX);
