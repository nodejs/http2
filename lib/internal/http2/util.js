'use strict';

const errors = require('internal/errors');

function isIllegalConnectionSpecificHeader(name, value) {
  switch (name) {
    case 'connection':
    case 'upgrade':
    case 'http2-settings':
      return true;
    case 'te':
      return value !== 'trailers';
    default:
      return false;
  }
}

function assertIllegalConnectionSpecificHeader(name, value, ctor) {
  if (isIllegalConnectionSpecificHeader(name, value)) {
    var err = new errors.Error('ERR_HTTP2_INVALID_CONNECTION_HEADERS');
    Error.captureStackTrace(err, ctor);
    throw err;
  }
}

function mapToHeaders(map) {
  var ret = [];
  var keys = Object.keys(map);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = map[key];
    var val;
    if (typeof key === 'symbol' || value === undefined || !key)
      continue;
    var isArray = Array.isArray(value);
    if (key[0] === ':') {
      if (isArray) {
        if (value.length > 1)
          throw new errors.Error('ERR_HTTP2_PSEUDO_HEADERS_SINGLE_VALUE');
        value = value[0];
      }
      val = String(value);
      assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
      ret.unshift([key, val]);
    } else {
      if (isArray) {
        for (var k = 0; k < value.length; k++) {
          val = String(value[k]);
          assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
          ret.push([key, val]);
        }
      } else {
        val = String(value);
        assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
        ret.push([key, val]);
      }
    }
  }

  return ret;
}

module.exports = {
  mapToHeaders,
  isIllegalConnectionSpecificHeader
};
