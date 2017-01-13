'use strict';

function isIllegalConnectionSpecificHeader(name, value) {
  switch (name) {
    case 'connection':
    case 'upgrade':
    case 'http2-settings':
      return true;
    case 'te':
      return value === 'trailers';
    default:
      return false;
  }
}

function isPseudoHeader(name) {
  return String(name)[0] === ':';
}

function mapToHeaders(map) {
  var keys = Object.keys(map);
  var size = keys.length;
  for (var i = 0; i < keys.length; i++) {
    if (Array.isArray(keys[i])) {
      size += keys[i].length - 1;
    }
  }
  var ret = Array(size);
  var c = 0;

  for (i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = map[key];
    if (Array.isArray(value) && value.length > 0) {
      for (var k = 0; k < value.length; k++) {
        ret[c++] = [key, String(value[k])];
      }
    } else {
      ret[c++] = [key, String(value)];
    }
  }
  return ret;
}

function llistToHeaders(list, count) {
  var ret = [];
  while (!linkedList.isEmpty(list)) {
    var item = linkedList.shift(list);
    ret.push([item[0], item[1], item[2]]);
  }
  return ret;
}

module.exports = {
  mapToHeaders,
  isPseudoHeader,
  isIllegalConnectionSpecificHeader,
  llistToHeaders,
  mapToHeaders
};



/*
onStream stuff
  var request =
    new Http2ServerRequest(stream, options.defaultIncomingOptions);
  var response =
    new Http2ServerResponse(stream, options.defaultOutgoingOptions);

  var headers - stream[kHeaders];

  // Check for the CONNECT method
  var method = headers[constants.HTTP2_HEADER_METHOD];
  if (method === 'CONNECT') {
    if (!server.emit('connect', request, response)) {
      response.statusCode = constants.HTTP_STATUS_METHOD_NOT_ALLOWED;
      response.end();
    }
    return;
  }

  // Check for Expectations
  if (headers.expect !== undefined) {
    if (headers.expect === '100-continue') {
      if (server.listenerCount('checkContinue')) {
        server.emit('checkContinue', request, response);
      } else {
        response.sendContinue();
        server.emit('request', request, response);
      }
    } else if (server.listenerCount('checkExpectation')) {
      server.emit('checkExpectation', request, response);
    } else {
      response.statusCode = constants.HTTP_STATUS_EXPECTATION_FAILED;
      response.end();
    }
    return;
  }

 */
