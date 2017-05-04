'use strict';

const linkedList = require('internal/linkedlist');
const Stream = require('stream');
const Readable = Stream.Readable;
const binding = process.binding('http2');
const {
  isIllegalConnectionSpecificHeader,
} = require('internal/http2/util');
const constants = binding.constants;

const kFinish = Symbol('finish');
const kBeginSend = Symbol('begin-send');
const kState = Symbol('state');
const kStream = Symbol('stream');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kHeaders = Symbol('headers');
const kTrailers = Symbol('trailers');

// Defines and implements an API compatibility layer on top of the core
// HTTP/2 implementation, intended to provide an interface that is as
// close as possible to the current require('http') API

function setHeader(list, name, value) {
  name = String(name).toLowerCase().trim();
  if (isPseudoHeader(name))
    throw new Error('Cannot set HTTP/2 pseudo-headers');
  if (isIllegalConnectionSpecificHeader(name, value))
    throw new Error('Connection-specific HTTP/1 headers are not permitted');
  if (value === undefined || value === null)
    throw new TypeError('Value must not be undefined or null');
  linkedList.append(list, [name, String(value)]);
}

function llistToHeaders(list, count) {
  var ret = {};
  while (!linkedList.isEmpty(list)) {
    var item = list._idlePrev;
    linkedList.remove(item);
    var key = item[0];

    if (ret[key]) {
      ret[key].push(item[1]);
    } else {
      ret[key] = [item[1]];
    }
  }
  return ret;
}

function isPseudoHeader(name) {
  switch (name) {
    case ':status':
      return true;
    case ':method':
      return true;
    case ':path':
      return true;
    case ':authority':
      return true;
    case ':scheme':
      return true;
    default:
      return false;
  }
}

function onStreamData(chunk) {
  var request = this[kRequest];
  if (!request.push(chunk))
    this.pause();
}

function onStreamEnd() {
  // Cause the request stream to end as well.
  var request = this[kRequest];
  request.push(null);
}

function onStreamError(error) {
  var request = this[kRequest];
  request.emit('error', error);
}

function onRequestPause() {
  var stream = this[kStream];
  stream.pause();
}

function onRequestResume() {
  var stream = this[kStream];
  stream.resume();
}

function onRequestDrain() {
  if (this.isPaused())
    this.resume();
}

function onStreamResponseDrain() {
  var response = this[kResponse];
  response.emit('drain');
}

function onStreamResponseError(error) {
  var response = this[kResponse];
  response.emit('error', error);
}

function onStreamClosedRequest() {
  var req = this[kRequest];
  req.push(null);
}

function onStreamClosedResponse() {
  var res = this[kResponse];
  res.writable = false;
  res.emit('finish');
}

function onAborted(hadError, code) {
  if ((this.writable) ||
      (this._readableState && !this._readableState.ended)) {
    this.emit('aborted', hadError, code);
  }
}

class Http2ServerRequest extends Readable {
  constructor(stream, options) {
    super(options);
    this[kState] = {
      closed: false,
      closedCode: constants.NGHTTP2_NO_ERROR
    };
    this[kStream] = stream;
    stream[kRequest] = this;

    // Pause the stream..
    stream.pause();
    stream.on('data', onStreamData);
    stream.on('end', onStreamEnd);
    stream.on('error', onStreamError);
    stream.on('close', onStreamClosedRequest);
    stream.on('aborted', onAborted.bind(this));
    this.on('pause', onRequestPause);
    this.on('resume', onRequestResume);
    this.on('drain', onRequestDrain);
  }

  get finished() {
    return this._readableState.ended;
  }

  get closed() {
    var state = this[kState];
    return Boolean(state.closed);
  }

  get code() {
    var state = this[kState];
    return Number(state.closedCode);
  }

  get stream() {
    return this[kStream];
  }

  get headers() {
    var stream = this[kStream];
    return stream ? stream[kHeaders] : undefined;
  }

  getHeader(name) {
    var stream = this[kStream];
    if (!stream)
      return;
    var headers = stream[kHeaders];
    name = String(name).trim().toLowerCase();
    return headers.get(name);
  }

  hasHeader(name) {
    var stream = this[kStream];
    if (!stream)
      return false;
    var headers = stream[kHeaders];
    name = String(name).trim().toLowerCase();
    return headers.has(name);
  }

  getTrailer(name) {
    var trailers = this[kTrailers];
    if (!trailers)
      return;
    name = String(name).trim().toLowerCase();
    return trailers.get(name);
  }

  hasTrailer(name) {
    var trailers = this[kTrailers];
    if (!trailers)
      return false;
    name = String(name).trim().toLowerCase();
    return trailers.has(name);
  }

  get trailers() {
    var stream = this[kStream];
    return stream ? stream[kTrailers] : undefined;
  }

  get httpVersion() {
    return '2.0';
  }

  _read(nread) {
    var stream = this[kStream];
    if (stream) {
      stream.resume();
    } else {
      throw new Error('HTTP/2 Stream has been closed');
    }
  }

  get method() {
    var stream = this[kStream];
    if (!stream) return;
    var headers = stream[kHeaders];
    return headers.get(constants.HTTP2_HEADER_METHOD);
  }

  get authority() {
    var stream = this[kStream];
    if (!stream) return;
    var headers = stream[kHeaders];
    return headers.get(constants.HTTP2_HEADER_AUTHORITY);
  }

  get scheme() {
    var stream = this[kStream];
    if (!stream) return;
    var headers = stream[kHeaders];
    return headers.get(constants.HTTP2_HEADER_SCHEME);
  }

  get path() {
    var stream = this[kStream];
    if (!stream) return;
    var headers = stream[kHeaders];
    return headers.get(constants.HTTP2_HEADER_PATH);
  }

  setTimeout(msecs, callback) {
    var stream = this[kStream];
    if (!stream) return;
    stream.setTimeout(msecs, callback);
    return this;
  }

  [kFinish](code) {
    var state = this[kState];
    state.closeCode = code;
    state.closed = true;
    this.push(null);
    this[kStream] = undefined;
  }
}

class Http2ServerResponse extends Stream {
  constructor(stream, options) {
    super(options);
    this[kState] = {
      sendDate: true,
      statusCode: constants.HTTP_STATUS_OK,
      headerCount: 0,
      trailerCount: 0,
      closed: false,
      closedCode: constants.NGHTTP2_NO_ERROR
    };
    this[kStream] = stream;
    stream[kResponse] = this;
    var headerList = {
      _idleNext: null,
      _idlePrev: null,
    };
    linkedList.init(headerList);
    this[kHeaders] = headerList;
    var trailersList = {
      _idleNext: null,
      _idlePrev: null,
    };
    linkedList.init(trailersList);
    this[kHeaders] = trailersList;
    this.writable = true;
    stream.on('drain', onStreamResponseDrain);
    stream.on('error', onStreamResponseError);
    stream.on('close', onStreamClosedResponse);
    stream.on('aborted', onAborted.bind(this));
  }

  get finished() {
    return this._writableState.ended;
  }

  get closed() {
    var state = this[kState];
    return Boolean(state.closed);
  }

  get code() {
    var state = this[kState];
    return Number(state.closedCode);
  }

  get stream() {
    return this[kStream];
  }

  get headersSent() {
    var state = this[kState];
    return state.headersSent;
  }

  get sendDate() {
    return Boolean(this[kState].sendDate);
  }

  set sendDate(bool) {
    this[kState].sendDate = Boolean(bool);
  }

  get statusCode() {
    return this[kState].statusCode;
  }

  set statusCode(code) {
    var state = this[kState];
    if (state.headersSent)
      throw new Error('Cannot set status after the HTTP message has been sent');
    code |= 0;
    if (code >= 100 && code < 200)
      throw new RangeError('Informational status codes cannot be used');
    if (code < 200 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    state.statusCode = code;
  }

  setHeader(name, value) {
    var state = this[kState];
    var headers = this[kHeaders];
    if (state.headersSent) {
      throw new Error(
        'Cannot set headers after the HTTP message has been sent');
    }
    setHeader(headers, name, value);
    state.headerCount++;
    return this;
  }

  setTrailer(name, value) {
    var state = this[kState];
    var trailers = this[kTrailers];
    if (state.trailersSent) {
      throw new Error(
        'Cannot set trailers after the HTTP message has been sent');
    }
    setHeader(trailers, name, value);
    state.trailerCount++;
    return this;
  }

  writeHead(statusCode, headers) {
    var keys = Object.keys(headers);
    var key = '';
    for (var i = 0; i < keys.length; i++) {
      key = keys[i];
      this.setHeader(key, headers[key]);
    }
    this.statusCode = statusCode;
    this[kBeginSend]();
    return this;
  }

  write(chunk, encoding, cb) {
    var stream = this[kStream];
    if (!stream) {
      cb(new Error('HTTP/2 Stream has been closed'));
      return;
    }
    var beginSend = this[kBeginSend];
    beginSend.call(this);
    return stream.write(chunk, encoding, cb);
  }

  end(chunk, encoding, cb) {
    var stream = this[kStream];
    this.write(chunk, encoding, cb);
    stream.end();
  }

  destroy(err) {
    var stream = this[kStream];
    if (!stream) {
      // nothing to do, already closed
      return;
    }
    stream.destroy(err);
  }

  setTimeout(msecs, callback) {
    var stream = this[kStream];
    if (!stream) return;
    stream.setTimeout(msecs, callback);
    return this;
  }

  sendContinue(headers) {
    this.sendInfo(100, headers);
  }

  sendInfo(code, headers) {
    var state = this[kState];
    if (state.headersSent) {
      throw new Error(
        'Cannot send informational headers after the HTTP message' +
        'has been sent');
    }
    if (headers && typeof headers !== 'object')
      throw new TypeError('headers must be an object');
    var stream = this[kStream];
    if (!stream) return;
    code |= 0;
    if (code < 100 || code >= 200)
      throw new RangeError(`Invalid informational status code: ${code}`);

    state.headersSent = true;
    headers[constants.HTTP2_HEADER_STATUS] = code;
    stream.respond(headers);
  }

  [kBeginSend]() {
    var state = this[kState];
    var stream = this[kStream];
    if (!state.headersSent) {
      state.headersSent = true;
      const headers = llistToHeaders(this[kHeaders]);
      headers[constants.HTTP2_HEADER_STATUS] = state.statusCode;
      stream.respond(headers);
    }
  }

  [kFinish](code) {
    var state = this[kState];
    state.closeCode = code;
    state.closed = true;
    this.end();
    this[kStream] = undefined;
  }
}

function onServerStream(stream, headers, flags) {
  var server = this;
  var request =
    new Http2ServerRequest(stream);
  var response =
    new Http2ServerResponse(stream);

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

  server.emit('request', request, response);
}

module.exports = { onServerStream };
