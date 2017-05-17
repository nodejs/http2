'use strict';

const Stream = require('stream');
const Readable = Stream.Readable;
const binding = process.binding('http2');
const constants = binding.constants;

const kFinish = Symbol('finish');
const kBeginSend = Symbol('begin-send');
const kState = Symbol('state');
const kStream = Symbol('stream');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kHeaders = Symbol('headers');
const kTrailers = Symbol('trailers');

let statusMessageWarned = false;

// Defines and implements an API compatibility layer on top of the core
// HTTP/2 implementation, intended to provide an interface that is as
// close as possible to the current require('http') API

function assertValidHeader(name, value) {
  if (isPseudoHeader(name))
    throw new Error('Cannot set HTTP/2 pseudo-headers');
  if (value === undefined || value === null)
    throw new TypeError('Value must not be undefined or null');
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
  constructor(stream, headers, options) {
    super(options);
    this[kState] = {
      statusCode: null,
      closed: false,
      closedCode: constants.NGHTTP2_NO_ERROR
    };
    this[kHeaders] = headers;
    this[kStream] = stream;
    stream[kRequest] = this;

    // Pause the stream..
    stream.pause();
    stream.on('data', onStreamData);
    stream.on('end', onStreamEnd);
    stream.on('error', onStreamError);
    stream.on('close', onStreamClosedRequest);
    stream.on('aborted', onAborted.bind(this));
    const onfinish = this[kFinish].bind(this);
    stream.on('streamClosed', onfinish);
    stream.on('finish', onfinish);
    this.on('pause', onRequestPause);
    this.on('resume', onRequestResume);
    this.on('drain', onRequestDrain);
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

  get statusCode() {
    return this[kState].statusCode;
  }

  get headers() {
    return this[kHeaders];
  }

  get rawHeaders() {
    var headers = this[kHeaders];
    if (headers === undefined)
      return [];
    var tuples = Object.entries(headers);
    var flattened = Array.prototype.concat.apply([], tuples);
    return flattened.map(String);
  }

  get trailers() {
    return this[kTrailers];
  }

  get httpVersionMajor() {
    return 2;
  }

  get httpVersionMinor() {
    return 0;
  }

  get httpVersion() {
    return '2.0';
  }

  get socket() {
    return this.stream.session.socket;
  }

  get connection() {
    return this.socket;
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
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    return headers[constants.HTTP2_HEADER_METHOD];
  }

  get authority() {
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    return headers[constants.HTTP2_HEADER_AUTHORITY];
  }

  get scheme() {
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    return headers[constants.HTTP2_HEADER_SCHEME];
  }

  get url() {
    return this.path;
  }

  get path() {
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    return headers[constants.HTTP2_HEADER_PATH];
  }

  setTimeout(msecs, callback) {
    var stream = this[kStream];
    if (stream === undefined) return;
    stream.setTimeout(msecs, callback);
  }

  [kFinish](code) {
    var state = this[kState];
    if (state.closed)
      return;
    state.closedCode = code;
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
      headersSent: false,
      headerCount: 0,
      trailerCount: 0,
      closed: false,
      closedCode: constants.NGHTTP2_NO_ERROR
    };
    this[kStream] = stream;
    stream[kResponse] = this;
    this.writable = true;
    stream.on('drain', onStreamResponseDrain);
    stream.on('error', onStreamResponseError);
    stream.on('close', onStreamClosedResponse);
    stream.on('aborted', onAborted.bind(this));
    stream.on('streamClosed', this[kFinish].bind(this));
    stream.on('finish', this[kFinish].bind(this));
  }

  get finished() {
    var stream = this[kStream];
    return stream === undefined || stream._writableState.ended;
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
    if (state.headersSent === true)
      throw new Error('Cannot set status after the HTTP message has been sent');
    code |= 0;
    if (code >= 100 && code < 200)
      throw new RangeError('Informational status codes cannot be used');
    if (code < 200 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    state.statusCode = code;
  }

  addTrailers(headers) {
    var trailers = this[kTrailers];
    var keys = Object.keys(headers);
    var key = '';
    if (keys.length > 0)
      return;
    if (trailers === undefined)
      trailers = this[kTrailers] = Object.create(null);
    for (var i = 0; i < keys.length; i++) {
      key = String(keys[i]).trim().toLowerCase();
      var value = headers[key];
      assertValidHeader(key, value);
      trailers[key] = String(value);
    }
  }

  getHeader(name) {
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    name = String(name).trim().toLowerCase();
    return headers[name];
  }

  getHeaderNames() {
    var headers = this[kHeaders];
    if (headers === undefined)
      return [];
    return Object.keys(headers);
  }

  getHeaders() {
    var headers = this[kHeaders];
    return Object.assign({}, headers);
  }

  hasHeader(name) {
    var headers = this[kHeaders];
    if (headers === undefined)
      return false;
    name = String(name).trim().toLowerCase();
    return Object.prototype.hasOwnProperty.call(headers, name);
  }

  removeHeader(name) {
    var headers = this[kHeaders];
    if (headers === undefined)
      return;
    name = String(name).trim().toLowerCase();
    delete headers[name];
  }

  setHeader(name, value) {
    var state = this[kState];
    if (state.headersSent === true)
      throw new Error('Cannot set headers after ' +
        'the HTTP message has been sent');
    name = String(name).trim().toLowerCase();
    assertValidHeader(name, value);
    var headers = this[kHeaders];
    if (headers === undefined)
      headers = this[kHeaders] = Object.create(null);
    headers[name] = String(value);
  }

  flushHeaders() {
    var state = this[kState];
    if (state.headersSent === true)
      return;
    var statusCode = this[kState].statusCode;
    this.writeHead(statusCode);
  }

  writeHead(statusCode, statusMessage, headers) {
    if (typeof statusMessage === 'string' && statusMessageWarned === false) {
      process.emitWarning(
        'Status message is not supported by HTTP/2 (RFC7540 8.1.2.4)',
        'UnsupportedWarning'
      );
      statusMessageWarned = true;
    }
    if (headers === undefined && typeof statusMessage === 'object') {
      headers = statusMessage;
    }
    var state = this[kState];
    if (state.headersSent === true)
      return;
    if (headers) {
      var keys = Object.keys(headers);
      var key = '';
      for (var i = 0; i < keys.length; i++) {
        key = keys[i];
        this.setHeader(key, headers[key]);
      }
    }
    this.statusCode = statusCode;
    this[kBeginSend]();
  }

  write(chunk, encoding, cb) {
    var stream = this[kStream];
    if (stream === undefined) {
      cb(new Error('HTTP/2 Stream has been closed'));
      return;
    }
    var beginSend = this[kBeginSend];
    beginSend.call(this);
    return stream.write(chunk, encoding, cb);
  }

  end(chunk, encoding, cb) {
    var stream = this[kStream];
    if (chunk)
      this.write(chunk, encoding, cb);
    stream.end();
  }

  destroy(err) {
    var stream = this[kStream];
    if (stream === undefined) {
      // nothing to do, already closed
      return;
    }
    stream.destroy(err);
  }

  setTimeout(msecs, callback) {
    var stream = this[kStream];
    if (stream === undefined) return;
    stream.setTimeout(msecs, callback);
  }

  sendContinue(headers) {
    this.sendInfo(100, headers);
  }

  sendInfo(code, headers) {
    var state = this[kState];
    if (state.headersSent === true) {
      throw new Error(
        'Cannot send informational headers after the HTTP message' +
        'has been sent');
    }
    if (headers && typeof headers !== 'object')
      throw new TypeError('headers must be an object');
    var stream = this[kStream];
    if (stream === undefined) return;
    code |= 0;
    if (code < 100 || code >= 200)
      throw new RangeError(`Invalid informational status code: ${code}`);

    state.headersSent = true;
    headers[constants.HTTP2_HEADER_STATUS] = code;
    stream.respond(headers);
  }

  createPushResponse(headers, callback) {
    var stream = this[kStream];
    if (stream === undefined) {
      throw new Error('HTTP/2 Stream has been closed');
    }
    stream.pushStream(headers, {}, function(stream, headers, options) {
      var response = new Http2ServerResponse(stream);
      callback(null, response);
    });
  }

  [kBeginSend]() {
    var state = this[kState];
    var stream = this[kStream];
    if (state.headersSent === false) {
      state.headersSent = true;
      const headers = this[kHeaders] || Object.create(null);
      headers[constants.HTTP2_HEADER_STATUS] = state.statusCode;
      stream.respond(headers);
    }
  }

  [kFinish](code) {
    var state = this[kState];
    if (state.closed)
      return;
    state.closedCode = code;
    state.closed = true;
    this.end();
    this[kStream] = undefined;
  }
}

function onServerStream(stream, headers, flags) {
  var server = this;
  var request = new Http2ServerRequest(stream, headers);
  var response = new Http2ServerResponse(stream);

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
