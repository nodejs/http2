'use strict';

const core = require('internal/http2/core');

// Defines and implements an API compatibility layer on top of the core
// HTTP/2 implementation, intended to provide an interface that is as
// close as possible to the current require('http') API


function setHeader(list, name, value, noindex) {
  name = String(name).toLowerCase().trim();
  if (isPseudoHeader(name))
    throw new Error('Cannot set HTTP/2 pseudo-headers');
  if (isIllegalConnectionSpecificHeader(name, value))
    throw new Error('Connection-specific HTTP/1 headers are not permitted');
  if (value === undefined || value === null)
    throw new TypeError('Value must not be undefined or null');
  linkedList.append(list, [name, String(value), Boolean(noindex)]);
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

function onStreamGetTrailers(ret) {
  var response = this[kResponse];
  if (response) {
    ret.trailers = llistToHeaders(response[kTrailers]);
  }
}

function onResponseFinish() {
  var beginSend = this[kBeginSend];
  beginSend.call(this);
  var stream = this[kStream];
  stream.end();
}

function onStreamClosedRequest() {
  this.push(null);
}

function onStreamClosedResponse() {
  this.end();
}

function onAborted(hadError, code) {
  if ((this._writableState && !this._writableState.ended) ||
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
    stream.on('close', onStreamClosedRequest.bind(this));
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

  get trailers() {
    return this[kTrailers];
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

function statusRequiresEmptyPayload(statusCode) {
  statusCode |= 0;
  switch (statusCode) {
    case constants.HTTP_STATUS_NO_CONTENT:
    case constants.HTTP_STATUS_RESET_CONTENT:
    case constants.HTTP_STATUS_NOT_MODIFIED:
      return true;
    default:
      return false;
  }
}

class Http2ServerResponse extends Writable {
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
    this[kHeaders] = linkedList.create();
    this[kTrailers] = linkedList.create();
    this.on('finish', onResponseFinish);
    stream.on('drain', onStreamResponseDrain);
    stream.on('error', onStreamResponseError);
    stream.on('close', onStreamClosedResponse.bind(this));
    stream.on('aborted', onAborted.bind(this));
    stream.on(kGetTrailers, onStreamGetTrailers);
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

  setHeader(name, value, noindex) {
    var state = this[kState];
    var headers = this[kHeaders];
    if (state.headersSent) {
      throw new Error(
        'Cannot set headers after the HTTP message has been sent');
    }
    setHeader(headers, name, value, noindex);
    state.headerCount++;
    return this;
  }

  setTrailer(name, value, noindex) {
    var state = this[kState];
    var trailers = this[kTrailers];
    if (state.trailersSent) {
      throw new Error(
        'Cannot set trailers after the HTTP message has been sent');
    }
    setHeader(trailers, name, value, noindex);
    state.trailerCount++;
    return this;
  }

  _write(chunk, encoding, cb) {
    var stream = this[kStream];
    if (!stream)
      throw Error('HTTP/2 Stream has been closed');
    var beginSend = this[kBeginSend];
    beginSend.call(this);
    return stream.write(chunk, encoding, cb);
  }

  _writev(chunks, cb) {
    var stream = this[kStream];
    if (!stream)
      throw Error('HTTP/2 Stream has been closed');
    var beginSend = this[kBeginSend];
    beginSend.call(this);
    return stream.writev(chunks, cb);
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
    headers[constants.HTTP2_HEADERS_STATUS] = String(code);
    stream.sendHeaders(mapToHeaders(headers));
  }

  [kImplicitHeaders]() {
    var headers = this[kHeaders];
    var state = this[kState];
    linkedList.append(
        headers,
        [constants.HTTP2_HEADER_STATUS, String(state.statusCode)]);
    linkedList.append(headers, ['date', utcDate()]);
  }

  [kBeginSend]() {
    var state = this[kState];
    var stream = this[kStream];
    if (!stream)
      throw Error('HTTP/2 Stream has been closed');
    var implicitHeaders = this[kImplicitHeaders];
    if (!state.headersSent) {
      state.headersSent = true;
      implicitHeaders.call(this);
      stream.respond(llistToHeaders(this[kHeaders]),
                     statusRequiresEmptyPayload(state.statusCode));
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
