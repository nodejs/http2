'use strict';

const Buffer = require('buffer').Buffer;
const binding = process.binding('http2');
const SessionShutdownWrap = binding.SessionShutdownWrap;
const streamwrap = process.binding('stream_wrap');
const WriteWrap = streamwrap.WriteWrap;
const constants = binding.constants;
const stream = require('stream');
const timers = require('timers');
const Duplex = stream.Duplex;
const Writable = stream.Writable;
const Readable = stream.Readable;
const EventEmitter = require('events');
const utcDate = require('internal/http').utcDate;
const linkedList = require('internal/linkedlist');
const net = require('net');
const NETServer = net.Server;
const TLSServer = require('tls').Server;

const kBeginSend = Symbol('begin-send');
const kDestroySocket = Symbol('destroy-socket');
const kFinish = Symbol('finish');
const kGetTrailers = Symbol('get-trailers');
const kHandle = Symbol('handle');
const kHeaders = Symbol('headers');
const kId = Symbol('id');
const kImplicitHeaders = Symbol('implicit-headers');
const kLocalSettings = Symbol('local-settings');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kRemoteSettings = Symbol('remote-settings');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kServer = Symbol('server');
const kSession = Symbol('session');
const kSocket = Symbol('socket');
const kState = Symbol('state');
const kStream = Symbol('stream');
const kStreams = Symbol('streams');
const kTrailers = Symbol('trailers');
const kType = Symbol('type');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

function unrefTimer(item) {
  timers._unrefActive(item);
}

function isPseudoHeader(name) {
  return String(name)[0] === ':';
}

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

var count = 0;
function onSessionHeaders(id, cat, flags, headers) {
  unrefTimer(this);
  var owner = this[kOwner];
  var type = owner[kType];
  var streams = owner[kStreams];
  var stream;
  var eos = flags & constants.NGHTTP2_FLAG_END_STREAM;
  var options = { readable: !Boolean(eos) };
  switch (cat) {
    case constants.NGHTTP2_HCAT_REQUEST:
      stream = new Http2Stream(owner, id, flags, headers, options);
      streams.set(id, stream);
      owner.emit('request', stream);
      break;
    case constants.NGHTTP2_HCAT_RESPONSE:
      stream = new Http2Stream(owner, id, flags, headers, options);
      streams.set(id, stream);
      owner.emit('response', stream);
      break;
    case constants.NGHTTP2_HCAT_PUSH_RESPONSE:
      stream = new Http2Stream(owner, id, flags, headers, options);
      streams.set(id, stream);
      owner.emit('push', stream);
      break;
    case constants.NGHTTP2_HCAT_HEADERS:
      stream = streams.get(id);
      unrefTimer(stream);
      owner.emit('headers', stream, headers);
      break;
  }
}

// Called to determine if there are trailers to be sent
function onSessionTrailers(id) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var stream = streams.get(id);
  if (!stream)
    return;
  var ret = {};
  stream.emit(kGetTrailers, ret);
  return ret.trailers;
}

function onSessionStreamClose(id, code) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var stream = streams.get(id);
  unrefTimer(this);
  unrefTimer(stream);
  owner.emit('streamClose', stream, code);
  timers.unenroll(stream);
  stream[kSession] = undefined;
  streams.delete(id);
}

function onSessionError(error) {
  unrefTimer(this);
  var owner = this[kOwner];
  owner.emit('error', error);
}

function onSessionRead(nread, buf, handle) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var id = handle.id;
  var stream = streams.get(id);
  unrefTimer(this);
  unrefTimer(stream);
  if (!stream.push(buf))
    this.streamReadStop(id);
}

function onSettings() {
  unrefTimer(this);
  var owner = this[kOwner];
  owner[kRemoteSettings] = undefined;
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

function onSessionShutdownComplete(status, wrap) {
  if (wrap && typeof wrap.callback === 'function')
    wrap.callback(status);
  wrap[kOwner] = undefined;
}

class Http2Session extends EventEmitter {
  constructor(type, options, socket) {
    super();
    if (type !== constants.NGHTTP2_SESSION_SERVER &&
        type !== constants.NGHTTP2_SESSION_CLIENT) {
      throw new TypeError(
          'type must be one of http2.constants.NGHTTP2_SESSION_SERVER ' +
          'or http2.constants.NGHTTP2_SESSION_CLIENT');
    }
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    if (!(socket instanceof net.Socket))
      throw new TypeError('socket must be a net.Socket');

    socket[kSession] = this;
    this[kState] = {};
    this[kSocket] = socket;
    this[kType] = type;
    this[kStreams] = new Map();
    var handle = new binding.Http2Session(type, options);
    handle[kOwner] = this;
    this[kHandle] = handle;
    handle.onsettings = onSettings;
    handle.onheaders = onSessionHeaders;
    handle.ontrailers = onSessionTrailers;
    handle.onstreamclose = onSessionStreamClose;
    handle.onerror = onSessionError;
    handle.onread = onSessionRead;
    handle.consume(socket._handle._externalStream);

    // Any individual session can have any number of active open
    // streams, these may all need to be made aware of changes
    // in state that occur -- such as when the associated socket
    // is closed. To do so, we need to set the max listener count
    // to something more reasonable.
    this.setMaxListeners(Infinity);
  }

  get destroyed() {
    var state = this[kState];
    return Boolean(state.destroyed);
  }

  get type() {
    return this[kType];
  }

  get _handle() {
    return this[kHandle];
  }

  get state() {
    var obj = {};
    this.getSessionState(obj);
    return obj;
  }

  get localSettings() {
    var handle = this[kHandle];
    var settings = this[kLocalSettings];
    if (!settings) {
      settings = this[kLocalSettings] = {};
      handle.getLocalSettings(settings);
    }
    return settings;
  }

  get remoteSettings() {
    var handle = this[kHandle];
    var settings = this[kRemoteSettings];
    if (!settings) {
      settings = this[kRemoteSettings] = {};
      handle.getRemoteSettings(settings);
    }
    return settings;
  }

  submitSettings(settings) {
    unrefTimer(this);
    var handle = this[kHandle];
    if (typeof settings !== 'object')
      throw new TypeError('settings must be an object');
    this[kLocalSettings] = undefined;
    handle.submitSettings(settings);
  }

  rstStream(stream, code) {
    unrefTimer(this);
    var handle = this[kHandle];
    if (typeof stream !== 'number' &&
        !(stream instanceof Http2Stream)) {
      throw new TypeError('stream must be an Http2Stream object or a number');
    }
    var id = typeof stream === 'number' ? stream : stream[kId];
    if (id === undefined)
      throw new TypeError('stream must be an Http2Stream object or a number');
    handle.submitRstStream(id, Number(code));
  }

  noError(stream) {
    this.rstStream(stream, constants.NGHTTP2_NO_ERROR);
  }

  protocolError(stream) {
    this.rstStream(stream, constants.NGHTTP2_PROTOCOL_ERROR);
  }

  cancel(stream) {
    this.rstStream(stream, constants.NGHTTP2_CANCEL);
  }

  refuse(stream) {
    this.rstStream(stream, constants.NGHTTP2_REFUSED_STREAM);
  }

  internalError(stream) {
    this.rstStream(stream, constants.NGHTTP2_INTERNAL_ERROR);
  }

  destroy() {
    var state = this[kState];
    state.destroyed = true;
    timers.unenroll(this);
    var handle = this[kHandle];
    handle.unconsume();
    handle.destroy();
    this.emit('close');
    this.removeAllListeners();
  }

  shutdown(options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = {};
    } else {
      options = options || {};
    }
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    if (callback && typeof callback !== 'function')
      throw new TypeError('callback must be a function');
    options.errorCode |= 0;
    options.lastStreamID |= 0;
    if (options.opaqueData && !Buffer.isBuffer(options.opaqueData))
      throw new TypeError('opaqueData option must be a Buffer');

    var sessionShutdownWrap = new SessionShutdownWrap();
    sessionShutdownWrap.oncomplete = onSessionShutdownComplete;
    sessionShutdownWrap.callback = callback;
    sessionShutdownWrap.options = options;
    sessionShutdownWrap[kOwner] = this;
    binding.submitShutdown(sessionShutdownWrap,
                           options.graceful,
                           options.immediate,
                           options.errorCode,
                           options.lastStreamID,
                           options.opaqueData);
  }
}

function createWriteReq(req, handle, data, encoding) {
  switch (encoding) {
    case 'latin1':
    case 'binary':
      return handle.writeLatin1String(req, data);

    case 'buffer':
      return handle.writeBuffer(req, data);

    case 'utf8':
    case 'utf-8':
      return handle.writeUtf8String(req, data);

    case 'ascii':
      return handle.writeAsciiString(req, data);

    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return handle.writeUcs2String(req, data);

    default:
      return handle.writeBuffer(req, Buffer.from(data, encoding));
  }
}

function afterDoStreamWrite(status, handle, req) {
  //unrefTimer(handle[kOwner]);
  if (typeof req.callback === 'function')
    req.callback();
}

function onHandleFinish() {
  var session = this[kSession];
  var handle = session[kHandle];
  handle.shutdownStream(this[kId]);
}

function onSessionClose(hadError, code) {
  if (!this._readableState.ended || !this._writableState.ended) {
    this.emit('aborted', hadError, code);
  }
  // Close the readable side
  this.push(null);
  // Close the writable side
  this.end();
}

function onStreamClosed(code) {
  onSessionClose.apply(this, code !== constants.NGHTTP2_NO_ERROR, code);
}

class Http2Stream extends Duplex {
  constructor(session, id, flags, headers, options) {
    options.allowHalfOpen = true;
    super(options);
    this[kId] = id;
    this[kHeaders] = headers;
    this[kSession] = session;
    this.on('finish', onHandleFinish);
    session.on('close', onSessionClose.bind(this));
    session.on('streamClosed', onStreamClosed.bind(this));
  }

  get id() {
    return this[kId];
  }

  get headers() {
    return this[kHeaders];
  }

  get session() {
    return this[kSession];
  }

  get state() {
    var obj = {};
    var id = this[kId];
    var session = this[kSession];
    var handle = session[kHandle];
    handle.getStreamState(id, obj);
    return obj;
  }

  _write(data, encoding, cb) {
    unrefTimer(this);
    var session = this[kSession];
    var handle = session[kHandle];
    var req = new WriteWrap();
    req.stream = this[kId];
    req.handle = handle;
    req.callback = cb;
    req.oncomplete = afterDoStreamWrite;
    req.async = false;
    var enc = data instanceof Buffer ? 'buffer' : encoding;
    var err = createWriteReq(req, handle, data, enc);
    if (err)
      throw util._errnoException(err, 'write', req.error);
    this._bytesDispatched += req.bytes;
  }

  _writev(data, cb) {
    unrefTimer(this);
    var session = this[kSession];
    var handle = session[kHandle];
    var req = new WriteWrap();
    req.stream = this[kId];
    req.handle = handle;
    req.callback = cb;
    req.oncomplete = afterDoStreamWrite;
    req.async = false;
    var chunks = new Array(data.length << 1);
    for (var i = 0; i < data.length; i++) {
      var entry = data[i];
      chunks[i * 2] = entry.chunk;
      chunks[i * 2 + 1] = entry.encoding;
    }
    var err = handle.writev(req, chunks);
    if (err)
      throw util._errnoException(err, 'write', req.error);
  }

  _read(nread) {
    unrefTimer(this);
    var session = this[kSession];
    var handle = session[kHandle];
    handle.streamReadStart(this[kId]);
  }

  rstStream(code) {
    unrefTimer(this);
    var session = this[kSession];
    session.rstStream(this[kId], code);
  }

  protocolError() {
    unrefTimer(this);
    var session = this[kSession];
    session.protocolError(this[kId]);
  }

  noError() {
    unrefTimer(this);
    var session = this[kSession];
    session.noError(this[kId]);
  }

  cancel() {
    unrefTimer(this);
    var session = this[kSession];
    session.cancel(this[kId]);
  }

  refuse() {
    unrefTimer(this);
    var session = this[kSession];
    session.refuse(this[kId]);
  }

  internalError() {
    unrefTimer(this);
    var session = this[kSession];
    session.internalEror(this[kId]);
  }

  respond(headers, emptyPayload) {
    unrefTimer(this);
    var session = this[kSession];
    var handle = session[kHandle];
    handle.submitResponse(this[kId], headers, emptyPayload);
  }

  sendHeaders(headers) {
    unrefTimer(stream);
    var session = this[kSession];
    var handle = session[kHandle];
    handle.submitInfo(this[kId], headers);
  }
}

const setTimeout = {
  configurable: true,
  enumerable: true,
  value: function(msecs, callback) {
    if (msecs === 0) {
      timers.unenroll(this);
      if (callback) {
        this.removeListener('timeout', callback);
      }
    } else {
      timers.enroll(this, msecs);
      timers._unrefActive(this);
      if (callback) {
        this.once('timeout', callback);
      }
    }
    return this;
  }
};

const onTimeout = {
  configurable: false,
  enumerable: false,
  value: function() {
    this.emit('timeout');
  }
};
Object.defineProperty(Http2Stream.prototype, 'setTimeout', setTimeout);
Object.defineProperty(Http2Stream.prototype, '_onTimeout', onTimeout);
Object.defineProperty(Http2Session.prototype, 'setTimeout', setTimeout);
Object.defineProperty(Http2Session.prototype, '_onTimeout', onTimeout);

// --------------------------------------------------------------------
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
// --------------------------------------------------------------------

function socketDestroy(error) {
  var session = this[kSession];
  session.destroy();
  this[kServer] = undefined;
  session[kServer] = undefined;
  session[kServer] = undefined;
  session[kSocket] = undefined;
  this.destroy = this[kDestroySocket];
  this.destroy(error);
}

function socketOnResume() {
  if (this._paused)
    return this.pause();
  if (this._handle && !this._handle.reading) {
    this._handle.reading = true;
    this._handle.readStart();
  }
}

function socketOnPause() {
  if (this._handle && this._handle.reading) {
    this._handle.reading = false;
    this._handle.readStop();
  }
}

function socketOnDrain() {
  var needPause = 0 > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}

function sessionOnError(error) {
  var session = this;
  var server = session[kServer];
  if (server.emit('sessionError', error))
    return;
  var socket = session[kSocket];
  socket.destroy(error);
}

function socketOnTimeout() {
  var socket = this;
  var server = socket[kServer];
  if (!server.emit('timeout', this)) {
    var session = socket[kSession];
    session.shutdown({graceful: true, errorCode: constants.NGHTTP2_NO_ERROR},
                     this.destroy.bind(this));
  }
}

function socketOnError(error) {
  if (kRenegTest.test(error.message))
    return this.destroy();
  var server = this[kServer];
  if (!server.emit('socketError', error, this))
    this.destroy(error);
}

function sessionOnStreamClose(stream, code) {
  stream.emit('streamClosed', code);
}

function sessionOnRequest(stream) {
  var server = this[kServer];
  var options = server[kOptions];

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

  server.emit('request', request, response);
}

function sessionOnHeaders(stream, headers) {
  var request = stream[kRequest];
  if (request) {
    request[kTrailers] = headers;
  }
}

function socketOnClose(hadError) {
  var session = this[kSession];
  session.emit('close', hadError);
}

function connectionListener(socket) {
  var options = this[kOptions] || {};

  // Set up the Socket
  // 1. Do not use nagle's algorithm
  socket.setNoDelay();
  // 2. Disable TLS renegotiation on the socket
  if (typeof socket.disableRenegotiation === 'function')
    socket.disableRenegotiation();
  // 3. Set up the timout
  if (this.timeout) {
    socket.setTimeout(this.timeout);
    socket.on('timeout', socketOnTimeout);
  }
  socket[kDestroySocket] = socket.destroy;
  socket.destroy = socketDestroy;
  socket.on('close', socketOnClose);
  socket.on('error', socketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  // Set up the Session
  var session = createServerSession(this[kOptions], socket);
  session.on('error', sessionOnError);
  session.on('request', sessionOnRequest);
  session.on('headers', sessionOnHeaders);
  session.on('streamClose', sessionOnStreamClose);

  session[kServer] = this;
  socket[kServer] = this;

  // Complete the handshake
  session.submitSettings(options.settings);
}

function initHttp2IncomingOptions(options) {
  options = options || {};
  return options;
}

function initHttp2OutgoingOptions(options) {
  options = options || {};
  return options;
}

function initializeOptions(options) {
  options = options || {};
  if (typeof options !== 'object')
    throw new TypeError('options must be an object');
  options.allowHalfOpen = true;
  options.settings = options.settings || {};
  if (typeof options.settings !== 'object')
    throw new TypeError('options.settings must be an object');
  if (!options.defaultIncomingOptions ||
      typeof options.defaultIncomingOptions !== 'object') {
    options.defaultIncomingOptions = initHttp2IncomingOptions({});
  }
  if (!options.defaultOutgoingOptions ||
     typeof options.defaultOutgoingOptions !== 'object') {
    options.defaultOutgoingOptions = initHttp2OutgoingOptions({});
  }
  return options;
}

function initializeTLSOptions(options) {
  options = initializeOptions(options);
  options.ALPNProtocols = ['hc', 'h2'];
  options.NPNProtocols = ['hc', 'h2'];
  return options;
}

function onErrorSecureServerSession(err, conn) {
  if (!this.emit('clientError', err, conn))
    conn.destroy(err);
}

class Http2SecureServer extends TLSServer {
  constructor(options, requestListener) {
    options = initializeTLSOptions(options);
    super(options, connectionListener);
    this[kOptions] = options;
    this.timeout = kDefaultSocketTimeout;
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', onErrorSecureServerSession);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback)
      this.on('timeout', callback);
    return this;
  }
}

class Http2Server extends NETServer {
  constructor(options, requestListener) {
    super(connectionListener);
    this[kOptions] = initializeOptions(options);
    this.timeout = kDefaultSocketTimeout;
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback)
      this.on('timeout', callback);
    return this;
  }
}

function createServerSession(options, socket) {
  return new Http2Session(constants.NGHTTP2_SESSION_SERVER, options, socket);
}

function createClientSession(options, socket) {
  return new Http2Session(constants.NGHTTP2_SESSION_CLIENT, options, socket);
}

function createSecureServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  if (typeof handler !== 'function')
    throw new TypeError('handler must be a function');
  return new Http2SecureServer(options, handler);
}

function createServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  if (typeof handler !== 'function')
    throw new TypeError('handler must be a function');
  return new Http2Server(options, handler);
}

function getDefaultSettings() {
  var holder = {};
  binding.getDefaultSettings(holder);
  return holder;
}

function getPackedSettings(obj) {
  obj = obj || {};
  if (typeof obj !== 'object')
    throw new TypeError('settings must be an object');
  return binding.packSettings(obj);
}

// Exports
module.exports = {
  constants,
  getDefaultSettings,
  getPackedSettings,
  createServer,
  createSecureServer,
  createServerSession,
  createClientSession
};
