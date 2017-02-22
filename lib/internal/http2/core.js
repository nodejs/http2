'use strict';

const debug = require('util').debuglog('http2');
const assert = require('assert');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const net = require('net');
const stream = require('stream');
const timers = require('timers');
const util = require('util');
const { mapToHeaders } = require('internal/http2/util');
const { onServerStream } = require('internal/http2/compat');
const { utcDate } = require('internal/http');

const binding = process.binding('http2');
const streamwrap = process.binding('stream_wrap');
const SessionShutdownWrap = binding.SessionShutdownWrap;
const WriteWrap = streamwrap.WriteWrap;
const constants = binding.constants;

const Duplex = stream.Duplex;
const NETServer = net.Server;
const TLSServer = require('tls').Server;

const kDestroySocket = Symbol('destroy-socket');
const kHandle = Symbol('handle');
const kId = Symbol('id');
const kInspect = require('internal/util').customInspectSymbol;
const kLocalSettings = Symbol('local-settings');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kRemoteSettings = Symbol('remote-settings');
const kServer = Symbol('server');
const kSession = Symbol('session');
const kSocket = Symbol('socket');
const kState = Symbol('state');
const kStreams = Symbol.for('streams');
const kType = Symbol('type');
const kProceed = Symbol('proceed');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

const Holder = function() {};
Holder.prototype = Object.create(null);


function unrefTimer(item) {
  timers._unrefActive(item);
}

// TODO(jasnell): Currently this throws, but there may be some situations
// where emit('error') may be more appropriate.
function throwIfNecessary(ret) {
  if (ret < 0) {
    var err = new Error(binding.nghttp2ErrorString(ret));
    err.errno = ret;
    Error.captureStackTrace(err, throwIfNecessary);
    throw err;
  }
}

// Called when a new block of headers has been received for a given
// stream. The stream may or may not be new. If the stream is new,
// create the associated Http2Stream instance and emit the 'stream'
// event. If the stream is not new, emit the 'headers' event to pass
// the block of headers on.
function onSessionHeaders(id, cat, flags, headers) {
  unrefTimer(this); // unref the *session* timer
  var owner = this[kOwner]; // the Http2Session JS wrapper
  var type = owner[kType];
  var streams = owner[kStreams]; // the collection of known streams
  var stream = streams.get(id); // the current stream, if it exists

  var eos = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);

  // If this is a server, the stream might need to be created. If it's
  // client side the stream object should already be in the cache by this
  // point in time.
  if (stream === undefined && type === constants.NGHTTP2_SESSION_SERVER) {
    stream = new ServerHttp2Stream(owner, id, { readable: !eos });
    streams.set(id, stream);
    // Notify session that a new stream has been initialized
    owner.emit('stream', stream, headers, flags);
  } else {
    var event;
    switch (cat) {
      case constants.NGHTTP2_HCAT_RESPONSE:
        // Should only happen when type === NGHTTP2_SESSION_CLIENT
        event = 'response';
        break;
      case constants.NGHTTP2_HCAT_PUSH_RESPONSE:
        // Should only happen when type === NGHTTP2_SESSION_CLIENT
        event = 'push';
        break;
      case constants.NGHTTP2_HCAT_HEADERS:
        // trailers if eos is true, otherwise, just headers
        event = eos ? 'trailers' : 'headers';
        break;
      default:
        // If cat === NGHTTP2_HCAT_REQUEST then some kind of internal
        // error has occurred.
        assert.fail(null, null,
                    'Internal HTTP/2 Error. Invalid headers category.');
    }
    stream.emit(event, headers, flags);
  }
}

// Called to determine if there are trailers to be sent at the end of a
// Stream. The 'fetchTrailers' event is emitted and passed a holder object.
// The trailers to return are set on that object by the handler. Once the
// event handler returns, those are sent off for processing. Note that this
// is a necessarily synchronous operation. We need to know immediately if
// there are trailing headers to send.
function onSessionTrailers(id) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  var trailers = new Holder();
  stream.emit('fetchTrailers', trailers);
  return mapToHeaders(trailers);
}

// Called when the stream is closed. The streamClosed event is emitted on the
// Http2Stream instance. Note that this event is distinctly different than the
// require('stream') interface 'close' event which deals with the state of the
// Readable and Writable sides of the Duplex.
function onSessionStreamClose(id, code) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  unrefTimer(this); // Unref the session timer
  unrefTimer(stream); // Unref the stream timer
  // Notify the stream that it has been closed.
  stream.emit('streamClosed', code);
  timers.unenroll(stream);
  stream[kSession] = undefined;
  streams.delete(id);
}

// Called when an error event needs to be triggered
function onSessionError(error) {
  unrefTimer(this);
  var owner = this[kOwner];
  owner.emit('error', error);
}

// Receives a chunk of data for a given stream and forwards it on
// to the Http2Stream Duplex for processing.
function onSessionRead(nread, buf, handle) {
  var owner = this[kOwner];
  var streams = owner[kStreams];
  var id = handle.id;
  var stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  var state = stream[kState];
  unrefTimer(this);
  unrefTimer(stream);
  if (!stream.push(buf)) {
    throwIfNecessary(this.streamReadStop(id));
    state.reading = false;
  }
}

// Called when the remote peer settings have been updated.
// Resets the cached settings.
function onSettings() {
  unrefTimer(this);
  var owner = this[kOwner];
  owner[kRemoteSettings] = undefined;
}

// Called when a requested session shutdown has been completed.
function onSessionShutdownComplete(status, wrap) {
  if (wrap && typeof wrap.callback === 'function')
    wrap.callback(status);
  wrap[kOwner] = undefined;
}

function onSelectPadding(frameLen, maxFramePayloadLen) {
  var owner = this[kOwner];
  var ret = {length: frameLen};
  owner.emit('selectPadding', frameLen, maxFramePayloadLen, ret);
  return Math.min(maxFramePayloadLen, Math.max(frameLen, ret.length | 0));
}

function request(headers, options) {
  unrefTimer(this);
  var handle = this[kHandle];
  options = options || {};
  headers = headers || {};

  if (headers[constants.HTTP2_HEADER_METHOD] === undefined)
    headers[constants.HTTP2_HEADER_METHOD] = 'GET';

  if (typeof options !== 'object')
    throw new TypeError('options must be an object');
  if (options.weight === undefined)
    options.weight = constants.NGHTTP2_DEFAULT_WEIGHT;
  if (options.parent === undefined)
    options.parent = 0;
  if (options.exclusive === undefined)
    options.exclusive = false;
  if (options.endStream === undefined)
    options.endStream = false;

  var ret = handle.submitRequest(mapToHeaders(headers),
                                 Boolean(options.endStream),
                                 options.parent | 0,
                                 options.weight | 0,
                                 Boolean(options.exclusive));
  throwIfNecessary(ret); // TODO mcollina emit('error') instead
  var stream = new ClientHttp2Stream(this, ret, {});
  var streams = this[kStreams];
  streams.set(ret, stream);
  return stream;
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

    if (type === constants.NGHTTP2_SESSION_CLIENT) {
      Object.defineProperty(this, 'request', {
        enumerable: true,
        configurable: true,
        writable: true,
        value: request
      });
      debug('creating client http2 session');
    } else {
      debug('creating server http2 session');
    }

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
    handle.ongetpadding = onSelectPadding;
    handle.consume(socket._handle._externalStream);

    // Any individual session can have any number of active open
    // streams, these may all need to be made aware of changes
    // in state that occur -- such as when the associated socket
    // is closed. To do so, we need to set the max listener count
    // to something more reasonable.
    this.setMaxListeners(Infinity);
  }

  [kInspect](depth, opts) {
    var state = this[kState];
    var obj = {
      type: this[kType],
      destroyed: Boolean(state.destroyed),
      state: this.state,
      localSettings: this.localSettings,
      remoteSettings: this.remoteSettings
    };
    return `Http2Session ${util.format(obj)}`;
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
    var handle = this[kHandle];
    handle.getSessionState(obj);
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
    throwIfNecessary(handle.submitSettings(settings));
  }

  submitPriority(stream, options) {
    unrefTimer(this);
    var handle = this[kHandle];
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream must be an Http2Stream');
    options = options || {};
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    if (options.weight === undefined)
      options.weight = constants.NGHTTP2_DEFAULT_WEIGHT;
    if (options.parent === undefined)
      options.parent = 0;
    if (options.exclusive === undefined)
      options.exclusive = false;
    if (options.silent === undefined)
      options.silent = false;
    throwIfNecessary(
      handle.submitPriority(
        stream[kId],
        options.parent | 0,
        options.weight | 0,
        Boolean(options.exclusive),
        Boolean(options.silent)));
  }

  rstStream(stream, code) {
    unrefTimer(this);
    var handle = this[kHandle];
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream must be an Http2Stream');
    throwIfNecessary(handle.submitRstStream(stream[kId], Number(code)));
  }

  destroy() {
    var state = this[kState];
    state.destroyed = true;
    timers.unenroll(this);
    var streams = this[kStreams];
    streams.forEach((value, key) => {
      value[kSession] = undefined;
      value[kState].shutdown = true;
    });
    streams.clear();
    var handle = this[kHandle];
    handle.unconsume();
    this.emit('close');
    this.removeAllListeners();
    setImmediate(() => handle.destroy());
  }

  shutdown(options, callback) {
    var handle = this[kHandle];
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
    if (options.opaqueData && !Buffer.isBuffer(options.opaqueData))
      throw new TypeError('opaqueData option must be a Buffer');

    var sessionShutdownWrap = new SessionShutdownWrap();
    sessionShutdownWrap.oncomplete = onSessionShutdownComplete;
    sessionShutdownWrap.callback = callback;
    sessionShutdownWrap.options = options;
    sessionShutdownWrap[kOwner] = this;
    handle.submitShutdown(sessionShutdownWrap,
                          options.graceful,
                          options.immediate,
                          options.errorCode | 0,
                          options.lastStreamID | 0,
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
  unrefTimer(handle[kOwner]);
  if (typeof req.callback === 'function')
    req.callback();
  this.handle = undefined;
}

function onHandleFinish() {
  var session = this[kSession];
  var handle = session[kHandle];
  throwIfNecessary(handle.shutdownStream(this[kId]));
}

function onSessionClose(hadError, code) {
  if ((this._readableState && !this._readableState.ended) ||
      (this._writableState && !this._writableState.ended)) {
    this.emit('aborted', hadError, code);
  }
  // Close the readable side
  this.push(null);
  // Close the writable side
  this.end();
}

function onStreamClosed(code) {
  if ((this._readableState && !this._readableState.ended) ||
      (this._writableState && !this._writableState.ended)) {
    this.emit('aborted', code !== constants.NGHTTP2_NO_ERROR, code);
  }
  // Close the readable side
  this.push(null);
  // Close the writable side
  this.end();
}

function onStreamError(error) {
  var session = this[kSession];
  if (!session.emit('streamError', error, this))
    session.emit('error', error, this);
}

function streamOnResume() {
  if (this._paused)
    return this.pause();
  var session = this[kSession];
  var state = this[kState];
  var id = this[kId];
  if (session && !state.reading) {
    var handle = session[kHandle];
    state.reading = true;
    throwIfNecessary(handle.streamReadStart(id));
  }
}

function streamOnPause() {
  var session = this[kSession];
  var state = this[kState];
  var id = this[kId];
  if (session && state.reading) {
    var handle = session[kHandle];
    state.reading = false;
    throwIfNecessary(handle.streamReadStop(id));
  }
}

function streamOnDrain() {
  var needPause = 0 > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}


// An Http2Stream is essentially a Duplex stream. It has a Readable side
// and a Writable side. On the server-side, the Readable side provides
// access to the received request data. The `headers` event is used to
// notify when a new block of headers has been received, including those
// that carry the request headers. At least one `headers` event should
// trigger before any other events on the stream. On the client-side, the
// Readable side provides access to the received response data. On the
// server side, the writable side is used to transmit response data, while
// on the client side it is used to transmit request data.
class Http2Stream extends Duplex {
  constructor(session, id, options) {
    options.allowHalfOpen = true;
    super(options);
    this[kState] = {};
    this[kId] = id;
    this[kSession] = session;
    this.on('finish', onHandleFinish);
    this.on('streamClosed', onStreamClosed);
    this.on('error', onStreamError);
    this.on('resume', streamOnResume);
    this.on('pause', streamOnPause);
    this.on('drain', streamOnDrain);
    session.on('close', onSessionClose.bind(this));
  }

  [kInspect](depth, opts) {
    var obj = {
      id: this[kId],
      state: this.state,
      readableState: this._readableState,
      writeableSate: this._writableState
    };
    return `Http2Stream ${util.format(obj)}`;
  }

  get id() {
    return this[kId];
  }

  get session() {
    return this[kSession];
  }

  get state() {
    var obj = {};
    var id = this[kId];
    var session = this[kSession];
    var handle = session[kHandle];
    throwIfNecessary(handle.getStreamState(id, obj));
    return obj;
  }

  [kProceed]() {
    throw new Error('implementors MUST implement this');
  }

  _write(data, encoding, cb) {
    unrefTimer(this);
    var state = this[kState];
    if (!state.headersSent)
      this[kProceed]();
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
    var state = this[kState];
    if (!state.headersSent)
      this[kProceed]();
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
    var state = this[kState];
    if (state.reading)
      return;
    state.reading = true;
    var session = this[kSession];
    var handle = session[kHandle];
    throwIfNecessary(handle.streamReadStart(this[kId]));
  }

  rstStream(code) {
    unrefTimer(this);
    var session = this[kSession];
    session.rstStream(this, code);
  }

  rstWithNoError() {
    this.rstStream(constants.NGHTTP2_NO_ERROR);
  }

  rstWithProtocolError() {
    this.rstStream(constants.NGHTTP2_PROTOCOL_ERROR);
  }

  rstWithCancel() {
    this.rstStream(constants.NGHTTP2_CANCEL);
  }

  rstWithRefuse() {
    this.rstStream(constants.NGHTTP2_REFUSED_STREAM);
  }

  rstWithInternalError() {
    this.rstStream(constants.NGHTTP2_INTERNAL_ERROR);
  }

  priority(options) {
    unrefTimer(this);
    var session = this[kSession];
    session.submitPriority(this, options);
  }

  // Sends a block of headers.
  sendHeaders(headers) {
    unrefTimer(this);
    var state = this[kState];
    var session = this[kSession];
    var handle = session[kHandle];

    if (headers && (typeof headers !== 'object' || Array.isArray(headers)))
      throw new TypeError('headers must be an object');
    headers = Object.assign(new Holder(), headers);
    if (headers[constants.HTTP2_HEADER_STATUS] != null) {
      if (state.headersSent) {
        throw new Error(
          'Cannot specify HTTP status header after response initiated');
      }
      var statusCode = headers[constants.HTTP2_HEADER_STATUS] |= 0;
      if (statusCode === constants.HTTP_STATUS_SWITCHING_PROTOCOLS)
        throw new RangeError(
          'HTTP status code 101 (Switching Protocols) is forbidden in HTTP/2');
      if (statusCode < 100 || statusCode >= 200)
        throw new RangeError('Invalid informational status code');
    }

    throwIfNecessary(handle.sendHeaders(this[kId], mapToHeaders(headers)));
  }
}

class ServerHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, id, options);
  }

  pushStream(headers, options, callback) {
    unrefTimer(this);
    var session = this[kSession];
    var streams = session[kStreams];
    var handle = session[kHandle];

    if (typeof options === 'function') {
      callback = options;
      options = {};
    } else {
      options = options || {};
    }

    if (typeof callback !== 'function')
      throw new TypeError('callback must be a function');
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    options = Object.create(options || {});
    options.endStream = Boolean(options.endStream);
    if (typeof headers !== 'object' || Array.isArray(headers))
      throw new TypeError('headers must be an object');
    headers = Object.assign(new Holder(), headers);

    if (headers[constants.HTTP2_HEADER_METHOD] === undefined)
      headers[constants.HTTP2_HEADER_METHOD] = 'GET';

    if (headers[constants.HTTP2_HEADER_AUTHORITY] === undefined)
      throw new Error('The :authority header is required');
    if (headers[constants.HTTP2_HEADER_PATH] === undefined)
      throw new Error('The :path header is required');
    if (headers[constants.HTTP2_HEADER_SCHEME] === undefined)
      throw new Error('The :scheme header is required');

    var ret = handle.submitPushPromise(this[kId],
                                       mapToHeaders(headers),
                                       options.endStream);
    if (ret <= 0) {
      throwIfNecessary(ret);
    } else {
      options.readable = !options.endStream;
      var stream = new ServerHttp2Stream(session, ret, options);
      streams.set(ret, stream);
      process.nextTick(callback, stream, headers, 0);
    }
  }

  respond(headers, options) {
    unrefTimer(this);
    var state = this[kState];
    var session = this[kSession];
    var handle = session[kHandle];

    if (state.headersSent)
      throw new Error('Response has already been initiated.');
    state.headersSent = true;

    options = Object.create(options || null);
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    options.endStream = Boolean(options.endStream);

    if (headers && (typeof headers !== 'object' || Array.isArray(headers)))
      throw new TypeError('headers must be an object');
    headers = Object.assign(new Holder(), headers);
    if (headers[constants.HTTP2_HEADER_STATUS] == null) {
      headers[constants.HTTP2_HEADER_STATUS] = constants.HTTP_STATUS_OK;
    } else {
      var statusCode = headers[constants.HTTP2_HEADER_STATUS] |= 0;
      if (statusCode < 200 || statusCode > 999)
        throw new RangeError('Invalid status code.');

      // Payload/DATA frames are not permitted in these cases
      if (statusCode === constants.HTTP_STATUS_NO_CONTENT ||
          statusCode === constants.HTTP_STATUS_CONTENT_RESET ||
          statusCode === constants.HTTP_STATUS_NOT_MODIFIED) {
        options.endStream = true;
      }
    }
    headers[constants.HTTP2_HEADER_DATE] = utcDate();

    // Close the writable side if the endStream option is set
    if (options.endStream)
      this.end();

    throwIfNecessary(
        handle.submitResponse(this[kId],
                              mapToHeaders(headers),
                              options.endStream));
  }
}

ServerHttp2Stream.prototype[kProceed] = ServerHttp2Stream.prototype.respond;

class ClientHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, id, options);
    this[kState].headerSent = true;
  }
}

const setTimeout = {
  configurable: true,
  enumerable: true,
  value: function(msecs, callback) {
    if (msecs === 0) {
      timers.unenroll(this);
      if (callback) {
        if (typeof callback !== 'function')
          throw new TypeError('callback must be a function');
        this.removeListener('timeout', callback);
      }
    } else {
      timers.enroll(this, msecs);
      timers._unrefActive(this);
      if (callback) {
        if (typeof callback !== 'function')
          throw new TypeError('callback must be a function');
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

// Set as a replacement for socket.prototype.destroy upon the
// establishment of a new connection.
function socketDestroy(error) {
  var session = this[kSession];
  session.destroy();
  session[kServer] = undefined;
  session[kSocket] = undefined;
  this[kServer] = undefined;
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

// Handler session.on('error') by giving the server
// the opportunity to handle the error. If there is
// no sessionError handler on the server, the socket
// is destroyed.
function sessionOnError(error) {
  var session = this;
  var server = session[kServer];
  if (server.emit('sessionError', error))
    return;
  var socket = session[kSocket];
  socket.destroy(error);
}

// When the socket times out, attempt a graceful shutdown
// of the session
function socketOnTimeout() {
  var socket = this;
  var server = socket[kServer];
  // server can be null if the socket is a client
  if (!server || !server.emit('timeout', this)) {
    var session = socket[kSession];
    session.shutdown(
      {
        graceful: true,
        errorCode: constants.NGHTTP2_NO_ERROR
      },
      this.destroy.bind(this));
  }
}

// Handles socket.on('error') by giving the server an opportunity
// to handle the error. If no socketError handler is configured,
// destroy to destroying the socket.
function socketOnError(error) {
  if (kRenegTest.test(error.message))
    return this.destroy();
  var server = this[kServer];
  if (!server.emit('socketError', error, this))
    this.destroy(error);
}

// Handles the on('stream') event for a session and forwards
// it on to the server object.
function sessionOnStream(stream, headers, flags) {
  var server = this[kServer];
  server.emit('stream', stream, headers, flags);
}

function sessionOnSelectPadding(frameLen, maxPayloadLen, ret) {
  var server = this[kServer];
  if (!server.emit('selectPadding', frameLen, maxPayloadLen, ret)) {
    ret.length = frameLen;
  }
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
  socket.on('error', socketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  // Set up the Session
  var session = createServerSession(this[kOptions], socket);
  session.on('error', sessionOnError);
  session.on('stream', sessionOnStream);
  session.on('selectPadding', sessionOnSelectPadding);

  session[kServer] = this;
  socket[kServer] = this;

  // Complete the handshake by sending the initial settings frame
  session.submitSettings(options.settings);
}

function initializeOptions(options) {
  options = options || {};
  if (typeof options !== 'object')
    throw new TypeError('options must be an object');
  options.allowHalfOpen = true;
  options.settings = options.settings || {};
  if (typeof options.settings !== 'object')
    throw new TypeError('options.settings must be an object');
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
    this.on('newListener', setupCompat);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', onErrorSecureServerSession);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback) {
      if (typeof callback !== 'function')
        throw new TypeError('callback must be a function');
      this.on('timeout', callback);
    }
    return this;
  }
}

class Http2Server extends NETServer {
  constructor(options, requestListener) {
    super(connectionListener);
    this[kOptions] = initializeOptions(options);
    this.timeout = kDefaultSocketTimeout;
    this.on('newListener', setupCompat);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback) {
      if (typeof callback !== 'function')
        throw new TypeError('callback must be a function');
      this.on('timeout', callback);
    }
    return this;
  }
}

function setupCompat(ev) {
  if (ev === 'request') {
    this.removeListener('newListener', setupCompat);
    this.on('stream', onServerStream);
  }
}

function createServerSession(options, socket) {
  return new Http2Session(constants.NGHTTP2_SESSION_SERVER, options, socket);
}

function createClientSession(options, socket) {
  if (!socket) {
    socket = options;
    options = {};
  }

  // TODO mc what are those, can we put those within options?
  const settings = options.settings || {};

  socket.allowHalfOpen = true;

  const session = new Http2Session(constants.NGHTTP2_SESSION_CLIENT,
                                   options, socket);

  // Set up the Socket
  // 1. Do not use nagle's algorithm
  socket.setNoDelay();
  // 2. Disable TLS renegotiation on the socket
  if (typeof socket.disableRenegotiation === 'function')
    socket.disableRenegotiation();
  // 3. Set up the timout
  // TODO @mcollina figure this out, this is not set here
  // if (this.timeout) {
  //   socket.setTimeout(this.timeout);
  //   socket.on('timeout', socketOnTimeout);
  // }
  socket[kDestroySocket] = socket.destroy;
  socket.destroy = socketDestroy;
  socket.on('error', socketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  session.on('error', sessionOnError);
  session.on('stream', sessionOnStream);
  session.on('selectPadding', sessionOnSelectPadding);

  socket[kSession] = session;

  // Complete the handshake by sending the initial settings frame
  // setImmediate(session.submitSettings.bind(session, settings));
  setImmediate(() => session.submitSettings(settings));

  return session;
}

function createSecureServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  return new Http2SecureServer(options, handler);
}

function createServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  return new Http2Server(options, handler);
}

function getDefaultSettings() {
  return binding.getDefaultSettings(new Holder());
}

function getPackedSettings(obj) {
  obj = obj || new Holder();
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
