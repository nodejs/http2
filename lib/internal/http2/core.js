'use strict';

const {
  mapToHeaders
} = require('internal/http2/util');

const {utcDate} = require('internal/http');

const assert = require('assert');
const Buffer = require('buffer').Buffer;
const binding = process.binding('http2');
const SessionShutdownWrap = binding.SessionShutdownWrap;
const streamwrap = process.binding('stream_wrap');
const WriteWrap = streamwrap.WriteWrap;
const constants = binding.constants;
const stream = require('stream');
const timers = require('timers');
const Duplex = stream.Duplex;
const EventEmitter = require('events');
const linkedList = require('internal/linkedlist');
const net = require('net');
const NETServer = net.Server;
const TLSServer = require('tls').Server;

const kDestroySocket = Symbol('destroy-socket');
const kHandle = Symbol('handle');
const kId = Symbol('id');
const kInspect = require('internal/util').customInspectSymbol;
const kLocalSettings = Symbol('local-settings');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kRemoteSettings = Symbol('remote-settings');;
const kServer = Symbol('server');
const kSession = Symbol('session');
const kSocket = Symbol('socket');
const kState = Symbol('state');
const kStreams = Symbol('streams');
const kType = Symbol('type');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

function unrefTimer(item) {
  timers._unrefActive(item);
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

  // If this is a server, the stream might need to be created. If it's
  // client side the stream object should already be in the cache by this
  // point in time.
  if (stream === undefined && type === constants.NGHTTP2_SESSION_SERVER) {
    var eos = flags & constants.NGHTTP2_FLAG_END_STREAM;
    var options = { readable: !Boolean(eos) };
    stream = new ServerHttp2Stream(owner, id, options);
    streams.set(id, stream);
    // Notify session that a new stream has been initialized
    owner.emit('stream', stream);
  }
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  // Notify stream that a block of headers is available
  stream.emit('headers', cat, headers, flags);
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
  var trailers = {};
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
  unrefTimer(this);
  unrefTimer(stream);
  if (!stream.push(buf))
    this.streamReadStop(id);
}

// Called when the remote peer settings have been updated.
// Resets the cached settings.
function onSettings() {
  unrefTimer(this);
  var owner = this[kOwner];
  owner[kRemoteSettings] = undefined;
}

// Callend when a requested session shutdown has been completed.
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

  [kInspect](depth, opts) {
    var ret = 'Http2Session {\n';
    // TODO(jasnell): Fill this in
    ret += '}';
    return ret;
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
  if ((this._readableState && !this._readableState.ended) ||
      (this._writableState && !this._writableState.ended)) {
    this.emit('aborted', code !== constants.NGHTTP2_NO_ERROR, code);
  }
  // Close the readable side
  this.push(null);
  // Close the writable side
  this.end();
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
    this.on('streamClosed', onStreamClosed.bind(this));
    session.on('close', onSessionClose.bind(this));
  }

  [kInspect](depth, opts) {
    var ret = 'Http2Stream {\n';
    ret += `  id: ${this[kId]}\n`;
    ret += '}';
    return ret;
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

  // Sends a block of headers
  sendHeaders(headers) {
    unrefTimer(this);
    var session = this[kSession];
    var handle = session[kHandle];
    handle.sendHeaders(this[kId], mapToHeaders(headers));
  }
}

class ServerHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, id, options);
  }

  // Begins the response/request
  respond(statusCode, headers, options) {
    var state = this[kState];
    if (state.headersSent)
      throw new Error('Response has already been initiated.');
    state.headersSent = true;

    unrefTimer(this);
    options = options || {};
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    options.endStream = Boolean(options.endStream);

    statusCode |= 0;
    if (statusCode < 200 || stateCode > 999)
      throw new RangeError('Invalid status code.');
    headers[constants.HTTP2_HEADER_STATUS] = statusCode;
    headers[constants.HTTP2_HEADER_DATE] = utcDate();

    // Close the writable side if the endStream option is set
    if (options.endStream)
      this.end();
    var session = this[kSession];
    var handle = session[kHandle];
    handle.submitResponse(this[kId], mapToHeaders(headers), options.endStream);
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
  if (!server.emit('timeout', this)) {
    var session = socket[kSession];
    session.shutdown({
      graceful: true,
      errorCode: constants.NGHTTP2_NO_ERROR},
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
function sessionOnStream(stream) {
  var server = this[kServer];
  server.emit('stream', stream);
}

// Notifies the session that the socket has closed.
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
  session.on('stream', sessionOnStream);

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
    if (typeof requestListener === 'function')
      this.on('stream', requestListener);
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
      this.on('stream', requestListener);
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
