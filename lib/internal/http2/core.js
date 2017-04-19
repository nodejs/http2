'use strict';

const debug = require('util').debuglog('http2');
const assert = require('assert');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const net = require('net');
const tls = require('tls');
const stream = require('stream');
const timers = require('timers');
const url = require('url');
const URL = url.URL;
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
const TLSServer = tls.Server;

const kAuthority = Symbol('authority');
const kDestroySocket = Symbol('destroy-socket');
const kHandle = Symbol('handle');
const kInit = Symbol('init');
const kInspect = require('internal/util').customInspectSymbol;
const kLocalSettings = Symbol('local-settings');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kProtocol = Symbol('protocol');
const kRemoteSettings = Symbol('remote-settings');
const kServer = Symbol('server');
const kSession = Symbol('session');
const kSocket = Symbol('socket');
const kState = Symbol('state');
const kProceed = Symbol('proceed');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

const NGHTTP2_CANCEL = constants.NGHTTP2_CANCEL;
const NGHTTP2_DEFAULT_WEIGHT = constants.NGHTTP2_DEFAULT_WEIGHT;
const NGHTTP2_FLAG_END_STREAM = constants.NGHTTP2_FLAG_END_STREAM;
const NGHTTP2_HCAT_HEADERS = constants.NGHTTP2_HCAT_HEADERS;
const NGHTTP2_HCAT_PUSH_RESPONSE = constants.NGHTTP2_HCAT_PUSH_RESPONSE;
const NGHTTP2_HCAT_RESPONSE = constants.NGHTTP2_HCAT_RESPONSE;
const NGHTTP2_INTERNAL_ERROR = constants.NGHTTP2_INTERNAL_ERROR;
const NGHTTP2_NO_ERROR = constants.NGHTTP2_NO_ERROR;
const NGHTTP2_PROTOCOL_ERROR = constants.NGHTTP2_PROTOCOL_ERROR;
const NGHTTP2_REFUSED_STREAM = constants.NGHTTP2_REFUSED_STREAM;
const NGHTTP2_SESSION_CLIENT = constants.NGHTTP2_SESSION_CLIENT;
const NGHTTP2_SESSION_SERVER = constants.NGHTTP2_SESSION_SERVER;

const HTTP2_HEADER_AUTHORITY = constants.HTTP2_HEADER_AUTHORITY;
const HTTP2_HEADER_DATE = constants.HTTP2_HEADER_DATE;
const HTTP2_HEADER_METHOD = constants.HTTP2_HEADER_METHOD;
const HTTP2_HEADER_PATH = constants.HTTP2_HEADER_PATH;
const HTTP2_HEADER_SCHEME = constants.HTTP2_HEADER_SCHEME;
const HTTP2_HEADER_STATUS = constants.HTTP2_HEADER_STATUS;

const HTTP_STATUS_CONTENT_RESET = constants.HTTP_STATUS_CONTENT_RESET;
const HTTP_STATUS_OK = constants.HTTP_STATUS_OK;
const HTTP_STATUS_NO_CONTENT = constants.HTTP_STATUS_NO_CONTENT;
const HTTP_STATUS_NOT_MODIFIED = constants.HTTP_STATUS_NOT_MODIFIED;
const HTTP_STATUS_SWITCHING_PROTOCOLS =
  constants.HTTP_STATUS_SWITCHING_PROTOCOLS;

// TODO(jasnell): Currently this throws, but there may be some situations
// where emit('error') may be more appropriate.
function emitErrorIfNecessary(emitter, ret) {
  if (ret < 0) {
    const err = new Error(binding.nghttp2ErrorString(ret));
    err.errno = ret;
    Error.captureStackTrace(err, emitErrorIfNecessary);
    emitter.emit('error', err);
    return true;
  }
  return false;
}

// Called when a new block of headers has been received for a given
// stream. The stream may or may not be new. If the stream is new,
// create the associated Http2Stream instance and emit the 'stream'
// event. If the stream is not new, emit the 'headers' event to pass
// the block of headers on.
function onSessionHeaders(id, cat, flags, headers) {
  timers._unrefActive(this);
  const owner = this[kOwner];
  const state = owner[kState];
  const streams = state.streams;
  let stream = streams.get(id);

  const eos = Boolean(flags & NGHTTP2_FLAG_END_STREAM);

  if (stream === undefined && owner.type === NGHTTP2_SESSION_SERVER) {
    stream = new ServerHttp2Stream(owner, id, { readable: !eos });
    streams.set(id, stream);
    owner.emit('stream', stream, headers, flags);
    return;
  }

  let event;
  switch (cat) {
    case NGHTTP2_HCAT_RESPONSE:
      event = 'response';
      break;
    case NGHTTP2_HCAT_PUSH_RESPONSE:
      event = 'push';
      break;
    case NGHTTP2_HCAT_HEADERS:
      event = eos ? 'trailers' : 'headers';
      break;
    default:
      assert.fail(null, null,
                  'Internal HTTP/2 Error. Invalid headers category.');
  }
  stream.emit(event, headers, flags);
}

// Called to determine if there are trailers to be sent at the end of a
// Stream. The 'fetchTrailers' event is emitted and passed a holder object.
// The trailers to return are set on that object by the handler. Once the
// event handler returns, those are sent off for processing. Note that this
// is a necessarily synchronous operation. We need to know immediately if
// there are trailing headers to send.
function onSessionTrailers(id) {
  const owner = this[kOwner];
  const state = owner[kState];
  const streams = state.streams;
  const stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  const trailers = Object.create(null);
  stream.emit('fetchTrailers', trailers);
  return mapToHeaders(trailers);
}

// Called when the stream is closed. The streamClosed event is emitted on the
// Http2Stream instance. Note that this event is distinctly different than the
// require('stream') interface 'close' event which deals with the state of the
// Readable and Writable sides of the Duplex.
function onSessionStreamClose(id, code) {
  const owner = this[kOwner];
  const state = owner[kState];
  const streams = state.streams;
  const stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  timers._unrefActive(this); // Unref the session timer
  timers._unrefActive(stream); // Unref the stream timer
  // Notify the stream that it has been closed.
  stream.emit('streamClosed', code);
  timers.unenroll(stream);
  stream[kSession] = undefined;
  streams.delete(id);
}

// Called when an error event needs to be triggered
function onSessionError(error) {
  timers._unrefActive(this);
  const owner = this[kOwner];
  owner.emit('error', error);
}

// Receives a chunk of data for a given stream and forwards it on
// to the Http2Stream Duplex for processing.
function onSessionRead(nread, buf, handle) {
  const owner = this[kOwner];
  const sessionState = owner[kState];
  const streams = sessionState.streams;
  const id = handle.id;
  const stream = streams.get(id);
  assert(stream, 'Internal HTTP/2 Failure. Stream does not exist.');
  const state = stream[kState];
  timers._unrefActive(this);
  timers._unrefActive(stream);
  if (!stream.push(buf)) {
    if (emitErrorIfNecessary(this, this.streamReadStop(id)))
      return;
    state.reading = false;
  }
}

// Called when the remote peer settings have been updated.
// Resets the cached settings.
function onSettings() {
  timers._unrefActive(this);
  const owner = this[kOwner];
  owner[kRemoteSettings] = undefined;
}

// Called when a requested session shutdown has been completed.
function onSessionShutdownComplete(status, wrap) {
  if (wrap && typeof wrap.callback === 'function')
    wrap.callback(status);
  wrap[kOwner] = undefined;
}

function onSelectPadding(frameLen, maxFramePayloadLen) {
  const owner = this[kOwner];
  const ret = {length: frameLen};
  owner.emit('selectPadding', frameLen, maxFramePayloadLen, ret);
  return Math.min(maxFramePayloadLen, Math.max(frameLen, ret.length | 0));
}

function requestOnConnect(headers, options) {
  const session = this[kSession];
  const state = session[kState];
  const streams = state.streams;
  const handle = session[kHandle];
  const ret = handle.submitRequest(mapToHeaders(headers),
                                   Boolean(options.endStream),
                                   options.parent | 0,
                                   options.weight | 0,
                                   Boolean(options.exclusive));
  if (emitErrorIfNecessary(this, ret))
    return;
  this[kInit](ret);
  streams.set(ret, this);
}

function request(headers, options) {
  timers._unrefActive(this);
  options = options || {};
  headers = headers || {};

  if (headers[HTTP2_HEADER_METHOD] === undefined)
    headers[HTTP2_HEADER_METHOD] = 'GET';
  if (headers[HTTP2_HEADER_AUTHORITY] === undefined)
    headers[HTTP2_HEADER_AUTHORITY] = this[kAuthority];
  if (headers[HTTP2_HEADER_SCHEME] === undefined)
    headers[HTTP2_HEADER_SCHEME] = this[kProtocol].slice(0, -1);
  if (headers[HTTP2_HEADER_PATH] === undefined)
    headers[HTTP2_HEADER_PATH] = '/';

  if (typeof options !== 'object')
    throw new TypeError('options must be an object');
  if (options.weight === undefined)
    options.weight = NGHTTP2_DEFAULT_WEIGHT;
  if (options.parent === undefined)
    options.parent = 0;
  if (options.exclusive === undefined)
    options.exclusive = false;
  if (options.endStream === undefined)
    options.endStream = false;

  const stream = new ClientHttp2Stream(this, {});
  const onConnect = requestOnConnect.bind(stream, headers, options);

  const state = this[kState];
  if (state.connecting) {
    stream.on('connect', onConnect);
  } else {
    onConnect();
  }
  return stream;
}

function setupHandle(session, socket, type, options, settings) {
  return function() {
    const handle = new binding.Http2Session(type, options);
    handle[kOwner] = session;
    session[kHandle] = handle;
    handle.onsettings = onSettings;
    handle.onheaders = onSessionHeaders;
    handle.ontrailers = onSessionTrailers;
    handle.onstreamclose = onSessionStreamClose;
    handle.onerror = onSessionError;
    handle.onread = onSessionRead;
    handle.ongetpadding = onSelectPadding;
    handle.consume(socket._handle._externalStream);
    session.submitSettings(settings);
    const state = session[kState];
    state.connecting = false;
    session.emit('connect', session, socket);
  };
}

class Http2Session extends EventEmitter {
  constructor(type, options, socket, settings) {
    super();
    if (type !== NGHTTP2_SESSION_SERVER &&
        type !== NGHTTP2_SESSION_CLIENT) {
      throw new TypeError(
          'type must be one of http2.constants.NGHTTP2_SESSION_SERVER ' +
          'or http2.constants.NGHTTP2_SESSION_CLIENT');
    }
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    if (!(socket instanceof net.Socket))
      throw new TypeError('socket must be a net.Socket');
    if (socket[kSession])
      throw new Error('socket is already associated with an Http2Session');

    if (type === NGHTTP2_SESSION_CLIENT) {
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
    this[kState] = {
      streams: new Map()
    };
    this[kSocket] = socket;

    Object.defineProperty(this, 'type', {
      configurable: false,
      enumerable: true,
      value: type
    });

    const setupFn = setupHandle(this, socket, type, options, settings);
    if (socket.connecting) {
      this[kState].connecting = true;
      socket.once('connect', setupFn);
    } else {
      setupFn();
    }

    // Any individual session can have any number of active open
    // streams, these may all need to be made aware of changes
    // in state that occur -- such as when the associated socket
    // is closed. To do so, we need to set the max listener count
    // to something more reasonable.
    this.setMaxListeners(Infinity);
  }

  [kInspect](depth, opts) {
    const state = this[kState];
    const obj = {
      type: this.type,
      destroyed: Boolean(state.destroyed),
      state: this.state,
      localSettings: this.localSettings,
      remoteSettings: this.remoteSettings
    };
    return `Http2Session ${util.format(obj)}`;
  }

  get socket() {
    const socket = this[kSocket];
    return socket;
  }

  get destroyed() {
    const state = this[kState];
    return Boolean(state.destroyed);
  }

  get _handle() {
    return this[kHandle];
  }

  get state() {
    const obj = {};
    const handle = this[kHandle];
    handle.getSessionState(obj);
    return obj;
  }

  get localSettings() {
    const handle = this[kHandle];
    let settings = this[kLocalSettings];
    if (!settings) {
      settings = this[kLocalSettings] = {};
      handle.getLocalSettings(settings);
    }
    return settings;
  }

  get remoteSettings() {
    const handle = this[kHandle];
    let settings = this[kRemoteSettings];
    if (!settings) {
      settings = this[kRemoteSettings] = {};
      handle.getRemoteSettings(settings);
    }
    return settings;
  }

  submitSettings(settings) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    if (typeof settings !== 'object')
      throw new TypeError('settings must be an object');
    this[kLocalSettings] = undefined;
    emitErrorIfNecessary(this, handle.submitSettings(settings));
  }

  submitPriority(stream, options) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream must be an Http2Stream');
    options = options || {};
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    if (options.weight === undefined)
      options.weight = NGHTTP2_DEFAULT_WEIGHT;
    if (options.parent === undefined)
      options.parent = 0;
    if (options.exclusive === undefined)
      options.exclusive = false;
    if (options.silent === undefined)
      options.silent = false;
    emitErrorIfNecessary(
      this,
      handle.submitPriority(
        stream.id,
        options.parent | 0,
        options.weight | 0,
        Boolean(options.exclusive),
        Boolean(options.silent)));
  }

  rstStream(stream, code) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream must be an Http2Stream');
    emitErrorIfNecessary(this, handle.submitRstStream(stream.id, Number(code)));
  }

  destroy() {
    const state = this[kState];
    const streams = state.streams;
    state.destroyed = true;
    timers.unenroll(this);
    streams.forEach((value, key) => {
      value[kSession] = undefined;
      value[kState].shutdown = true;
    });
    streams.clear();
    const handle = this[kHandle];
    if (handle) {
      handle.unconsume();
      setImmediate(() => handle.destroy());
    }
    this.emit('close');
  }

  shutdown(options, callback) {
    const handle = this[kHandle];
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

    const sessionShutdownWrap = new SessionShutdownWrap();
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
  timers._unrefActive(handle[kOwner]);
  if (typeof req.callback === 'function')
    req.callback();
  this.handle = undefined;
}

function onHandleFinish() {
  const session = this[kSession];
  if (this.id === undefined) {
    this.on('connect', () => {
      const handle = session[kHandle];
      emitErrorIfNecessary(this, handle.shutdownStream(this.id));
    });
  } else {
    const handle = session[kHandle];
    emitErrorIfNecessary(this, handle.shutdownStream(this.id));
  }
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
    this.emit('aborted', code !== NGHTTP2_NO_ERROR, code);
  }
  // Close the readable side
  this.push(null);
  // Close the writable side
  this.end();
}

function onStreamError(error) {
  const session = this[kSession];
  if (!session.emit('streamError', error, this))
    session.emit('error', error, this);
}

function streamOnResume() {
  if (this._paused)
    return this.pause();
  const session = this[kSession];
  const state = this[kState];
  if (this.id === undefined) {
    this.on('connect', () => {
      state.reading = true;
      const handle = session[kHandle];
      emitErrorIfNecessary(this, handle.streamReadStart(this.id));
    });
    return;
  }
  if (session && !state.reading) {
    state.reading = true;
    const handle = session[kHandle];
    emitErrorIfNecessary(this, handle.streamReadStart(this.id));
  }
}

function streamOnPause() {
  const session = this[kSession];
  const state = this[kState];
  if (session && state.reading) {
    const handle = session[kHandle];
    state.reading = false;
    emitErrorIfNecessary(this, handle.streamReadStop(this.id));
  }
}

function streamOnDrain() {
  const needPause = 0 > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}

function streamOnSessionConnect() {
  const state = this[kState];
  state.connecting = false;
  this.emit('connect');
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
  constructor(session, options) {
    options.allowHalfOpen = true;
    super(options);
    this[kState] = {};
    this[kSession] = session;
    this.on('finish', onHandleFinish);
    this.on('streamClosed', onStreamClosed);
    this.on('error', onStreamError);
    this.on('resume', streamOnResume);
    this.on('pause', streamOnPause);
    this.on('drain', streamOnDrain);
    session.on('close', onSessionClose.bind(this));

    const sessionState = session[kState];
    if (sessionState.connecting) {
      this[kState].connecting = true;
      session.on('connect', streamOnSessionConnect.bind(this));
    }
  }

  [kInit](id) {
    Object.defineProperty(this, 'id', {
      configurable: false,
      enumerable: true,
      value: id
    });
  }

  [kInspect](depth, opts) {
    const obj = {
      id: this.id,
      state: this.state,
      readableState: this._readableState,
      writeableSate: this._writableState
    };
    return `Http2Stream ${util.format(obj)}`;
  }

  get session() {
    return this[kSession];
  }

  get state() {
    const obj = {};
    if (this.id === undefined)
      return obj;
    const session = this[kSession];
    const handle = session[kHandle];
    emitErrorIfNecessary(this, handle.getStreamState(this.id, obj));
    return obj;
  }

  [kProceed]() {
    throw new Error('implementors MUST implement this');
  }

  _write(data, encoding, cb) {
    if (this.id === undefined) {
      this.once('connect', () => this._write(data, encoding, cb));
      return;
    }
    timers._unrefActive(this);
    const state = this[kState];
    if (!state.headersSent)
      this[kProceed]();
    const session = this[kSession];
    const handle = session[kHandle];
    const req = new WriteWrap();
    req.stream = this.id;
    req.handle = handle;
    req.callback = cb;
    req.oncomplete = afterDoStreamWrite;
    req.async = false;
    const enc = data instanceof Buffer ? 'buffer' : encoding;
    const err = createWriteReq(req, handle, data, enc);
    if (err)
      throw util._errnoException(err, 'write', req.error);
    this._bytesDispatched += req.bytes;

  }

  _writev(data, cb) {
    if (this.id === undefined) {
      this.once('connect', () => this._writev(data, cb));
      return;
    }
    timers._unrefActive(this);
    const state = this[kState];
    if (!state.headersSent)
      this[kProceed]();
    const session = this[kSession];
    const handle = session[kHandle];
    const req = new WriteWrap();
    req.stream = this.id;
    req.handle = handle;
    req.callback = cb;
    req.oncomplete = afterDoStreamWrite;
    req.async = false;
    const chunks = new Array(data.length << 1);
    for (var i = 0; i < data.length; i++) {
      const entry = data[i];
      chunks[i * 2] = entry.chunk;
      chunks[i * 2 + 1] = entry.encoding;
    }
    const err = handle.writev(req, chunks);
    if (err)
      throw util._errnoException(err, 'write', req.error);
  }

  _read(nread) {
    if (this.id === undefined) {
      this.once('connect', () => this._read(nread));
      return;
    }
    timers._unrefActive(this);
    const state = this[kState];
    if (state.reading)
      return;
    state.reading = true;
    const session = this[kSession];
    const handle = session[kHandle];
    emitErrorIfNecessary(this, handle.streamReadStart(this.id));
  }

  rstStream(code) {
    if (this.id === undefined) {
      this.once('connect', () => this.rstStream(code));
      return;
    }
    timers._unrefActive(this);
    const session = this[kSession];
    session.rstStream(this, code);
  }

  rstWithNoError() {
    this.rstStream(NGHTTP2_NO_ERROR);
  }

  rstWithProtocolError() {
    this.rstStream(NGHTTP2_PROTOCOL_ERROR);
  }

  rstWithCancel() {
    this.rstStream(NGHTTP2_CANCEL);
  }

  rstWithRefuse() {
    this.rstStream(NGHTTP2_REFUSED_STREAM);
  }

  rstWithInternalError() {
    this.rstStream(NGHTTP2_INTERNAL_ERROR);
  }

  priority(options) {
    if (this.id === undefined) {
      this.once('connect', () => this.priority(options));
      return;
    }
    timers._unrefActive(this);
    const session = this[kSession];
    session.submitPriority(this, options);
  }

  // Sends a block of headers.
  sendHeaders(headers) {
    if (this.id === undefined) {
      this.once('connect', () => this.sendHeaders(headers));
      return;
    }
    timers._unrefActive(this);
    const state = this[kState];
    const session = this[kSession];
    const handle = session[kHandle];

    if (headers && (typeof headers !== 'object' || Array.isArray(headers)))
      throw new TypeError('headers must be an object');
    headers = Object.assign(Object.create(null), headers);
    if (headers[HTTP2_HEADER_STATUS] != null) {
      if (state.headersSent) {
        throw new Error(
          'Cannot specify HTTP status header after response initiated');
      }
      const statusCode = headers[HTTP2_HEADER_STATUS] |= 0;
      if (statusCode === HTTP_STATUS_SWITCHING_PROTOCOLS)
        throw new RangeError(
          'HTTP status code 101 (Switching Protocols) is forbidden in HTTP/2');
      if (statusCode < 100 || statusCode >= 200)
        throw new RangeError('Invalid informational status code');
    }

    emitErrorIfNecessary(this,
                         handle.sendHeaders(this.id, mapToHeaders(headers)));
  }
}

class ServerHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, options);
    this[kInit](id);
  }

  pushStream(headers, options, callback) {
    timers._unrefActive(this);
    const session = this[kSession];
    const state = session[kState];
    const streams = state.streams;
    const handle = session[kHandle];

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
    headers = Object.assign(Object.create(null), headers);

    if (headers[HTTP2_HEADER_METHOD] === undefined)
      headers[HTTP2_HEADER_METHOD] = 'GET';

    if (headers[HTTP2_HEADER_AUTHORITY] === undefined)
      throw new Error('The :authority header is required');
    if (headers[HTTP2_HEADER_PATH] === undefined)
      throw new Error('The :path header is required');
    if (headers[HTTP2_HEADER_SCHEME] === undefined)
      throw new Error('The :scheme header is required');

    const ret = handle.submitPushPromise(this.id,
                                         mapToHeaders(headers),
                                         options.endStream);
    if (ret <= 0) {
      emitErrorIfNecessary(this, ret);
    } else {
      options.readable = !options.endStream;
      const stream = new ServerHttp2Stream(session, ret, options);
      streams.set(ret, stream);
      process.nextTick(callback, stream, headers, 0);
    }
  }

  respond(headers, options) {
    timers._unrefActive(this);
    const state = this[kState];
    const session = this[kSession];
    const handle = session[kHandle];

    if (state.headersSent)
      throw new Error('Response has already been initiated.');
    state.headersSent = true;

    options = Object.create(options || null);
    if (typeof options !== 'object')
      throw new TypeError('options must be an object');
    options.endStream = Boolean(options.endStream);

    if (headers && (typeof headers !== 'object' || Array.isArray(headers)))
      throw new TypeError('headers must be an object');
    headers = Object.assign(Object.create(null), headers);
    if (headers[HTTP2_HEADER_STATUS] == null) {
      headers[HTTP2_HEADER_STATUS] = HTTP_STATUS_OK;
    } else {
      const statusCode = headers[HTTP2_HEADER_STATUS] |= 0;
      if (statusCode < 200 || statusCode > 999)
        throw new RangeError('Invalid status code.');

      // Payload/DATA frames are not permitted in these cases
      if (statusCode === HTTP_STATUS_NO_CONTENT ||
          statusCode === HTTP_STATUS_CONTENT_RESET ||
          statusCode === HTTP_STATUS_NOT_MODIFIED) {
        options.endStream = true;
      }
    }
    headers[HTTP2_HEADER_DATE] = utcDate();

    // Close the writable side if the endStream option is set
    if (options.endStream)
      this.end();

    emitErrorIfNecessary(
      this,
      handle.submitResponse(this.id,
                            mapToHeaders(headers),
                            options.endStream));
  }
}

ServerHttp2Stream.prototype[kProceed] = ServerHttp2Stream.prototype.respond;

class ClientHttp2Stream extends Http2Stream {
  constructor(session, options) {
    super(session, options);
    this[kState].headersSent = true;
  }
}

const setTimeout = {
  configurable: true,
  enumerable: true,
  writable: true,
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

Object.defineProperties(Http2Stream.prototype, {
  setTimeout,
  onTimeout
});
Object.defineProperties(Http2Session.prototype, {
  setTimeout,
  onTimeout
});

// --------------------------------------------------------------------

// Set as a replacement for socket.prototype.destroy upon the
// establishment of a new connection.
function socketDestroy(error) {
  const session = this[kSession];
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
  const needPause = 0 > this._writableState.highWaterMark;
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
  const session = this;
  const server = session[kServer];
  if (server.emit('sessionError', error))
    return;
  const socket = session[kSocket];
  socket.destroy(error);
}

// When the socket times out, attempt a graceful shutdown
// of the session
function socketOnTimeout() {
  const socket = this;
  const server = socket[kServer];
  // server can be null if the socket is a client
  if (!server || !server.emit('timeout', this)) {
    const session = socket[kSession];
    session.shutdown(
      {
        graceful: true,
        errorCode: NGHTTP2_NO_ERROR
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
  const server = this[kServer];
  if (!server.emit('socketError', error, this))
    this.destroy(error);
}

// Handles the on('stream') event for a session and forwards
// it on to the server object.
function sessionOnStream(stream, headers, flags) {
  const server = this[kServer];
  server.emit('stream', stream, headers, flags);
}

function sessionOnSelectPadding(frameLen, maxPayloadLen, ret) {
  const server = this[kServer];
  if (!server.emit('selectPadding', frameLen, maxPayloadLen, ret)) {
    ret.length = frameLen;
  }
}

function connectionListener(socket) {
  const options = this[kOptions] || {};

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
  const session = createServerSession(this[kOptions], socket, options.settings);
  session.on('error', sessionOnError);
  session.on('stream', sessionOnStream);
  session.on('selectPadding', sessionOnSelectPadding);

  session[kServer] = this;
  socket[kServer] = this;
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

function createServerSession(options, socket, settings) {
  return new Http2Session(NGHTTP2_SESSION_SERVER,
                          options, socket, settings);
}


function clientSocketOnError(error) {
  if (kRenegTest.test(error.message))
    return this.destroy();
  const session = this[kSession];
  if (!session.emit('error', error, this)) {
    this.destroy(error);
  }
}

function clientSessionOnError(error) {
  const socket = this[kSocket];
  if (socket)
    socket.destroy(error);
}

function createClientSession(options, socket) {
  if (!socket) {
    socket = options;
    options = {};
  }

  // TODO mc what are those, can we put those within options?
  const settings = options.settings || {};

  socket.allowHalfOpen = true;

  const session = new Http2Session(NGHTTP2_SESSION_CLIENT,
                                   options, socket, settings);

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
  socket.on('error', clientSocketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  session.on('error', clientSessionOnError);
  session.on('stream', sessionOnStream);
  session.on('selectPadding', sessionOnSelectPadding);

  socket[kSession] = session;

  return session;
}

function connect(authority, options, listener) {
  if (typeof options === 'function') {
    listener = options;
    options = Object.create(null);
  } else if (options === undefined) {
    options = Object.create(null);
  }
  if (typeof options !== 'object')
    throw new TypeError('"options" must be an object');

  if (typeof authority === 'string')
    authority = new URL(authority);
  else if (typeof authority !== 'object')
    throw new TypeError('"authority" must be a string or URL-like object');

  const protocol = authority.protocol || options.protocol || 'https:';
  const port = '' + (authority.port !== '' ? authority.port : 443);
  const host = authority.hostname || authority.host || 'localhost';

  let socket;
  switch (protocol) {
    case 'http:':
      socket = net.connect(port, host);
      break;
    case 'https:':
      socket = tls.connect(port, host, options);
      break;
    default:
      throw new TypeError(`protocol "${protocol}" in unsupported.`);
  }

  const session = createClientSession(options, socket);
  session[kAuthority] = `${host}:${port}`;
  session[kProtocol] = protocol;
  if (typeof listener === 'function')
    session.once('connect', listener);
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

const defaultSettings = new Uint32Array(binding.defaultSettingsArrayBuffer);
binding.refreshDefaultSettings();
const DEFAULT_SETTINGS_HEADER_TABLE_SIZE = 0;
const DEFAULT_SETTINGS_ENABLE_PUSH = 1;
const DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE = 2;
const DEFAULT_SETTINGS_MAX_FRAME_SIZE = 3;

function getDefaultSettings() {
  const holder = Object.create(null);
  holder.headerTableSize =
    defaultSettings[DEFAULT_SETTINGS_HEADER_TABLE_SIZE];
  holder.enablePush =
    Boolean(defaultSettings[DEFAULT_SETTINGS_ENABLE_PUSH]);
  holder.initialWindowSize =
    defaultSettings[DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE];
  holder.maxFrameSize =
    defaultSettings[DEFAULT_SETTINGS_MAX_FRAME_SIZE];
  return holder;
}

// Returns a Base64 encoded settings frame payload from the given
// object. The value is suitable for passing as the value of the
// HTTP2-Settings header frame.
function getPackedSettings(obj) {
  obj = obj || Object.create(null);
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
  createClientSession,
  connect
};
