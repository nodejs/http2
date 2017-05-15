'use strict';

const debug = require('util').debuglog('http2');
const assert = require('assert');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const net = require('net');
const tls = require('tls');
const stream = require('stream');
const timers = require('timers');
const util = require('util');
const errors = require('internal/errors');
const { URL } = require('url');
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

const kInspect = require('internal/util').customInspectSymbol;

const kAuthority = Symbol('authority');
const kDestroySocket = Symbol('destroy-socket');
const kHandle = Symbol('handle');
const kInit = Symbol('init');
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

const {
  NGHTTP2_CANCEL,
  NGHTTP2_DEFAULT_WEIGHT,
  NGHTTP2_FLAG_END_STREAM,
  NGHTTP2_HCAT_REQUEST,
  NGHTTP2_HCAT_HEADERS,
  NGHTTP2_HCAT_PUSH_RESPONSE,
  NGHTTP2_HCAT_RESPONSE,
  NGHTTP2_INTERNAL_ERROR,
  NGHTTP2_NO_ERROR,
  NGHTTP2_PROTOCOL_ERROR,
  NGHTTP2_REFUSED_STREAM,
  NGHTTP2_SESSION_CLIENT,
  NGHTTP2_SESSION_SERVER,

  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_DATE,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_STATUS,
  HTTP2_HEADER_COOKIE,

  HTTP_STATUS_CONTENT_RESET,
  HTTP_STATUS_OK,
  HTTP_STATUS_NO_CONTENT,
  HTTP_STATUS_NOT_MODIFIED,
  HTTP_STATUS_SWITCHING_PROTOCOLS
} = constants;

// The following ArrayBuffer instances are used to share memory more efficiently
// with the native binding side for a number of methods. These are not intended
// to be used directly by users in any way. The ArrayBuffers are created on
// the native side with values that are filled in on demand, the js code then
// reads those values out. The set of IDX constants that follow identify the
// relevant data positions within these buffers.
const defaultSettings = new Uint32Array(binding.defaultSettingsArrayBuffer);
const settingsBuffer = new Uint32Array(binding.settingsArrayBuffer);

// Note that Float64Array is used here because there is no Int64Array available
// and these deal with numbers that can be beyond the range of Uint32 and Int32.
// The values set on the native side will always be integers. This is not a
// unique example of this, this pattern can be found in use in other parts of
// Node.js core as a performance optimization.
const sessionState = new Float64Array(binding.sessionStateArrayBuffer);
const streamState = new Float64Array(binding.streamStateArrayBuffer);

const IDX_SETTINGS_HEADER_TABLE_SIZE = 0;
const IDX_SETTINGS_ENABLE_PUSH = 1;
const IDX_SETTINGS_INITIAL_WINDOW_SIZE = 2;
const IDX_SETTINGS_MAX_FRAME_SIZE = 3;
const IDX_SETTINGS_MAX_CONCURRENT_STREAMS = 4;
const IDX_SETTINGS_MAX_HEADER_LIST_SIZE = 5;

const IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE = 0;
const IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH = 1;
const IDX_SESSION_STATE_NEXT_STREAM_ID = 2;
const IDX_SESSION_STATE_LOCAL_WINDOW_SIZE = 3;
const IDX_SESSION_STATE_LAST_PROC_STREAM_ID = 4;
const IDX_SESSION_STATE_REMOTE_WINDOW_SIZE = 5;
const IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE = 6;
const IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE = 7;
const IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE = 8;
const IDX_STREAM_STATE = 0;
const IDX_STREAM_STATE_WEIGHT = 1;
const IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT = 2;
const IDX_STREAM_STATE_LOCAL_CLOSE = 3;
const IDX_STREAM_STATE_REMOTE_CLOSE = 4;
const IDX_STREAM_STATE_LOCAL_WINDOW_SIZE = 5;

binding.refreshDefaultSettings();

function emitErrorIfNecessary(emitter, ret) {
  if (ret < 0) {
    const err = new Error(binding.nghttp2ErrorString(ret));
    err.code = 'ERR_HTTP2_ERROR';
    err.name = 'Name [ERR_HTTP2_ERROR]';
    err.errno = ret;
    Error.captureStackTrace(err, emitErrorIfNecessary);
    emitter.emit('error', err);
    return true;
  }
  return false;
}

function assertIsObject(value, name, types) {
  if (value !== undefined &&
      (value === null ||
       typeof value !== 'object' ||
       Array.isArray(value))) {
    const err = errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 name,
                                 types || 'object');
    Error.captureStackTrace(err, assertIsObject);
    throw err;
  }
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

  const endOfStream = !!(flags & NGHTTP2_FLAG_END_STREAM);
  let stream = streams.get(id);

  // https://tools.ietf.org/html/rfc7540#section-8.1.2.5
  // "...If there are multiple Cookie header fields after decompression,
  //  these MUST be concatenated into a single octet string using the
  //  two-octet delimiter of 0x3B, 0x20 (the ASCII string "; ") before being
  //  passed into a non-HTTP/2 context."
  if (Array.isArray(headers[HTTP2_HEADER_COOKIE]))
    headers[HTTP2_HEADER_COOKIE] =
      headers[HTTP2_HEADER_COOKIE].join('; ');

  if (stream === undefined) {
    switch (owner.type) {
      case NGHTTP2_SESSION_SERVER:
        stream = new ServerHttp2Stream(owner, id, { readable: !endOfStream });
        break;
      case NGHTTP2_SESSION_CLIENT:
        stream = new ClientHttp2Stream(owner, id, { readable: !endOfStream });
        break;
      default:
        assert.fail(null, null,
                    'Internal HTTP/2 Error. Invalid session type. Please ' +
                    'report this as a bug in Node.js');
    }
    streams.set(id, stream);
    owner.emit('stream', stream, headers, flags);
  } else {
    let event;
    switch (cat) {
      case NGHTTP2_HCAT_REQUEST:
        event = 'request';
        break;
      case NGHTTP2_HCAT_RESPONSE:
        event = 'response';
        break;
      case NGHTTP2_HCAT_PUSH_RESPONSE:
        event = 'push';
        break;
      case NGHTTP2_HCAT_HEADERS:
        event = endOfStream ? 'trailers' : 'headers';
        break;
      default:
        assert.fail(null, null,
                    'Internal HTTP/2 Error. Invalid headers category. Please ' +
                    'report this as a bug in Node.js');
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
  const owner = this[kOwner];
  const state = owner[kState];
  const streams = state.streams;
  const stream = streams.get(id);
  // It should not be possible for the stream not to exist at this point.
  // If it does not exist, there is something very very wrong.
  assert(stream !== undefined,
         'Internal HTTP/2 Failure. Stream does not exist. Please ' +
         'report this as a bug in Node.js');
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
  const alreadyClosed = stream === undefined;
  if (alreadyClosed)
    return;
  timers._unrefActive(this); // Reset the session timout timer
  timers._unrefActive(stream); // Reset the stream timout timer
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
  // It should not be possible for the stream to not exist at this point.
  // If it does not, something is very very wrong
  assert(stream !== undefined,
         'Internal HTTP/2 Failure. Stream does not exist. Please ' +
         'report this as a bug in Node.js');
  const state = stream[kState];
  timers._unrefActive(this); // Reset the session timeout timer
  timers._unrefActive(stream); // Reset the stream timout timer
  if (!stream.push(buf)) {
    // If the chunk cannot be pushed, stop reading.
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

// If the stream exists, an attempt will be made to emit an event
// on the stream object itself. Otherwise, forward it on to the
// session (which may, in turn, forward it on to the server)
function onPriority(id, parent, weight, exclusive) {
  debug(`priority advisement for stream ${id}: \n` +
        `  parent: ${parent},\n  weight: ${weight},\n` +
        `  exclusive: ${exclusive}`);
  timers._unrefActive(this);
  const owner = this[kOwner];
  const state = owner[kState];
  const streams = state.streams;
  const stream = streams.get(id);
  if (stream === undefined ||
      !stream.emit('priority', parent, weight, exclusive)) {
    owner.emit('priority', id, parent, weight, exclusive);
  }
}

// Called when a requested session shutdown has been completed.
function onSessionShutdownComplete(status, wrap) {
  if (wrap && typeof wrap.callback === 'function')
    wrap.callback(status);
  wrap[kOwner] = undefined;
}

// Returns the padding to use per frame. The selectPadding event is
// emitted with three arguments: the length of frame data, the max
// allowed length of the frame payload, and a return value object.
// The return object has a single length property that is defaulted
// to frameLen. The handler can change the value of length to specify
// the padding to use. Note that this padding strategy is expensive
// because the onSelectPadding is called once for each frame, which
// means for each frame there's a call across the C++/JS boundary and
// a trip through EventEmitter land. This likely is not going to be
// the most efficient padding strategy to use.
function onSelectPadding(frameLen, maxFramePayloadLen) {
  const owner = this[kOwner];
  const ret = {length: frameLen};
  owner.emit('selectPadding', frameLen, maxFramePayloadLen, ret);
  return Math.min(maxFramePayloadLen, Math.max(frameLen, ret.length | 0));
}

// Called when the socket is connected to handle a pending request.
function requestOnConnect(headers, options) {
  const session = this[kSession];
  const state = session[kState];
  const streams = state.streams;
  const handle = session[kHandle];
  // ret will be either the reserved stream ID (if positive)
  // or an error code (if negative)
  const ret = handle.submitRequest(mapToHeaders(headers),
                                   !!options.endStream,
                                   options.parent | 0,
                                   options.weight | 0,
                                   !!options.exclusive);
  if (emitErrorIfNecessary(this, ret))
    return;
  this[kInit](ret);
  streams.set(ret, this);
}

function validatePriorityOptions(options) {

  if (options.weight === undefined)
    options.weight = NGHTTP2_DEFAULT_WEIGHT;
  else if (typeof options.weight !== 'number') {
    const err = new errors.RangeError('ERR_INVALID_OPT_VALUE',
                                      'weight',
                                      options.weight);
    Error.captureStackTrace(err, validatePriorityOptions);
    throw err;
  }

  if (options.parent === undefined)
    options.parent = 0;
  else if (typeof options.parent !== 'number' || options.parent < 0) {
    const err = new errors.RangeError('ERR_INVALID_OPT_VALUE',
                                      'parent',
                                      options.parent);
    Error.captureStackTrace(err, validatePriorityOptions);
    throw err;
  }

  if (options.exclusive === undefined)
    options.exclusive = false;
  else if (typeof options.exclusive !== 'boolean') {
    const err = new errors.RangeError('ERR_INVALID_OPT_VALUE',
                                      'exclusive',
                                      options.exclusive);
    Error.captureStackTrace(err, validatePriorityOptions);
    throw err;
  }

  if (options.silent === undefined)
    options.silent = false;
  else if (typeof options.silent !== 'boolean') {
    const err = new errors.RangeError('ERR_INVALID_OPT_VALUE',
                                      'silent',
                                      options.silent);
    Error.captureStackTrace(err, validatePriorityOptions);
    throw err;
  }
}

function request(headers, options) {
  timers._unrefActive(this);

  assertIsObject(headers, 'headers');
  assertIsObject(options, 'options');

  headers = Object.assign(Object.create(null), headers);
  options = Object.assign(Object.create(null), options);

  if (headers[HTTP2_HEADER_METHOD] === undefined)
    headers[HTTP2_HEADER_METHOD] = 'GET';
  if (headers[HTTP2_HEADER_AUTHORITY] === undefined)
    headers[HTTP2_HEADER_AUTHORITY] = this[kAuthority];
  if (headers[HTTP2_HEADER_SCHEME] === undefined)
    headers[HTTP2_HEADER_SCHEME] = this[kProtocol].slice(0, -1);
  if (headers[HTTP2_HEADER_PATH] === undefined)
    headers[HTTP2_HEADER_PATH] = '/';

  validatePriorityOptions(options);

  if (options.endStream === undefined) {
    options.endStream = false;
  } else if (typeof options.endStream !== 'boolean') {
    throw new errors.RangeError('ERR_INVALID_OPT_VALUE',
                                'endStream',
                                options.endStream);
  }

  const stream = new ClientHttp2Stream(this, undefined, {});
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
    handle.onpriority = onPriority;
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
    if (type !== NGHTTP2_SESSION_SERVER && type !== NGHTTP2_SESSION_CLIENT) {
      throw new RangeError(
          '"type" must be one of http2.constants.NGHTTP2_SESSION_SERVER ' +
          'or http2.constants.NGHTTP2_SESSION_CLIENT');
    }

    if (options && typeof options !== 'object') {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'options',
                                 'object');
    }
    if (!(socket instanceof net.Socket)) {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'socket',
                                 'net.Socket');
    }
    if (socket[kSession] !== undefined)
      throw new errors.Error('ERR_HTTP2_SOCKET_BOUND');

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
      streams: new Map(),
      destroyed: false
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
    // to something more reasonable because we may have any number
    // of concurrent streams (2^31-1 is the upper limit on the number
    // of streams)
    this.setMaxListeners((2 ** 31) - 1);
  }

  [kInspect](depth, opts) {
    const state = this[kState];
    const obj = {
      type: this.type,
      destroyed: state.destroyed,
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
    return state.destroyed;
  }

  get _handle() {
    return this[kHandle];
  }

  get state() {
    const handle = this[kHandle];
    return handle !== undefined ?
      getSessionState(handle) :
      Object.create(null);
  }

  get localSettings() {
    let settings = this[kLocalSettings];
    if (settings !== undefined)
      return settings;

    const handle = this[kHandle];
    if (handle === undefined)
      return Object.create(null);

    settings = getSettings(handle, false); // Local
    this[kLocalSettings] = settings;
    return settings;
  }

  get remoteSettings() {
    let settings = this[kRemoteSettings];
    if (settings !== undefined)
      return settings;

    const handle = this[kHandle];
    if (handle === undefined)
      return Object.create(null);

    settings = getSettings(handle, true); // Remote
    this[kRemoteSettings] = settings;
    return settings;
  }

  submitSettings(settings) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    assertIsObject(settings, 'settings');
    settings = Object.assign(Object.create(null), settings);
    this[kLocalSettings] = undefined;
    emitErrorIfNecessary(this, handle.submitSettings(settings));
  }

  submitPriority(stream, options) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    if (!(stream instanceof Http2Stream)) {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'stream',
                                 'Http2Stream');
    }
    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);

    validatePriorityOptions(options);

    emitErrorIfNecessary(
      this,
      handle.submitPriority(
        stream.id,
        options.parent | 0,
        options.weight | 0,
        !!options.exclusive,
        !!options.silent));
  }

  rstStream(stream, code) {
    timers._unrefActive(this);
    const handle = this[kHandle];
    if (!(stream instanceof Http2Stream)) {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'stream',
                                 'Http2Stream');
    }
    if (typeof code !== 'number') {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'code',
                                 'number');
    }
    emitErrorIfNecessary(this, handle.submitRstStream(stream.id, code));
  }

  destroy() {
    const state = this[kState];
    const streams = state.streams;
    const socket = this[kSocket];
    if (state.destroyed) {
      return;
    }
    state.destroyed = true;
    if (!socket.destroyed) {
      socket.destroy();
    }
    this[kSocket] = undefined;
    this[kServer] = undefined;
    timers.unenroll(this);
    streams.forEach((value, key) => {
      value[kSession] = undefined;
      value[kState].shutdown = true;
    });
    streams.clear();
    const handle = this[kHandle];
    if (handle) {
      handle.destroy();
      debug('nghttp2session handle destroyed');
    }
    this.emit('close');
    debug('nghttp2session destroyed');
  }

  shutdown(options, callback) {
    const handle = this[kHandle];
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }

    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);

    if (callback !== undefined && typeof callback !== 'function')
      throw new errors.TypeError('ERR_INVALID_CALLBACK');
    if (options.opaqueData !== undefined &&
        !Buffer.isBuffer(options.opaqueData)) {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'opaqueData',
                                 options.opaqueData);
    }
    if (options.graceful !== undefined &&
        typeof options.graceful !== 'boolean') {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'graceful',
                                 options.graceful);
    }
    if (options.immediate !== undefined &&
        typeof options.immediate !== 'boolean') {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'immediate',
                                 options.immediate);
    }
    if (options.errorCode !== undefined &&
        typeof options.errorCode !== 'number') {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'errorCode',
                                 options.errorCode);
    }
    if (options.lastStreamID !== undefined &&
        (typeof options.lastStreamID !== 'number' ||
         options.lastStreamID < 0)) {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'lastStreamID',
                                 options.lastStreamID);
    }

    const sessionShutdownWrap = new SessionShutdownWrap();
    sessionShutdownWrap.oncomplete = onSessionShutdownComplete;
    sessionShutdownWrap.callback = callback;
    sessionShutdownWrap.options = options;
    sessionShutdownWrap[kOwner] = this;
    handle.submitShutdown(sessionShutdownWrap,
                          !!options.graceful,
                          !!options.immediate,
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
  if (session === undefined) return;
  if (this.id === undefined) {
    this.on('connect', () => {
      const handle = session[kHandle];
      if (handle !== undefined)
        emitErrorIfNecessary(this, handle.shutdownStream(this.id));
    });
  } else {
    const handle = session[kHandle];
    if (handle !== undefined)
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
    const session = this[kSession];
    const handle = session[kHandle];
    const id = this.id;
    return handle !== undefined && id !== undefined ?
      getStreamState(handle, id) :
      Object.create(null);
  }

  [kProceed]() {
    assert.fail(null, null,
                'Implementors MUST implement this. Please report this as a ' +
                'bug in Node.js');
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
    const err = createWriteReq(req, handle, data, encoding);
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

  // Note that this (and other methods like sendHeaders and rstStream) cause
  // nghttp to queue frames up in its internal buffer that are not actually
  // sent on the wire until the next tick of the event loop. The semantics of
  // this method then are: queue a priority frame to be sent and not immediately
  // send the priority frame. There is current no callback triggered when the
  // data is actually sent.
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

    assertIsObject(headers, 'headers');
    headers = Object.assign(Object.create(null), headers);
    if (headers[HTTP2_HEADER_STATUS] != null) {
      if (state.headersSent) {
        throw new errors.Error('ERR_HTTP2_HEADERS_AFTER_RESPOND');
      }
      const statusCode = headers[HTTP2_HEADER_STATUS] |= 0;
      if (statusCode === HTTP_STATUS_SWITCHING_PROTOCOLS)
        throw new errors.Error('ERR_HTTP2_STATUS_101');
      if (statusCode < 100 || statusCode >= 200)
        throw new errors.RangeError('ERR_HTTP2_INVALID_INFO_STATUS');
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
      options = undefined;
    }

    if (typeof callback !== 'function')
      throw new errors.TypeError('ERR_INVALID_CALLBACK');

    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);
    options.endStream = !!options.endStream;

    assertIsObject(headers, 'headers');
    headers = Object.assign(Object.create(null), headers);

    if (headers[HTTP2_HEADER_METHOD] === undefined)
      headers[HTTP2_HEADER_METHOD] = 'GET';

    if (headers[HTTP2_HEADER_AUTHORITY] === undefined)
      throw new errors.Error('ERR_HTTP2_HEADER_REQUIRED', ':authority');
    if (headers[HTTP2_HEADER_PATH] === undefined)
      throw new errors.Error('ERR_HTTP2_HEADER_REQUIRED', ':path');
    if (headers[HTTP2_HEADER_SCHEME] === undefined)
      throw new errors.Error('ERR_HTTP2_HEADER_REQUIRED', ':scheme');

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
      throw new errors.Error('ERR_HTTP2_HEADERS_SENT');
    state.headersSent = true;

    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);
    options.endStream = !!options.endStream;

    assertIsObject(headers, 'headers');
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
  constructor(session, id, options) {
    super(session, options);
    this[kState].headersSent = true;
    if (id !== undefined)
      this[kInit](id);
  }
}

const setTimeout = {
  configurable: true,
  enumerable: true,
  writable: true,
  value: function(msecs, callback) {
    if (typeof msecs !== 'number') {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'msecs',
                                 'number');
    }
    if (msecs === 0) {
      timers.unenroll(this);
      if (callback) {
        if (typeof callback !== 'function')
          throw new errors.TypeError('ERR_INVALID_CALLBACK');
        this.removeListener('timeout', callback);
      }
    } else {
      timers.enroll(this, msecs);
      timers._unrefActive(this);
      if (callback) {
        if (typeof callback !== 'function')
          throw new errors.TypeError('ERR_INVALID_CALLBACK');
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
  debug('socket destroy called');
  const session = this[kSession];
  this[kServer] = undefined;
  // destroy the session first so that it will stop trying to
  // send data while we close the socket.
  session.destroy();
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

function sessionOnPriority(stream, parent, weight, exclusive) {
  const server = this[kServer];
  server.emit('priority', stream, parent, weight, exclusive);
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
  session.on('priority', sessionOnPriority);

  session[kServer] = this;
  socket[kServer] = this;
}

function initializeOptions(options) {
  assertIsObject(options, 'options');
  options = Object.assign(Object.create(null), options);
  options.allowHalfOpen = true;
  assertIsObject(options.settings, 'options.settings');
  options.settings = Object.assign(Object.create(null), options.settings);
  return options;
}

function initializeTLSOptions(options, servername) {
  options = initializeOptions(options);
  options.ALPNProtocols = ['hc', 'h2'];
  options.NPNProtocols = ['hc', 'h2'];
  if (servername !== undefined) {
    options.servername = servername;
  }
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
        throw new errors.TypeError('ERR_INVALID_CALLBACK');
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
        throw new errors.TypeError('ERR_INVALID_CALLBACK');
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
  // TODO(jasnell): provide client specific implementations
  // session.on('stream', sessionOnStream);
  // session.on('selectPadding', sessionOnSelectPadding);

  socket[kSession] = session;

  return session;
}

function connect(authority, options, listener) {
  if (typeof options === 'function') {
    listener = options;
    options = undefined;
  }

  assertIsObject(options, 'options');
  options = Object.assign(Object.create(null), options);

  if (typeof authority === 'string')
    authority = new URL(authority);

  assertIsObject(authority, 'authority', ['string', 'object', 'URL']);

  const protocol = authority.protocol || options.protocol || 'https:';
  const port = '' + (authority.port !== '' ? authority.port : 443);
  const host = authority.hostname || authority.host || 'localhost';

  let socket;
  switch (protocol) {
    case 'http:':
      socket = net.connect(port, host);
      break;
    case 'https:':
      socket = tls.connect(port, host, initializeTLSOptions(options, host));
      break;
    default:
      throw new errors.Error('ERR_HTTP2_UNSUPPORTED_PROTOCOL', protocol);
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

function getDefaultSettings() {
  const holder = Object.create(null);
  holder.headerTableSize =
    defaultSettings[IDX_SETTINGS_HEADER_TABLE_SIZE];
  holder.enablePush =
    !!defaultSettings[IDX_SETTINGS_ENABLE_PUSH];
  holder.initialWindowSize =
    defaultSettings[IDX_SETTINGS_INITIAL_WINDOW_SIZE];
  holder.maxFrameSize =
    defaultSettings[IDX_SETTINGS_MAX_FRAME_SIZE];
  return holder;
}

function getSettings(session, remote) {
  const holder = Object.create(null);
  if (remote)
    binding.refreshRemoteSettings(session);
  else
    binding.refreshLocalSettings(session);

  holder.headerTableSize =
    settingsBuffer[IDX_SETTINGS_HEADER_TABLE_SIZE];
  holder.enablePush =
    !!settingsBuffer[IDX_SETTINGS_ENABLE_PUSH];
  holder.initialWindowSize =
    settingsBuffer[IDX_SETTINGS_INITIAL_WINDOW_SIZE];
  holder.maxFrameSize =
    settingsBuffer[IDX_SETTINGS_MAX_FRAME_SIZE];
  holder.maxConcurrentStreams =
    settingsBuffer[IDX_SETTINGS_MAX_CONCURRENT_STREAMS];
  holder.maxHeaderListSize =
    settingsBuffer[IDX_SETTINGS_MAX_HEADER_LIST_SIZE];
  return holder;
}

function getSessionState(session) {
  const holder = Object.create(null);
  binding.refreshSessionState(session);
  holder.effectiveLocalWindowSize =
    sessionState[IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE];
  holder.effectiveRecvDataLength =
    sessionState[IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH];
  holder.nextStreamID =
    sessionState[IDX_SESSION_STATE_NEXT_STREAM_ID];
  holder.localWindowSize =
    sessionState[IDX_SESSION_STATE_LOCAL_WINDOW_SIZE];
  holder.lastProcStreamID =
    sessionState[IDX_SESSION_STATE_LAST_PROC_STREAM_ID];
  holder.remoteWindowSize =
    sessionState[IDX_SESSION_STATE_REMOTE_WINDOW_SIZE];
  holder.outboundQueueSize =
    sessionState[IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE];
  holder.deflateDynamicTableSize =
    sessionState[IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE];
  holder.inflateDynamicTableSize =
    sessionState[IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE];
  return holder;
}

function getStreamState(session, stream) {
  const holder = Object.create(null);
  binding.refreshStreamState(session, stream);
  holder.state =
    streamState[IDX_STREAM_STATE];
  holder.weight =
    streamState[IDX_STREAM_STATE_WEIGHT];
  holder.sumDependencyWeight =
    streamState[IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT];
  holder.localClose =
    streamState[IDX_STREAM_STATE_LOCAL_CLOSE];
  holder.remoteClose =
    streamState[IDX_STREAM_STATE_REMOTE_CLOSE];
  holder.localWindowSize =
    streamState[IDX_STREAM_STATE_LOCAL_WINDOW_SIZE];
  return holder;
}

// Returns a Base64 encoded settings frame payload from the given
// object. The value is suitable for passing as the value of the
// HTTP2-Settings header frame.
function getPackedSettings(settings) {
  assertIsObject(settings, 'settings');
  return binding.packSettings(settings || Object.create(null));
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
