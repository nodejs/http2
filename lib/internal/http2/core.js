'use strict';

const binding = process.binding('http2');
const debug = require('util').debuglog('http2');
const assert = require('assert');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const net = require('net');
const tls = require('tls');
const util = require('util');
const errors = require('internal/errors');
const { Duplex } = require('stream');
const { URL } = require('url');
const { onServerStream } = require('internal/http2/compat');
const { utcDate } = require('internal/http');
const { _connectionListener: httpConnectionListener } = require('http');

const {
  assertIsObject,
  assertWithinRange,
  getDefaultSettings,
  getSessionState,
  getSettings,
  getStreamState,
  mapToHeaders,
  NghttpError
} = require('internal/http2/util');

const {
  _unrefActive,
  enroll,
  unenroll
} = require('timers');

const { WriteWrap } = process.binding('stream_wrap');
const { constants, SessionShutdownWrap } = binding;

const NETServer = net.Server;
const TLSServer = tls.Server;

const kInspect = require('internal/util').customInspectSymbol;

const kDestroySocket = Symbol('destroy-socket');
const kInit = Symbol('init');
const kLocalSettings = Symbol('local-settings');
const kRemoteSettings = Symbol('remote-settings');
const kProceed = Symbol('proceed');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

const paddingBuffer = new Uint32Array(binding.paddingArrayBuffer);

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
  NGHTTP2_ERR_NOMEM,
  NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE,
  NGHTTP2_ERR_INVALID_ARGUMENT,
  NGHTTP2_ERR_STREAM_CLOSED,

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

// Called when a new block of headers has been received for a given
// stream. The stream may or may not be new. If the stream is new,
// create the associated Http2Stream instance and emit the 'stream'
// event. If the stream is not new, emit the 'headers' event to pass
// the block of headers on.
function onSessionHeaders(id, cat, flags, headers) {
  _unrefActive(this);
  const owner = this._owner;
  const streams = owner._state.streams;

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

  if (headers[HTTP2_HEADER_STATUS]) {
    headers[HTTP2_HEADER_STATUS] |= 0;
  }

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
    let status;
    switch (cat) {
      case NGHTTP2_HCAT_REQUEST:
        event = 'request';
        break;
      case NGHTTP2_HCAT_RESPONSE:
        status = headers[HTTP2_HEADER_STATUS];
        if (!endOfStream &&
            status !== undefined &&
            status >= 100 &&
            status < 200) {
          event = 'headers';
        } else {
          event = 'response';
        }
        break;
      case NGHTTP2_HCAT_PUSH_RESPONSE:
        event = 'push';
        break;
      case NGHTTP2_HCAT_HEADERS:
        status = headers[HTTP2_HEADER_STATUS];
        if (!endOfStream && status !== undefined && status >= 200) {
          event = 'response';
        } else {
          event = endOfStream ? 'trailers' : 'headers';
        }
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
  const streams = this._owner._state.streams;
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
  const streams = this._owner._state.streams;
  const stream = streams.get(id);
  if (stream === undefined)
    return;
  _unrefActive(this);
  unenroll(stream);
  // Notify the stream that it has been closed.
  stream.emit('streamClosed', code);
  delete stream.session;
  streams.delete(id);
}

// Called when an error event needs to be triggered
function onSessionError(error) {
  _unrefActive(this);
  this._owner.emit('error', error);
}

// Receives a chunk of data for a given stream and forwards it on
// to the Http2Stream Duplex for processing.
function onSessionRead(nread, buf, handle) {
  const streams = this._owner._state.streams;
  const id = handle.id;
  const stream = streams.get(id);
  // It should not be possible for the stream to not exist at this point.
  // If it does not, something is very very wrong
  assert(stream !== undefined,
         'Internal HTTP/2 Failure. Stream does not exist. Please ' +
         'report this as a bug in Node.js');
  const state = stream._state;
  _unrefActive(this); // Reset the session timeout timer
  _unrefActive(stream); // Reset the stream timout timer
  if (!stream.push(buf)) {
    assert(this.streamReadStop(id) === undefined,
           `HTTP/2 Stream ${id} does not exist. Please report this as ' +
           'a bug in Node.js`);
    state.reading = false;
  }
}

// Called when the remote peer settings have been updated.
// Resets the cached settings.
function onSettings() {
  _unrefActive(this);
  this._owner[kRemoteSettings] = undefined;
}

// If the stream exists, an attempt will be made to emit an event
// on the stream object itself. Otherwise, forward it on to the
// session (which may, in turn, forward it on to the server)
function onPriority(id, parent, weight, exclusive) {
  debug(`priority advisement for stream ${id}: \n` +
        `  parent: ${parent},\n  weight: ${weight},\n` +
        `  exclusive: ${exclusive}`);
  _unrefActive(this);
  const owner = this._owner;
  const streams = owner._state.streams;
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
  delete wrap._owner;
}

// Returns the padding to use per frame. The selectPadding callback is set
// on the options. It is invoked with two arguments, the frameLen, and the
// maxPayloadLen. The method must return a numeric value within the range
// frameLen <= n <= maxPayloadLen.
function onSelectPadding(fn) {
  assert(typeof fn === 'function',
         'options.selectPadding must be a function. Please report this as a ' +
         'bug in Node.js');
  return function getPadding() {
    const frameLen = paddingBuffer[0];
    const maxFramePayloadLen = paddingBuffer[1];
    paddingBuffer[2] = Math.min(maxFramePayloadLen,
                                Math.max(frameLen,
                                         fn(frameLen,
                                            maxFramePayloadLen) | 0));
  };
}

// Called when the socket is connected to handle a pending request.
function requestOnConnect(headers, options) {
  const session = this.session;
  const streams = session._state.streams;
  // ret will be either the reserved stream ID (if positive)
  // or an error code (if negative)
  validatePriorityOptions(options);
  const ret = session._handle.submitRequest(mapToHeaders(headers),
                                            !!options.endStream,
                                            options.parent | 0,
                                            options.weight | 0,
                                            !!options.exclusive);

  // In an error condition, one of three possible response codes will be
  // possible:
  // * NGHTTP2_ERR_NOMEM - Out of memory, this should be fatal to the process.
  // * NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE - Maximum stream ID is reached, this
  //   is fatal for the session
  // * NGHTTP2_ERR_INVALID_ARGUMENT - Stream was made dependent on itself, this
  //   impacts on this stream.
  // For the first two, emit the error on the session,
  // For the third, emit the error on the stream, it will bubble up to the
  // session if not handled.
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      session.emit('error', new errors.Error('ERR_OUTOFMEMORY'));
      return;
    case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
      session.emit('error', new errors.Error('ERR_HTTP2_OUT_OF_STREAMS'));
      return;
    case NGHTTP2_ERR_INVALID_ARGUMENT:
      this.emit('error', new errors.Error('ERR_HTTP2_STREAM_SELF_DEPENDENCY'));
      return;
    default:
      // Some other, unexpected error was returned. Emit on the session.
      if (ret < 0) {
        session.emit('error', new NghttpError(ret));
        return;
      }
      this[kInit](ret);
      streams.set(ret, this);
  }
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

function setupHandle(session, socket, type, options) {
  return function() {
    const handle = new binding.Http2Session(type, options);
    handle._owner = session;
    handle.onpriority = onPriority;
    handle.onsettings = onSettings;
    handle.onheaders = onSessionHeaders;
    handle.ontrailers = onSessionTrailers;
    handle.onstreamclose = onSessionStreamClose;
    handle.onerror = onSessionError;
    handle.onread = onSessionRead;

    if (typeof options.selectPadding === 'function')
      handle.ongetpadding = onSelectPadding(options.selectPadding);

    assert(socket._handle !== undefined,
           'Internal HTTP/2 Failure. The socket is not connected. Please ' +
           'report this as a bug in Node.js');
    handle.consume(socket._handle._externalStream);

    Object.defineProperty(session, '_handle', {
      configurable: false,
      enumerable: false,
      value: handle
    });

    const settings = typeof options.settings === 'object' ?
        options.settings : Object.create(null);

    session.settings(settings);
    session._state.connecting = false;
    session.emit('connect', session, socket);
  };
}

function submitSettings(settings) {
  _unrefActive(this);
  this[kLocalSettings] = undefined;
  const ret = this._handle.submitSettings(settings);
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      this.emit('error', errors.Error('ERR_OUTOFMEMORY'));
      break;
    default:
      // Some other unexpected error was reported.
      if (ret < 0)
        this.emit('error', new NghttpError(ret));
  }
}

function submitPriority(stream, options) {
  _unrefActive(this);

  const ret =
    this._handle.submitPriority(
      stream.id,
      options.parent | 0,
      options.weight | 0,
      !!options.exclusive,
      !!options.silent);

  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      this.emit('error', new errors.Error('ERR_OUTOFMEMORY'));
      break;
    default:
      // Some other unexpected error was returned
      if (ret < 0)
        this.emit('error', new NghttpError(ret));
  }
}

function submitRstStream(stream, code) {
  _unrefActive(this);
  const ret = this._handle.submitRstStream(stream.id, code);
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      this.emit('error', new errors.Error('ERR_OUTOFMEMORY'));
      break;
    default:
      // Some other unexpected error occurred
      if (ret < 0)
        this.emit('error', new NghttpError(ret));
  }
}

function submitShutdown(options, callback) {
  const sessionShutdownWrap = new SessionShutdownWrap();
  sessionShutdownWrap.oncomplete = onSessionShutdownComplete;
  sessionShutdownWrap.callback = callback;
  sessionShutdownWrap.options = options;
  sessionShutdownWrap._owner = this;
  this._handle.submitShutdown(sessionShutdownWrap,
                              !!options.graceful,
                              !!options.immediate,
                              options.errorCode | 0,
                              options.lastStreamID | 0,
                              options.opaqueData);
}

// Upon creation, the Http2Session takes ownership of the socket. The session
// may not be ready to use immediately if the socket is not yet fully connected.
class Http2Session extends EventEmitter {

  // type     { number } either NGHTTP2_SESSION_SERVER or NGHTTP2_SESSION_CLIENT
  // options  { Object }
  // socket   { net.Socket | tls.TLSSocket }
  constructor(type, options, socket) {
    super();

    assert(type === NGHTTP2_SESSION_SERVER || type === NGHTTP2_SESSION_CLIENT,
           'Invalid session type. Please report this as a bug in Node.js');

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

    // If the session property already exists on the socket,
    // then it has already been bound to an Http2Session instance
    // and cannot be attached again.
    if (socket.session !== undefined)
      throw new errors.Error('ERR_HTTP2_SOCKET_BOUND');

    // Bind the socket to the session
    Object.defineProperty(socket, 'session', {
      configurable: true,
      enumerable: true,
      value: this
    });

    Object.defineProperties(this, {
      _state: {
        configurable: false,
        enumerable: false,
        value: {
          streams: new Map(),
          destroyed: false
        }
      },
      type: {
        configurable: false,
        enumerable: true,
        value: type
      },
      socket: {
        configurable: true,
        enumerable: true,
        value: socket
      }
    });

    // Do not use nagle's algorithm
    socket.setNoDelay();

    // Disable TLS renegotiation on the socket
    if (typeof socket.disableRenegotiation === 'function')
      socket.disableRenegotiation();

    socket[kDestroySocket] = socket.destroy;
    socket.destroy = socketDestroy;

    const setupFn = setupHandle(this, socket, type, options);
    if (socket.connecting) {
      this._state.connecting = true;
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
    const state = this._state;
    const obj = {
      type: this.type,
      destroyed: state.destroyed,
      state: this.state,
      localSettings: this.localSettings,
      remoteSettings: this.remoteSettings
    };
    return `Http2Session ${util.format(obj)}`;
  }

  get destroyed() {
    return this._state.destroyed;
  }

  get state() {
    const handle = this._handle;
    return handle !== undefined ?
      getSessionState(handle) :
      Object.create(null);
  }

  get localSettings() {
    let settings = this[kLocalSettings];
    if (settings !== undefined)
      return settings;

    const handle = this._handle;
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

    const handle = this._handle;
    if (handle === undefined)
      return Object.create(null);

    settings = getSettings(handle, true); // Remote
    this[kRemoteSettings] = settings;
    return settings;
  }

  settings(settings) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

    // Validate the input first
    assertIsObject(settings, 'settings');
    settings = Object.assign(Object.create(null), settings);
    assertWithinRange('settings.headerTableSize',
                      settings.headerTableSize,
                      0, 2 ** 32 - 1);
    assertWithinRange('settings.initialWindowSize',
                      settings.initialWindowSize,
                      0, 2 ** 32 - 1);
    assertWithinRange('settings.maxFrameSize',
                      settings.maxFrameSize,
                      16384, 2 ** 24 - 1);
    assertWithinRange('settings.maxConcurrentStreams',
                      settings.maxConcurrentStreams,
                      0, 2 ** 31 - 1);
    assertWithinRange('settings.maxHeaderListSize',
                      settings.maxHeaderListSize,
                      0, 2 ** 32 - 1);
    if (settings.enablePush !== undefined &&
        typeof settings.enablePush !== 'boolean') {
      // TODO: Use internal/errors
      throw new TypeError('settings.enablePush must be a boolean');
    }

    if (this._state.connecting) {
      this.once('connect', submitSettings.bind(this, settings));
      return;
    }
    submitSettings.call(this, settings);
  }

  priority(stream, options) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

    if (!(stream instanceof Http2Stream)) {
      throw new errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 'stream',
                                 'Http2Stream');
    }
    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);
    validatePriorityOptions(options);

    // A stream cannot be made to depend on itself
    if (options.parent === stream.id) {
      throw new errors.TypeError('ERR_INVALID_OPT_VALUE',
                                 'parent',
                                 options.parent);
    }

    if (this._state.connecting) {
      this.once('connect', submitPriority.bind(this, stream, options));
      return;
    }
    submitPriority.call(this, stream, options);
  }

  rstStream(stream, code) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

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

    if (this._state.connecting) {
      this.once('connect', submitRstStream.bind(this, stream, code));
      return;
    }
    submitRstStream.call(this, stream, code);
  }

  destroy() {
    const state = this._state;
    if (state.destroyed)
      return;
    state.destroyed = true;
    const socket = this.socket;
    if (!socket.destroyed) {
      socket.destroy();
    }
    delete this.socket;
    delete this.server;
    unenroll(this);
    const streams = state.streams;
    streams.forEach((value, key) => {
      delete value.session;
      value._state.shutdown = true;
    });
    streams.clear();
    const handle = this._handle;
    if (handle !== undefined) {
      handle.destroy();
      debug('nghttp2session handle destroyed');
    }
    this.emit('close');
    debug('nghttp2session destroyed');
  }

  shutdown(options, callback) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

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

    if (this._state.connecting) {
      this.once('connect', submitShutdown.bind(this, options, callback));
      return;
    }
    submitShutdown.call(this, options, callback);
  }
}

class ClientHttp2Session extends Http2Session {
  constructor(options, socket) {
    debug('creating client http2 session');
    super(NGHTTP2_SESSION_CLIENT, options, socket);
  }

  request(headers, options) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');
    _unrefActive(this);
    assertIsObject(headers, 'headers');
    assertIsObject(options, 'options');

    headers = Object.assign(Object.create(null), headers);
    options = Object.assign(Object.create(null), options);

    if (headers[HTTP2_HEADER_METHOD] === undefined)
      headers[HTTP2_HEADER_METHOD] = 'GET';
    if (headers[HTTP2_HEADER_AUTHORITY] === undefined)
      headers[HTTP2_HEADER_AUTHORITY] = this._authority;
    if (headers[HTTP2_HEADER_SCHEME] === undefined)
      headers[HTTP2_HEADER_SCHEME] = this._protocol.slice(0, -1);
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

    if (this._state.connecting) {
      stream.on('connect', onConnect);
    } else {
      onConnect();
    }
    return stream;
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
  _unrefActive(handle._owner);
  if (typeof req.callback === 'function')
    req.callback();
  this.handle = undefined;
}

function onHandleFinish() {
  const session = this.session;
  if (session === undefined) return;
  if (this.id === undefined) {
    this.once('connect', onHandleFinish.bind(this));
  } else {
    const handle = session._handle;
    if (handle !== undefined)
      assert(handle.shutdownStream(this.id) === undefined,
             `The stream ${this.id} does not exist. Please report this as ` +
             'a bug in Node.js');
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
  const session = this.session;
  if (session === undefined)
    process.emit('error', error);
  if (!session.emit('streamError', error, this))
    session.emit('error', error, this);
}

function streamOnResume() {
  if (this._paused)
    return this.pause();
  if (this.id === undefined) {
    this.once('connect', streamOnResume.bind(this));
    return;
  }
  const session = this.session;
  const state = this._state;
  if (session && !state.reading) {
    state.reading = true;
    assert(session._handle.streamReadStart(this.id) === undefined,
           'HTTP/2 Stream #{this.id} does not exist. Please report this as ' +
           'a bug in Node.js');
  }
}

function streamOnPause() {
  const session = this.session;
  const state = this._state;
  if (session && state.reading) {
    state.reading = false;
    assert(session._handle.streamReadStop(this.id) === undefined,
           `HTTP/2 Stream ${this.id} does not exist. Please report this as ' +
           'a bug in Node.js`);
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
  this._state.connecting = false;
  this.uncork();
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
    Object.defineProperties(this, {
      _state: {
        configurable: false,
        enumerable: false,
        value: {
          headersSent: false
        }
      },
      session: {
        configurable: true,
        enumerable: true,
        value: session
      }
    });
    this.on('finish', onHandleFinish);
    this.on('streamClosed', onStreamClosed);
    this.on('error', onStreamError);
    this.on('resume', streamOnResume);
    this.on('pause', streamOnPause);
    this.on('drain', streamOnDrain);
    session.on('close', onSessionClose.bind(this));

    const sessionState = session._state;
    if (sessionState.connecting) {
      this.cork();
      this._state.connecting = true;
      session.once('connect', streamOnSessionConnect.bind(this));
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

  get state() {
    const handle = this.session._handle;
    const id = this.id;
    return handle !== undefined && id !== undefined ?
      getStreamState(handle, id) :
      Object.create(null);
  }

  [kProceed]() {
    assert(!this.session._state.destroyed);
    assert.fail(null, null,
                'Implementors MUST implement this. Please report this as a ' +
                'bug in Node.js');
  }

  _write(data, encoding, cb) {
    if (this.id === undefined) {
      this.once('connect', () => this._write(data, encoding, cb));
      return;
    }
    _unrefActive(this);
    if (!this._state.headersSent)
      this[kProceed]();
    const session = this.session;
    const handle = session._handle;
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
    _unrefActive(this);
    if (!this._state.headersSent)
      this[kProceed]();
    const session = this.session;
    const handle = session._handle;
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
    _unrefActive(this);
    const state = this._state;
    if (this._state.reading)
      return;
    state.reading = true;
    const session = this.session;
    const handle = session._handle;
    assert(handle.streamReadStart(this.id) === undefined,
           'HTTP/2 Stream #{this.id} does not exist. Please report this as ' +
           'a bug in Node.js');
  }

  rstStream(code) {
    if (this.id === undefined) {
      this.once('connect', () => this.rstStream(code));
      return;
    }
    _unrefActive(this);
    this.session.rstStream(this, code);
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

  // Note that this (and other methods like additionalHeaders and rstStream)
  // cause nghttp to queue frames up in its internal buffer that are not
  // actually sent on the wire until the next tick of the event loop. The
  // semantics of this method then are: queue a priority frame to be sent and
  // not immediately send the priority frame. There is current no callback
  // triggered when the data is actually sent.
  priority(options) {
    if (this.id === undefined) {
      this.once('connect', () => this.priority(options));
      return;
    }
    _unrefActive(this);
    this.session.priority(this, options);
  }
}

class ServerHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, options);
    this[kInit](id);
  }

  pushStream(headers, options, callback) {
    if (this.session === undefined || this.session._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');
    _unrefActive(this);
    const session = this.session;
    const state = session._state;
    const streams = state.streams;
    const handle = session._handle;

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
      headers[HTTP2_HEADER_AUTHORITY] = session._authority;
    if (headers[HTTP2_HEADER_SCHEME] === undefined)
      headers[HTTP2_HEADER_SCHEME] = session._protocol.slice(0, -1);
    if (headers[HTTP2_HEADER_PATH] === undefined)
      headers[HTTP2_HEADER_PATH] = '/';

    const ret = handle.submitPushPromise(this.id,
                                         mapToHeaders(headers),
                                         options.endStream);
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        session.emit('error', errors.Error('ERR_OUTOFMEMORY'));
        break;
      case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
        throw errors.Error('ERR_HTTP2_OUT_OF_STREAMS');
      case NGHTTP2_ERR_STREAM_CLOSED:
        throw errors.Error('ERR_HTTP2_STREAM_CLOSED');
      default:
        if (ret <= 0) {
          this.emit('error', new NghttpError(ret));
        }
        options.readable = !options.endStream;
        const stream = new ServerHttp2Stream(session, ret, options);
        streams.set(ret, stream);
        process.nextTick(callback, stream, headers, 0);
    }
  }

  respond(headers, options) {
    if (this.session === undefined || this.session._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');
    _unrefActive(this);
    const state = this._state;

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
        throw new errors.RangeError('ERR_HTTP2_STATUS_INVALID',
                                    headers[HTTP2_HEADER_STATUS]);

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

    const ret =
      this.session._handle.submitResponse(this.id,
                                          mapToHeaders(headers),
                                          options.endStream);
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        this.session.emit('error', new errors.Error('ERR_OUTOFMEMORY'));
        break;
      default:
        if (ret < 0)
          this.emit('error', new NghttpError(ret));
    }
  }

  // Sends a block of informational headers. In theory, the HTTP/2 spec
  // allows sending a HEADER block at any time during a streams lifecycle,
  // but the HTTP request/response semantics defined in HTTP/2 places limits
  // such that HEADERS may only be sent *before* or *after* DATA frames.
  // If the block of headers being sent includes a status code, it MUST be
  // a 1xx informational code and it MUST be sent before the request/response
  // headers are sent, or an error will be thrown.
  additionalHeaders(headers) {
    if (this.session === undefined || this.session._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

    if (this._state.headersSent)
      throw new errors.Error('ERR_HTTP2_HEADERS_AFTER_RESPOND');

    assertIsObject(headers, 'headers');
    headers = Object.assign(Object.create(null), headers);
    if (headers[HTTP2_HEADER_STATUS] != null) {
      const statusCode = headers[HTTP2_HEADER_STATUS] |= 0;
      if (statusCode === HTTP_STATUS_SWITCHING_PROTOCOLS)
        throw new errors.Error('ERR_HTTP2_STATUS_101');
      if (statusCode < 100 || statusCode >= 200)
        throw new errors.RangeError('ERR_HTTP2_INVALID_INFO_STATUS');
    }

    _unrefActive(this);
    const handle = this.session._handle;
    const ret = handle.sendHeaders(this.id, mapToHeaders(headers));
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        this.session.emit('error', new errors.Error('ERR_OUTOFMEMORY'));
        break;
      default:
        if (ret < 0)
          this.emit('error', new NghttpError(ret));
    }
  }
}

ServerHttp2Stream.prototype[kProceed] = ServerHttp2Stream.prototype.respond;

class ClientHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, options);
    this._state.headersSent = true;
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
      unenroll(this);
      if (callback !== undefined) {
        if (typeof callback !== 'function')
          throw new errors.TypeError('ERR_INVALID_CALLBACK');
        this.removeListener('timeout', callback);
      }
    } else {
      enroll(this, msecs);
      _unrefActive(this);
      if (callback !== undefined) {
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
  const session = this.session;
  delete this.server;
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
  const server = session.server;
  if (server.emit('sessionError', error))
    return;
  const socket = session.socket;
  socket.destroy(error);
}

// When the socket times out, attempt a graceful shutdown
// of the session
function socketOnTimeout() {
  const socket = this;
  const server = socket.server;
  // server can be null if the socket is a client
  if (!server || !server.emit('timeout', this)) {
    const session = socket.session;
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
  const server = this.server;
  if (!server.emit('socketError', error, this))
    this.destroy(error);
}

// Handles the on('stream') event for a session and forwards
// it on to the server object.
function sessionOnStream(stream, headers, flags) {
  const server = this.server;
  server.emit('stream', stream, headers, flags);
}

function sessionOnPriority(stream, parent, weight, exclusive) {
  const server = this.server;
  server.emit('priority', stream, parent, weight, exclusive);
}

function connectionListener(socket) {
  const options = this._options || {};

  if (this.timeout) {
    socket.setTimeout(this.timeout);
    socket.on('timeout', socketOnTimeout);
  }

  // TLS ALPN fallback to HTTP/1.1
  if (options.allowHTTP1 === true &&
    (socket.alpnProtocol === false ||
    socket.alpnProtocol === 'http/1.1')) {
    return httpConnectionListener.call(this, socket);
  }

  socket.on('error', socketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  // Set up the Session
  const session = new Http2Session(NGHTTP2_SESSION_SERVER, options, socket);

  session.on('error', sessionOnError);
  session.on('stream', sessionOnStream);
  session.on('priority', sessionOnPriority);

  const prop = {
    configurable: true,
    enumerable: true,
    value: this
  };
  Object.defineProperty(session, 'server', prop);
  Object.defineProperty(socket, 'server', prop);
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
  options.ALPNProtocols = ['h2', 'http/1.1'];
  if (servername !== undefined && options.servername === undefined) {
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
    Object.defineProperty(this, '_options', {
      configurable: false,
      enumerable: false,
      value: options
    });
    this.timeout = kDefaultSocketTimeout;
    this.on('newListener', setupCompat);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', onErrorSecureServerSession);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback !== undefined) {
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
    Object.defineProperty(this, '_options', {
      configurable: false,
      enumerable: false,
      value: initializeOptions(options)
    });
    this.timeout = kDefaultSocketTimeout;
    this.on('newListener', setupCompat);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback !== undefined) {
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

function clientSocketOnError(error) {
  if (kRenegTest.test(error.message))
    return this.destroy();
  const session = this.session;
  if (!session.emit('error', error, this)) {
    this.destroy(error);
  }
}

function clientSessionOnError(error) {
  const socket = this.socket;
  if (socket !== undefined)
    socket.destroy(error);
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

  socket.on('error', clientSocketOnError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  const session = new ClientHttp2Session(options, socket);

  session.on('error', clientSessionOnError);

  Object.defineProperties(session, {
    _authority: {
      configurable: false,
      enumerable: false,
      value: `${host}:${port}`
    },
    _protocol: {
      configurable: false,
      enumerable: false,
      value: protocol
    }
  });

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
  connect
};
