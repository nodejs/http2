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
  assertValidPseudoHeaderResponse,
  assertValidPseudoHeaderTrailer,
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
  debug(`headers were received on stream ${id}: ${cat}`);
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
    debug(`emitting stream '${event}' event`);
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
  debug('checking for trailers');
  const streams = this._owner._state.streams;
  const stream = streams.get(id);
  // It should not be possible for the stream not to exist at this point.
  // If it does not exist, there is something very very wrong.
  assert(stream !== undefined,
         'Internal HTTP/2 Failure. Stream does not exist. Please ' +
         'report this as a bug in Node.js');

  // TODO(jasnell): mapToHeaders will throw synchronously if the headers
  // are not valid. Try catch to keep it from bubbling up to the native
  // layer so that we can emit. mapToHeaders can be refactored to take
  // an optional callback or event emitter instance so it can emit errors
  // async instead.
  try {
    const trailers = Object.create(null);
    stream.emit('fetchTrailers', trailers);
    return mapToHeaders(trailers, assertValidPseudoHeaderTrailer);
  } catch (err) {
    process.nextTick(() => stream.emit('error', err));
  }
}

// Called when the stream is closed. The streamClosed event is emitted on the
// Http2Stream instance. Note that this event is distinctly different than the
// require('stream') interface 'close' event which deals with the state of the
// Readable and Writable sides of the Duplex.
function onSessionStreamClose(id, code) {
  debug(`session is closing the stream ${id}: ${code}`);
  const owner = this._owner;
  const stream = owner._state.streams.get(id);
  if (stream === undefined)
    return;
  _unrefActive(this);
  // Set the rst state for the stream
  stream._state.rst = true;
  stream._state.rstCode = code;
  setImmediate(() => {
    stream.destroy();
    debug(`stream ${id} is closed`);
  });
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
  debug('new settings received');
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
  debug('new priority received');
  _unrefActive(this);
  const owner = this._owner;
  const streams = owner._state.streams;
  const stream = streams.get(id);
  if (stream === undefined ||
      !stream.emit('priority', parent, weight, exclusive)) {
    owner.emit('priority', id, parent, weight, exclusive);
  }
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
    debug('fetching padding for frame');
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
  debug('connected.. initializing request');
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
  let err;
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      err = new errors.Error('ERR_OUTOFMEMORY');
      process.nextTick(() => session.emit('error', err));
      break;
    case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
      err = new errors.Error('ERR_HTTP2_OUT_OF_STREAMS');
      process.nextTick(() => this.emit('error', err));
      break;
    case NGHTTP2_ERR_INVALID_ARGUMENT:
      err = new errors.Error('ERR_HTTP2_STREAM_SELF_DEPENDENCY');
      process.nextTick(() => this.emit('error', err));
      break;
    default:
      // Some other, unexpected error was returned. Emit on the session.
      if (ret < 0) {
        err = new NghttpError(ret);
        process.nextTick(() => session.emit('error', err));
        break;
      }
      debug(`stream ${ret} initialized`);
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
    debug('setting up session handle');
    session._state.connecting = false;

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
    session.emit('connect', session, socket);
  };
}

function submitSettings(settings) {
  debug('submitting actual settings');
  _unrefActive(this);
  this[kLocalSettings] = undefined;
  const ret = this._handle.submitSettings(settings);
  let err;
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      err = new errors.Error('ERR_OUTOFMEMORY');
      process.nextTick(() => this.emit('error', err));
      break;
    default:
      // Some other unexpected error was reported.
      if (ret < 0) {
        err = new NghttpError(ret);
        process.nextTick(() => this.emit('error', err));
      }
  }
  debug('settings complete');
}

function submitPriority(stream, options) {
  debug('submitting actual priority');
  _unrefActive(this);

  const ret =
    this._handle.submitPriority(
      stream.id,
      options.parent | 0,
      options.weight | 0,
      !!options.exclusive,
      !!options.silent);

  let err;
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      err = new errors.Error('ERR_OUTOFMEMORY');
      process.nextTick(() => this.emit('error', err));
      break;
    default:
      // Some other unexpected error was reported.
      if (ret < 0) {
        err = new NghttpError(ret);
        process.nextTick(() => this.emit('error', err));
      }
  }
  debug('priority complete');
}

function submitRstStream(stream, code) {
  debug('submit actual rststream');
  _unrefActive(this);
  const id = stream.id;
  const ret = this._handle.submitRstStream(id, code);
  let err;
  switch (ret) {
    case NGHTTP2_ERR_NOMEM:
      err = new errors.Error('ERR_OUTOFMEMORY');
      process.nextTick(() => this.emit('error', err));
      break;
    default:
      // Some other unexpected error was reported.
      if (ret < 0) {
        err = new NghttpError(ret);
        process.nextTick(() => this.emit('error', err));
        break;
      }
      stream.destroy();
  }
  debug('rststream complete');
}

// Called when a requested session shutdown has been completed.
function onSessionShutdownComplete(status, wrap) {
  const session = wrap._owner;
  session._state.shuttingDown = false;
  session._state.shutdown = true;
  process.nextTick(() => session.emit('shutdown', wrap.options));
  delete wrap._owner;
  debug('shutdown is complete');
}

function submitShutdown(options) {
  debug('submitting actual shutdown request');
  const sessionShutdownWrap = new SessionShutdownWrap();
  sessionShutdownWrap.oncomplete = onSessionShutdownComplete;
  sessionShutdownWrap.options = options;
  sessionShutdownWrap._owner = this;
  this._handle.submitShutdown(sessionShutdownWrap,
                              !!options.graceful,
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
          destroyed: false,
          shutdown: false,
          shuttingDown: false
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
    debug('http2session created');
  }

  [kInspect](depth, opts) {
    const state = this._state;
    const obj = {
      type: this.type,
      destroyed: state.destroyed,
      destroying: state.destroying,
      shutdown: state.shutdown,
      shuttingDown: state.shuttingDown,
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
    assertWithinRange('headerTableSize',
                      settings.headerTableSize,
                      0, 2 ** 32 - 1);
    assertWithinRange('initialWindowSize',
                      settings.initialWindowSize,
                      0, 2 ** 32 - 1);
    assertWithinRange('maxFrameSize',
                      settings.maxFrameSize,
                      16384, 2 ** 24 - 1);
    assertWithinRange('maxConcurrentStreams',
                      settings.maxConcurrentStreams,
                      0, 2 ** 31 - 1);
    assertWithinRange('maxHeaderListSize',
                      settings.maxHeaderListSize,
                      0, 2 ** 32 - 1);
    if (settings.enablePush !== undefined &&
        typeof settings.enablePush !== 'boolean') {
      const err = new errors.TypeError('ERR_HTTP2_INVALID_SETTING_VALUE',
                                       'enablePush', settings.enablePush);
      err.actual = settings.enablePush;
      throw err;
    }
    debug('sending settings');

    if (this._state.connecting) {
      debug('session still connecting, queue settings');
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

    debug(`initiative priority for stream ${stream.id}`);

    // A stream cannot be made to depend on itself
    if (options.parent === stream.id) {
      debug('session still connecting. queue priority');
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

    if (this._state.rst) {
      // rst has already been called, do not call again,
      // skip straight to destroy
      stream.destroy();
      return;
    }
    stream._state.rst = true;
    stream._state.rstCode = code;

    debug(`initiating rststream for stream ${stream.id}: ${code}`);

    if (this._state.connecting) {
      debug('session still connecting, queue rststream');
      this.once('connect', submitRstStream.bind(this, stream, code));
      return;
    }
    submitRstStream.call(this, stream, code);
  }

  destroy() {
    const state = this._state;
    if (state.destroyed || state.destroying)
      return;

    debug('destroying nghttp2session');
    state.destroying = true;

    // Unenroll the timer
    unenroll(this);

    // Shut down any still open streams
    const streams = state.streams;
    streams.forEach((stream) => stream.destroy());

    // Disassociate from the socket and server
    const socket = this.socket;
    socket.pause();
    delete this.socket;
    delete this.server;

    state.destroyed = true;
    state.destroying = false;

    setImmediate(() => {
      if (!socket.destroyed)
        socket.destroy();

      // Destroy the handle
      const handle = this._handle;
      if (handle !== undefined) {
        handle.destroy();
        debug('nghttp2session handle destroyed');
      }

      this.emit('close');
      debug('nghttp2session destroyed');
    });
  }

  shutdown(options, callback) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');

    if (this._state.shutdown || this._state.shuttingDown)
      return;

    debug('initiating shutdown');
    this._state.shuttingDown = true;

    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }

    assertIsObject(options, 'options');
    options = Object.assign(Object.create(null), options);

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

    if (callback) {
      this.on('shutdown', callback);
    }

    if (this._state.connecting) {
      debug('session still connecting, queue shutdown');
      this.once('connect', submitShutdown.bind(this, options));
      return;
    }

    debug('sending shutdown');
    submitShutdown.call(this, options);
  }
}

class ClientHttp2Session extends Http2Session {
  constructor(options, socket) {
    super(NGHTTP2_SESSION_CLIENT, options, socket);
    debug('clienthttp2session created');
  }

  request(headers, options) {
    if (this._state.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_SESSION');
    debug('initiating request');
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
      debug('session still connecting, queue stream init');
      stream.on('connect', onConnect);
    } else {
      debug('session connected, immediate stream init');
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
    this.once('ready', onHandleFinish.bind(this));
  } else {
    const handle = session._handle;
    if (handle !== undefined) {
      // Shutdown on the next tick of the event loop just in case there is
      // still data pending in the outbound queue.
      assert(handle.shutdownStream(this.id) === undefined,
             `The stream ${this.id} does not exist. Please report this as ` +
             'a bug in Node.js');
    }
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

function streamOnResume() {
  if (this._paused)
    return this.pause();
  if (this.id === undefined) {
    this.once('ready', streamOnResume.bind(this));
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
  debug('session connected. emiting stream connect');
  this._state.connecting = false;
  this.emit('connect');
}

function streamOnceReady() {
  debug(`stream ${this.id} is ready`);
  this.uncork();
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
    this.cork();
    Object.defineProperties(this, {
      _state: {
        configurable: false,
        enumerable: false,
        value: {
          rst: false,
          rstCode: NGHTTP2_NO_ERROR,
          headersSent: false
        }
      },
      session: {
        configurable: true,
        enumerable: true,
        value: session
      }
    });
    this.once('ready', streamOnceReady);
    this.once('streamClosed', onStreamClosed);
    this.once('finish', onHandleFinish);
    this.on('resume', streamOnResume);
    this.on('pause', streamOnPause);
    this.on('drain', streamOnDrain);
    session.once('close', onSessionClose.bind(this));

    if (session._state.connecting) {
      debug('session is still connecting, queuing stream init');
      this._state.connecting = true;
      session.once('connect', streamOnSessionConnect.bind(this));
    }
    debug('http2stream created');
  }

  [kInit](id) {
    Object.defineProperty(this, 'id', {
      configurable: false,
      enumerable: true,
      value: id
    });
    this.emit('ready');
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

  get rstCode() {
    return this._state.rst ? this._state.rstCode : undefined;
  }

  get state() {
    const id = this.id;
    if (this.destroyed || id === undefined)
      return Object.create(null);
    return getStreamState(this.session._handle, id);
  }

  [kProceed]() {
    assert.fail(null, null,
                'Implementors MUST implement this. Please report this as a ' +
                'bug in Node.js');
  }

  _write(data, encoding, cb) {
    if (this.id === undefined) {
      this.once('ready', () => this._write(data, encoding, cb));
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
      this.once('ready', () => this._writev(data, cb));
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
      this.once('ready', () => this._read(nread));
      return;
    }
    if (this.destroyed) {
      this.push(null);
      return;
    }
    _unrefActive(this);
    const state = this._state;
    if (state.reading)
      return;
    state.reading = true;
    assert(this.session._handle.streamReadStart(this.id) === undefined,
           'HTTP/2 Stream #{this.id} does not exist. Please report this as ' +
           'a bug in Node.js');
  }

  // Submits an RST-STREAM frame to shutdown this stream.
  // If the stream ID has not yet been allocated, the action will
  // defer until the ready event is emitted.
  // After sending the rstStream, this.destroy() will be called making
  // the stream object no longer usable.
  rstStream(code) {
    if (this.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_STREAM');
    if (this.id === undefined) {
      debug('queuing rstStream for new stream');
      this.once('ready', () => this.rstStream(code));
      return;
    }
    debug(`sending rstStream for stream ${this.id}: ${code}`);
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
    if (this.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_STREAM');
    if (this.id === undefined) {
      debug('queuing priority for new stream');
      this.once('ready', () => this.priority(options));
      return;
    }
    debug(`sending priority for stream ${this.id}`);
    _unrefActive(this);
    this.session.priority(this, options);
  }

  // Called by this.destroy().
  // * If called before the stream is allocated, will defer until the
  //   ready event is emitted.
  // * Will submit an RST stream to shutdown the stream if necessary.
  //   This will cause the internal resources to be released.
  // * Then cleans up the resources on the js side
  _destroy(err, callback) {
    if (this.id === undefined) {
      debug('queuing destroy for new stream');
      this.once('ready', this._destroy.bind(this, err, callback));
      return;
    }
    debug(`destroying stream ${this.id}`);

    // Submit RST-STREAM frame if one hasn't been sent already and the
    // stream hasn't closed normally...
    if (!this._state.rst) {
      const code =
        err instanceof Error ?
          NGHTTP2_INTERNAL_ERROR : NGHTTP2_NO_ERROR;
      this.session.rstStream(this, code);
    }

    // Unenroll the timer
    unenroll(this);

    // Remove the stream from the session
    const session = this.session;
    setImmediate(() => {
      if (session._handle !== undefined)
        session._handle.destroyStream(this.id);
    });
    session._state.streams.delete(this.id);
    delete this.session;

    // All done
    this.emit('streamClosed',
              this._state.rst ? this._state.rstCode : NGHTTP2_NO_ERROR);
    debug(`stream ${this.id} destroyed`);
    callback(err);
  }
}

class ServerHttp2Stream extends Http2Stream {
  constructor(session, id, options) {
    super(session, options);
    this[kInit](id);
    debug('created serverhttp2stream');
  }

  pushStream(headers, options, callback) {
    if (this.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_STREAM');

    debug(`initiating push stream for stream ${this.id}`);

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
    let err;
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        err = new errors.Error('ERR_OUTOFMEMORY');
        process.nextTick(() => session.emit('error', err));
        break;
      case NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE:
        err = new errors.Error('ERR_HTTP2_OUT_OF_STREAMS');
        process.nextTick(() => this.emit('error', err));
        break;
      case NGHTTP2_ERR_STREAM_CLOSED:
        err = new errors.Error('ERR_HTTP2_STREAM_CLOSED');
        process.nextTick(() => this.emit('error', err));
        break;
      default:
        if (ret <= 0) {
          err = new NghttpError(ret);
          process.nextTick(() => this.emit('error', err));
          break;
        }
        debug(`push stream ${ret} created`);
        options.readable = !options.endStream;
        const stream = new ServerHttp2Stream(session, ret, options);
        streams.set(ret, stream);
        process.nextTick(callback, stream, headers, 0);
    }
  }

  respond(headers, options) {
    if (this.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_STREAM');
    debug(`initiating response for stream ${this.id}`);
    _unrefActive(this);
    const state = this._state;

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

    if (state.headersSent)
      throw new errors.Error('ERR_HTTP2_HEADERS_SENT');

    // Close the writable side if the endStream option is set
    if (options.endStream)
      this.end();

    const ret =
      this.session._handle.submitResponse(
        this.id,
        mapToHeaders(headers, assertValidPseudoHeaderResponse),
        options.endStream);
    let err;
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        err = new errors.Error('ERR_OUTOFMEMORY');
        process.nextTick(() => this.session.emit('error', err));
        break;
      default:
        if (ret < 0) {
          err = new NghttpError(ret);
          process.nextTick(this.emit('error', err));
          return;
        }
        state.headersSent = true;
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
    if (this.destroyed)
      throw new errors.Error('ERR_HTTP2_INVALID_STREAM');

    if (this._state.headersSent)
      throw new errors.Error('ERR_HTTP2_HEADERS_AFTER_RESPOND');

    debug('sending additional headers');

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
    const ret =
      handle.sendHeaders(this.id,
                         mapToHeaders(headers,
                                      assertValidPseudoHeaderResponse));
    let err;
    switch (ret) {
      case NGHTTP2_ERR_NOMEM:
        err = new errors.Error('ERR_OUTOFMEMORY');
        process.nextTick(() => this.session.emit('error', err));
        break;
      default:
        if (ret < 0) {
          err = new NghttpError(ret);
          process.nextTick(() => this.emit('error', err));
        }
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
    debug('clienthttp2stream created');
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
  delete this.server;
  // destroy the session first so that it will stop trying to
  // send data while we close the socket.
  this.session.destroy();
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

// When an Http2Session emits an error, first try to forward it to the
// server as a sessionError; failing that, forward it to the socket as
// a sessionError; failing that, destroy, remove the error listener, and
// re-emit the error event
function sessionOnError(error) {
  debug(`server session error: ${error.message}`);
  if (this.server !== undefined && this.server.emit('sessionError', error))
    return;
  if (this.socket !== undefined && this.socket.emit('sessionError', error))
    return;
  this.destroy();
  this.removeListener('error', sessionOnError);
  this.emit('error', error);
}

// When a Socket emits an error, first try to forward it to the server
// as a socketError; failing that, forward it to the session as a
// socketError; failing that, remove the listener and call destroy
function socketOnError(error) {
  debug(`server socket error: ${error.message}`);
  if (kRenegTest.test(error.message))
    return this.destroy();
  if (this.server !== undefined && this.server.emit('socketError', error))
    return;
  if (this.session !== undefined && this.session.emit('socketError', error))
    return;
  this.removeListener('error', socketOnError);
  this.destroy(error);
}

// When the socket times out, attempt a graceful shutdown
// of the session
function socketOnTimeout() {
  debug('socket timeout');
  const server = this.server;
  // server can be null if the socket is a client
  if (server === undefined || !server.emit('timeout', this)) {
    this.session.shutdown(
      {
        graceful: true,
        errorCode: NGHTTP2_NO_ERROR
      },
      this.destroy.bind(this));
  }
}

// Handles the on('stream') event for a session and forwards
// it on to the server object.
function sessionOnStream(stream, headers, flags) {
  debug('emit server stream event');
  this.server.emit('stream', stream, headers, flags);
}

function sessionOnPriority(stream, parent, weight, exclusive) {
  debug('priority change received');
  this.server.emit('priority', stream, parent, weight, exclusive);
}

function connectionListener(socket) {
  debug('server received a connection');
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
    debug('http2secureserver created');
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
    debug('http2server created');
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
    debug('setting up compatibility handler');
    this.removeListener('newListener', setupCompat);
    this.on('stream', onServerStream);
  }
}

// If the socket emits an error, forward it to the session as a socketError;
// failing that, remove the listener and destroy the socket
function clientSocketOnError(error) {
  debug(`client socket error: ${error.message}`);
  if (kRenegTest.test(error.message))
    return this.destroy();
  if (this.session !== undefined && this.session.emit('socketError', error))
    return;
  this.removeListener('error', clientSocketOnError);
  this.destroy(error);
}

// If the session emits an error, forward it to the socket as a sessionError;
// failing that, destroy the session, remove the listener and re-emit the error
function clientSessionOnError(error) {
  debug(`client session error: ${error.message}`);
  if (this.socket !== undefined && this.socket.emit('sessionError', error))
    return;
  this.destroy();
  this.removeListener('error', clientSocketOnError);
  this.emit('error', error);
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

  debug(`connecting to ${authority}`);

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
    options = Object.create(null);
  }
  debug('creating http2secureserver');
  return new Http2SecureServer(options, handler);
}

function createServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = Object.create(null);
  }
  debug('creating htt2pserver');
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
