'use strict';

// General Notes:
// * There are internal Http2Session and Http2Stream objects provided
//   by process.binding('http2') and external Http2Session and Http2Stream
//   classes exported here. The internal objects serve as the _handle for
//   the external.
//
// * A FreeList pool is used to buffer and reuse instances of the internal
//   Http2Session to reduce the need for creating new instances every time.
//
// * Both of the internal Http2Stream and Http2Session objects are AsyncWraps
//
// * The internal Http2Stream instance extends from StreamBase, it supports
//   writev and does not expose the shutdown method. Within this StreamBase
//   implementation, there are two in memory NodeBIO buffers, one for outbound
//   data, the other for inbound.
//
// * The external Http2Stream class extends from Duplex. When data is written
//   to the Writable side of the Duplex, the data is passed through via a
//   StreamBase WriteReq to the underlying internal Http2Stream StreamBase
//   implementation. From there, the data is written to the outgoing NodeBIO
//   buffer where it is stored until nghttp2 is prompted to begin reading it
//   out. When the internal Http2Stream StreamBase is told to begin Reading
//   (when the readStart() method is called), chunks of data will be read
//   out of the internal incoming NodeBIO buffer and pushed into the Readable
//   side of the Http2Stream Duplex.
//
// * The Http2Incoming class is a Readable that wraps the external Http2Stream
//   Duplex. When created, Http2Incoming redirects the data being read out of
//   the internal incoming NodeBIO buffer to it's own Readable state as opposed
//   to being pushed into the Http2Stream objects Readable state. The flow here
//   likely is not ideal and needs to be optimized.
//
// * The Http2Outgoing class is a Writable that wraps the external Http2Stream
//   Duplex. As data is written to the Http2Outgoing instance, it is forwarded
//   on to Http2Stream Duplex writable interface which pushes it into the
//   internal outgoing NodeBIO buffer instance. The flow here likely is not
//   ideal and needs to be optimized
//
// * There are still a number of Readable/Writable state issues that need to be
//   worked through.
//
// * Performance Bottlenecks: There are three fundamental performance
//   bottlenecks at play in this implementation: (a) The Streams API, (b)
//   How quickly we can pass data to and from the nghttp2 implementation
//   (also related to the streams API via the Socket), and (c) How quickly
//   and efficiently we can process the callbacks emitted by nghttp2 as
//   it is processing the data.

const http2 = process.binding('http2');
const uv = process.binding('uv');
const streamwrap = process.binding('stream_wrap');
const timers = require('timers');
const util = require('util');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const internalHttp = require('internal/http');
const net = require('net');
const tls = require('tls');
const stream = require('stream');
const FreeList = require('internal/freelist').FreeList;
const url = require('url');
const common = require('_http_common');
const WriteWrap = streamwrap.WriteWrap;
const Writable = stream.Writable;
const Readable = stream.Readable;
const Duplex = stream.Duplex;
const TLSServer = tls.Server;
const NETServer = net.Server;
const constants = http2.constants;
const utcDate = internalHttp.utcDate;

const kBeginSend = Symbol('begin-send');
const kFinished = Symbol('finished');
const kHandle = Symbol('handle');
const kHeaders = Symbol('headers');
const kHeadersSent = Symbol('headers-sent');
const kId = Symbol('id');
const kInFlight = Symbol('in-flight');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kNoBody = Symbol('nobody');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kResume = Symbol('resume');
const kSendDate = Symbol('send-date');
const kServer = Symbol('server');
const kSession = Symbol('session');
const kSocket = Symbol('socket');
const kStatusCode = Symbol('status-code');
const kStream = Symbol('stream');
const kStreams = Symbol('streams');
const kType = Symbol('type');
const kTrailers = Symbol('trailers');

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

Object.defineProperty(exports, 'constants', {
  configurable: false,
  enumerable: true,
  value: constants
});


const sessions = new FreeList('session', 1000, initSessionHandle);

function initSessionHandle() {
  const session = new http2.Http2Session();
  session.onRstStream = onRstStream;
  session.onGoaway = onGoaway;
  session.onHeaders = onHeaders;
  session.onStreamClose = onStreamClose;
  session.onError = onError;
  return session;
}

function freeSession(session) {
  if (session) {
    session.reset();
    session[kOwner][kHandle] = undefined;
    session[kOwner] = undefined;
    if (sessions.free(session) === false)
      session.close();
  }
}

function freeStream(stream) {
  if (stream) {
    stream.reset();
    stream[kOwner].end();
    stream[kOwner][kHandle] = undefined;
    stream[kOwner] = undefined;
    stream[kType] = undefined;
    stream.close();
  }
}

function onread(nread, buffer) {
  const stream = this[kOwner];
  unrefTimer(this);

  if (nread > 0) {
    var ret = stream.push(buffer);
    if (stream.reading && !ret) {
      stream.reading = false;
      var err = stream.readStop();
      if (err) {
        // TODO(jasnell): figure this out
        maybeDestroyStream(stream);
      }
    }
    return;
  }

  if (nread === 0) {
    return;
  }

  if (nread !== uv.UV_EOF) {
    // TODO(jasnell): figure out
    return maybeDestroyStream(stream);
  }

  stream.push(null);

  if (stream._readableState.length === 0) {
    stream.readable = false;
    // TODO(jasnell): Figure out
    //maybeDestroy(self);
  }
}

function onRstStream(id, code) {
  this[kOwner].emit('rststream', id, code);
}
function onGoaway(code, lastProcStreamID) {
  this[kOwner].emit('goaway', code, lastProcStreamID);
}
function onHeaders(handle, flags, headers, category) {
  var stream = handle[kOwner];
  if (!stream) {
    const id = handle.getId();
    stream = new Http2Stream(this[kOwner], id, {});
    stream._handle = handle;
    this[kOwner][kStreams].set(id, stream);
  }
  this[kOwner].emit('headers', stream, flags, headers, category);
}
function onStreamClose(id, code) {
  const stream = this[kOwner][kStreams].get(id);
  if (stream) {
    this[kOwner].emit('stream-close', stream, code);
    this[kOwner][kStreams].delete(id);
    freeStream(stream._handle);
  }
}
function onError(error) {
  this[kOwner].emit('error', error);
}

function unrefTimer(item) {
  timers._unrefActive(item);
}

function afterDoStreamWrite(status, handle, req) {
  unrefTimer(handle[kOwner]);
  if (typeof req.callback === 'function')
    req.callback();
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

// TODO(jasnell):
// There are three key states that need to be tracked: (1) Is the Http2Stream
// attached to the underlying Http2Session (e.g. that is, is the internal
// nghttp2_stream handle still valid), (2) Is the Http2Stream Duplex interface
// still Writable, and (3) Is the Http2Stream Duplex still Readable. The
// Http2Stream object cannot be disposed of and garbage collected until all
// three of those states are false. Because of async reads/writes on the Duplex
// interface, it's possible for the Http2Stream to become detached from the
// underlying Http2Session. Ideally, when that happens both the Readable and
// Writable sides will close and any internally buffered data would be dropped
// and additional writes will fail but I do not have that completely wired up
// yet. The maybeDestroyStream(stream) check is largely a temporary stopgap to
// determine when the Writable and Readable sides are closed so that we can
// allow the Http2Stream to be garbage collected.
function maybeDestroyStream(stream) {
  // if ((!stream.readable &&
  //      !stream.writable &&
  //      !stream._writableState.length)) {
  if ((!stream.writable &&
       !stream._writableState.length)) {
    timers.unenroll(stream);
    stream.session[kStreams].delete(stream.id);
    freeStream(stream._handle);
  }
}


class Http2Stream extends Duplex {
  constructor(session, id, options) {
    super(options);
    this[kId] = id;
    this[kSession] = session;
  }

  get _handle() {
    return this[kHandle];
  }

  set _handle(handle) {
    if (!(handle instanceof http2.Http2Stream))
      throw new TypeError('handle must be an Http2Stream');
    this[kHandle] = handle;
    this[kHandle].onread = onread;
    this[kHandle][kOwner] = this;
    this.emit('handle', handle);
  }

  get uid() {
    if (this._handle)
      return this._handle.getUid();
  }

  set id(id) {
    this[kId] = Number(id);
  }

  get id() {
    return this[kId];
  }

  get session() {
    return this[kSession];
  }

  get state() {
    const obj = {};
    if (this._handle)
      this._handle.getState(obj);
    return obj;
  }

  setLocalWindowSize(size) {
    if (this._handle) {
      this._handle.setLocalWindowSize(size);
    } else {
      this.once('handle', () => {
        this._handle.setLocalWindowSize(size);
      });
    }
  }

  changeStreamPriority(parentId, priority, exclusive) {
    if (this._handle) {
      this._handle.changeStreamPriority(parentId, priority, exclusive);
    } else {
      this.once('handle', () => {
        this._handle.changeStreamPriority(parentId, priority, exclusive);
      });
    }
  }

  respond() {
    if (this._handle) {
      this._handle.respond();
    } else {
      this.once('handle', () => {
        this._handle.respond();
      });
    }
  }

  resume() {
    if (this._handle) {
      this._handle.resume();
    } else {
      this.once('handle', () => {
        this._handle.resume();
      });
    }
  }

  sendContinue() {
    if (this._handle) {
      this._handle.sendContinue();
    } else {
      this.once('handle', () => {
        this._handle.sendContinue();
      });
    }
  }

  sendPriority(parentId, priority, exclusive) {
    if (this._handle) {
      this._handle.sendPriority(parentId, priority, exclusive);
    } else {
      this.once('handle', () => {
        this._handle.sendPriority(parentId, priority, exclusive);
      });
    }
  }

  sendRstStream(code) {
    if (this._handle) {
      this._handle.sendRstStream(code);
    } else {
      this.once('handle', () => {
        this._handle.sendRstStream(code);
      });
    }
  }

  sendPushPromise(headers) {
    if (this._handle) {
      return this._handle.sendPushPromise(mapToHeaders(headers));
    } else {
      this.once('handle', () => {
        this._handle.sendPushPromise(mapToHeaders(headers));
      });
    }
  }

  addHeader(name, value, noindex) {
    if (this._handle) {
      this._handle.addHeader(name, value, noindex);
    } else {
      this.once('handle', () => {
        this._handle.addHeader(name, value, noindex);
      });
    }
  }

  addTrailer(name, value, noindex) {
    if (this._handle) {
      this._handle.addTrailer(name, value, noindex);
    } else {
      this.once('handle', () => {
        this._handle.addTrailer(name, value, noindex);
      });
    }
  }

  refuse() {
    this.sendRstStream(constants.NGHTTP2_REFUSED_STREAM);
  }

  cancel() {
    this.sendRstStream(constants.NGHTTP2_CANCEL);
  }

  protocolError() {
    this.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR);
  }

  setTimeout(msecs, callback) {
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

  _write(data, encoding, cb) {
    if (this._handle) {
      unrefTimer(this);
      const req = new WriteWrap();
      req.handle = this._handle;
      req.callback = cb;
      req.oncomplete = afterDoStreamWrite;
      req.async = false;
      const enc = data instanceof Buffer ? 'buffer' : encoding;
      const err = createWriteReq(req, this._handle, data, enc);
      if (err)
        throw util._errnoException(err, 'write', req.error);
      this._bytesDispatched += req.bytes;
    } else {
      this.once('handle', onHandleWrite(data, encoding, cb));
    }
  }

  end(chunk, encoding, callback) {
    const state = this._writableState;
    if (state.ending || state.finished) {
      return;
    }
    super.end(chunk, encoding, callback);

    if (this._handle) {
      this._handle.finishedWriting();
    } else {
      this.on('handle', () => {
        this._handle.finishedWriting();
      });
    }
  }

  _read(n) {
    if (this._handle) {
      this._handle.readStart();
    } else {
      this.once('handle', () => {
        this._handle.readStart();
      });
    }
  }
}

function onHandleWrite(data, encoding, cb) {
  return function onWriteFinished() {
    this._write(data, encoding, cb);
  };
}

class Http2Session extends EventEmitter {
  constructor(type, options, socket) {
    super();
    this[kType] = type;
    this[kStreams] = new Map();
    this[kHandle] = sessions.alloc();
    this[kHandle][kOwner] = this;
    this[kHandle].reinitialize(type, options, socket._handle._externalStream);
  }

  reset() {
    if (this._handle)
      this._handle.reset();
  }

  get _handle() {
    return this[kHandle];
  }

  get uid() {
    if (this._handle)
      return this._handle.getUid();
  }

  get type() {
    return this[kType];
  }

  get state() {
    const obj = {};
    if (this._handle)
      this._handle.getState(obj);
    return obj;
  }

  setNextStreamID(id) {
    if (this._handle)
      this._handle.setNextStreamID(id);
  }

  setLocalWindowSize(size) {
    if (this._handle)
      this._handle.setLocalWindowSize(size);
  }

  get remoteSettings() {
    if (this._handle)
      return this._handle.getRemoteSettings();
  }

  get localSettings() {
    if (this._handle)
      return this._handle.getLocalSettings();
  }

  set localSettings(settings) {
    if (!(settings instanceof http2.Http2Settings))
      throw new TypeError('settings must be an instance of Http2Settings');
    if (this._handle) {
      this._handle.setLocalSettings(settings);
    }
  }

  // Begin graceful termination process. See:
  // https://nghttp2.org/documentation/nghttp2_submit_shutdown_notice.html
  // For detail. This process results in sending two GOAWAY frames to the
  // client. The second one is the actual GOAWAY that will terminate the
  // session. The second terminate and the passed in callback are invoked
  // on nextTick (TODO(jasnell): setImmediate might be better)).
  gracefulTerminate(code, callback) {
    if (!this.isAlive) return;
    if (typeof code === 'function') {
      callback = code;
      code = undefined;
    }
    if (typeof callback !== 'function')
      throw new TypeError('callback must be a function');

    this._handle.startGracefulTerminate();
    process.nextTick(() => {
      this._handle.terminate(code || constants.NGHTTP2_NO_ERROR);
      callback();
    });
  }

  request(headers, nobody) {
    if (this._handle)
      return this._handle.request(headers, nobody);
  }
}


function initHttp2IncomingOptions(options) {
  // TODO(jasnell): It might make sense to set the default highWaterMark
  // for Incoming Streams to the configured Max Frame Size, this would
  // ensure that the stream buffer could at least consume a single complete
  // data frames worth of data
  options = options || {};
  return options;
}

function initHttp2OutgoingOptions(options) {
  options = options || {};
  return options;
}

function incomingOnRead(nread, buffer) {
  const stream = this[kOwner][kRequest];
  unrefTimer(this);

  if (nread > 0) {
    var ret = stream.push(buffer);
    if (stream.reading && !ret) {
      stream.reading = false;
      var err = stream.readStop();
      if (err) {
        // TODO(jasnell): figure this out
        maybeDestroyStream(stream);
      }
    }
    return;
  }

  if (nread === 0) {
    return;
  }

  if (nread !== uv.UV_EOF) {
    // TODO(jasnell): figure out
    return maybeDestroyStream(stream);
  }

  stream.push(null);

  if (stream._readableState.length === 0) {
    stream.readable = false;
    // TODO(jasnell): Figure out
    //maybeDestroy(self);
  }
}

// Represents an incoming HTTP/2 message.
// TODO(jasnell): This is currently incomplete
class Http2Incoming extends Readable {
  constructor(stream, headers, options) {
    super(initHttp2IncomingOptions(options));
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream argument must be an Http2Stream instance');
    if (!(headers instanceof Map))
      throw new TypeError('headers argument must be a Map');
    this[kStream] = stream;
    this[kHeaders] = headers;
    this[kFinished] = false;
    this[kStream]._handle.onread = incomingOnRead;
  }

  get finished() {
    return this.stream === undefined || this[kFinished];
  }

  get stream() {
    return this[kStream];
  }

  get headers() {
    return this[kHeaders];
  }

  get trailers() {
    return this[kTrailers];
  }

  get httpVersion() {
    return '2.0';
  }

  get complete() {
    return this[kFinished];
  }

  // Set the timeout on the underlying Http2Stream object
  setTimeout(msecs, callback) {
    if (!this.stream) return;
    this.stream.setTimeout(msecs, callback);
    return this;
  }

  _read(n) {
    this[kStream]._handle.readStart();
  }
}

// Represents an incoming HTTP Request on the Server.
class Http2ServerRequest extends Http2Incoming {
  constructor(stream, headers, options) {
    super(stream, headers, options);
  }

  get method() {
    return this.headers.get(constants.HTTP2_HEADER_METHOD);
  }

  get authority() {
    return this.headers.get(constants.HTTP2_HEADER_AUTHORITY);
  }

  get scheme() {
    return this.headers.get(constants.HTTP2_HEADER_SCHEME);
  }

  get url() {
    return this.headers.get(constants.HTTP2_HEADER_PATH);
  }
}

function onHttp2OutgoingPipe() {
  if (this[kHeadersSent])
    this[kResume]();
  else
    this[kBeginSend]();
}

// Represents an outbound HTTP message.
class Http2Outgoing extends Writable {
  constructor(stream, options) {
    super(initHttp2OutgoingOptions(options));
    this[kStream] = stream;
    this[kFinished] = false;
    this[kHeadersSent] = false;
    this.on('pipe', onHttp2OutgoingPipe);
    this.bufferedCallback = null;
  }

  get stream() {
    return this[kStream];
  }

  get finished() {
    return this.stream === undefined || this[kFinished];
  }

  get headersSent() {
    return this[kHeadersSent];
  }

  setHeader(name, value, noindex) {
    if (this.headersSent)
      throw new Error(
        'Cannot set headers after the HTTP message has been sent');
    if (!this.stream)
      throw new Error('Cannot set header on a closed stream');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP/1 headers are not permitted');
    if (value === undefined || value === null) {
      throw new TypeError('Value must not be undefined or null');
    }
    this.stream.addHeader(name, value, Boolean(noindex));
    return this;
  }

  setTrailer(name, value, noindex) {
    if (this.headersSent)
      throw new Error(
        'Cannot set trailers after the HTTP message has been sent');
    if (!this.stream)
      throw new Error('Cannot set trailer on a closed stream');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP/1 headers are not permitted');
    if (value === undefined || value === null) {
      throw new TypeError('Value must not be undefined or null');
    }
    this.stream.addTrailer(name, value, Boolean(noindex));
    return this;
  }

  addHeaders(headers) {
    if (!headers) return;
    const keys = Object.keys(headers);
    for (const key of keys)
      this.setHeader(key, headers[key]);
    return this;
  }

  addTrailers(headers) {
    if (!headers) return;
    const keys = Object.keys(headers);
    for (const key of keys)
      this.setTrailer(key, headers[key]);
    return this;
  }

  // Set the timeout on the underlying Http2Stream object
  setTimeout(msecs, callback) {
    if (!this.stream) return;
    this.stream.setTimeout(msecs, callback);
    return this;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string')
      chunk = Buffer.from(chunk, encoding);
    if (this.stream) {
      this[kBeginSend]();
      this.bufferedCallback = callback;
      this.stream.write(chunk, encoding, outWriteResume);
    } else {
      this[kFinished] = true;
      callback();
    }
  }

  end(data, encoding, callback) {
    if (this.stream) {
      this[kBeginSend]();
      this[kFinished] = true;
      this.stream.end(data, encoding, callback);
      return;
    }
    throw new Error('write after end');
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      this.stream.respond(Boolean(this[kNoBody]));
    }
  }

  [kResume]() {
    if (this.stream) {
      this.stream.resume();
    }
  }
}

function outWriteResume() {
  this[kResume]();
  const callback = this.bufferedCallback;
  this.bufferedCallback = null;
  if (typeof callback === 'function')
    callback();
}

// Represents an HTTP/2 server response message
class Http2ServerResponse extends Http2Outgoing {
  constructor(stream, options) {
    super(stream, options);
    this[kStatusCode] = constants.HTTP_STATUS_OK;
    this[kSendDate] = true;
    this[kOptions] = options;
  }

  get sendDate() {
    return this[kSendDate];
  }

  set sendDate(bool) {
    this[kSendDate] = Boolean(bool);
  }

  get statusCode() {
    return this[kStatusCode];
  }

  set statusCode(code) {
    code |= 0;
    if (code === constants.HTTP_STATUS_SWITCHING_PROTOCOLS)
      throw new RangeError(
        `Status code ${constants.HTTP_STATUS_SWITCHING_PROTOCOLS}` +
        ' is not supported by HTTP/2');
    if (code < 100 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    this[kStatusCode] = code;
  }

  get pushSupported() {
    if (!this.stream) return false;
    return this.stream.session.remoteSettings.enablePush;
  }

  writeContinue() {
    if (this.stream) {
      this.stream.sendContinue();
    }
  }

  // TODO(jasnell): It would be useful to have a variation on writeHead
  // that causes the Writable side to close automatically in the case
  // where there is no data to send. This would allow us to optimize
  // the HTTP/2 frames by only sending the response HEADERS frame and
  // no DATA frames. Otherwise, the current API would result in have to
  // send at least one possibly empty DATA frame every time...
  //
  // Note: the nobody arg is a temporary way of handling no-body responses.
  // I will be refactoring this API but I wanted a way to experiment with
  // the approach a bit.
  writeHead(statusCode, headers, nobody) {
    if (typeof statusCode === 'object') {
      headers = statusCode;
      statusCode = constants.HTTP_STATUS_OK;
    }
    this.statusCode = statusCode || constants.HTTP_STATUS_OK;
    this.addHeaders(headers);
    if (nobody)
      this[kNoBody] = true;
    return this;
  }

  createPushResponse() {
    if (!this.pushSupported)
      return;
    if (this[kHeadersSent])
      this[kResume]();
    else
      this[kBeginSend]();
    return new Http2PushResponse(this);
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this.stream.addHeader(constants.HTTP2_HEADER_STATUS, this.statusCode);
      if (this.sendDate)
        this.setHeader('date', utcDate());
    }
    super[kBeginSend]();
  }
}

// Http2PushResponse objects are used to prepare push streams.
// TODO(jasnell): The API on this is still largely undetermined.
class Http2PushResponse extends EventEmitter {
  constructor(response) {
    super();
    this[kResponse] = response;
    this[kHeaders] = new Map();
    this.headers.set(constants.HTTP2_HEADER_METHOD, 'GET');
    this.headers.set(constants.HTTP2_HEADER_AUTHORITY,
                     response.stream[kRequest].authority);
    this.headers.set(constants.HTTP2_HEADER_SCHEME,
                     response.stream[kRequest].scheme);
  }

  get path() {
    return this.headers.get(constants.HTTP2_HEADER_PATH);
  }

  set path(val) {
    this.headers.set(constants.HTTP2_HEADER_PATH, String(val));
  }

  get method() {
    return this.headers.get(constants.HTTP2_HEADER_METHOD);
  }

  set method(val) {
    this.headers.set(constants.HTTP2_HEADER_METHOD, String(val));
  }

  get authority() {
    return this.headers.get(constants.HTTP2_HEADER_AUTHORITY);
  }

  set authority(val) {
    this.headers.set(constants.HTTP2_HEADER_AUTHORITY, String(val));
  }

  get scheme() {
    return this.headers.get(constants.HTTP2_HEADER_SCHEME);
  }

  set scheme(val) {
    this.headers.set(constants.HTTP2_HEADER_SCHEME, String(val));
  }

  get headers() {
    return this[kHeaders];
  }

  push(callback) {
    if (typeof callback !== 'function')
      throw new TypeError('callback must be a function');
    const parent = this[kResponse].stream;
    const ret = parent.sendPushPromise(this[kHeaders]);
    if (ret) {
      const id = ret.getId();
      const stream = new Http2Stream(parent.session, id, {});
      stream._handle = ret;
      parent.session[kStreams].set(id, stream);

      stream.readable = false;
      const request =
          stream[kRequest] =
              new Http2ServerRequest(stream, this[kHeaders]);
      const response =
          stream[kResponse] =
              new Http2ServerResponse(stream, this[kResponse][kOptions]);
      request[kFinished] = true;
      request[kInFlight] = true;
      callback(request, response);
      request[kInFlight] = false;
    }
  }
}

// The HTTP/2 spec forbids request pseudo-headers from appearing within
// responses, and response pseudo-headers from appearing with requests.
// Improper use must be handled as malformed messages.
function isPseudoHeader(name) {
  return String(name)[0] === ':';
}

// HTTP/2 strictly forbids the use of connection specific headers. In
// particular, Connection, Upgrade and HTTP2-Settings must not be used
// within HTTP/2 requests or response messages. Their use must be handled
// as malformed messages.
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

// Converts a ES6 map into an http2.Http2Headers object.
// The Http2Headers object maintains an internal array
// of nghttp2_nv objects that contain a copy of the
// header value pairs as an std::vector. To avoid
// that vector having to copy and reallocate, we count
// the number of expected items up front (it's less
// expensive to count than it is to reallocate).
function mapToHeaders(map) {
  var size = map.size;
  for (const v of map) {
    if (Array.isArray(v[1])) {
      size += v[1].length - 1;
    }
  }
  const ret = new http2.Http2Headers(size);
  if (!(map instanceof Map))
    return ret;
  for (const v of map) {
    const key = String(v[0]);
    const value = v[1];
    if (Array.isArray(value) && value.length > 0) {
      for (const item of value)
        ret.add(key, String(item));
    } else {
      ret.add(key, String(value));
    }
  }
  return ret;
}

// The HTTP/2 Server Connection Listener. This is used for both the TLS and
// non-TLS variants. For every socket, there is exactly one Http2Session.
// TODO(jasnell): Currently, a new Http2Session instance is created for every
// socket. We should investigate whether it would be possible to use pooling
// like we do with http-parser instances currently. It might not be possible
// due to long term connection state management, but it's worth investigating
// for performance.

function socketOnResume() {
  if (this._paused) {
    this.pause();
    return;
  }
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

function sessionOnStreamClose(stream, code) {
  const request = stream[kRequest];
  const response = stream[kResponse];
  if (request && !request.finished) {
    request.readable = false;
    request[kFinished] = true;
    if (request[kInFlight])
      request.emit('aborted');
  }
  if (response && !response.finished) {
    response.end();
    response[kFinished] = true;
  }

  request[kStream] = undefined;
  response[kStream] = undefined;
  stream[kRequest] = undefined;
  stream[kResponse] = undefined;
  setImmediate(() => maybeDestroyStream(stream));
}

function sessionOnError(server, socket) {
  function fn(error) {
    if (server.listenerCount('sessionError') > 0) {
      server.emit('sessionError', error);
      return;
    }
    socket.destroy(error);
  }
  return fn;
}

function socketOnTimeout(server, session) {
  function fn() {
    if (!server.emit('timeout', this)) {
      // Session timed out, attempt a graceful exit
      session.gracefulTerminate(() => this.destroy());
    }
  }
  return fn;
}

function socketOnceError(error) {
  if (kRenegTest.test(error.message)) {
    // A tls renegotiation attempt was made. There's no need
    // to propogate the error and there's nothing more we can
    // do with the connection. Destroy it and move on.
    this.destroy();
    return;
  }
  // If the socket experiences an error, there's not much that
  // we're going to be able to do as the error could have a
  // fatal impact on any number of open in-flight requests.
  // In the http/1 implementation, we emit a clientError that
  // gives the user code an opportunity to send a graceful
  // HTTP error response. For here, since there may be any
  // number of open streams, we'll notify the server of the
  // failure allow it to do whatever it will. If no socketError
  // listeners are registered, destroy the socket.
  if (!this[kServer].emit('socketError', error, this)) {
    this.destroy(error);
  }
}

function sessionOnHeaderComplete(stream, flags, headers, category) {
  const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
  const server = this[kServer];
  // This is a server, so the only header categories supported are
  // NGHTTP2_HCAT_REQUEST and NGHGTTP2_HCAT_HEADERS. Other categories
  // must result in a Protocol error per the spec.
  var request;
  var response;
  switch (category) {
    case constants.NGHTTP2_HCAT_REQUEST:
      request = stream[kRequest] =
          new Http2ServerRequest(stream, headers,
                                 server[kOptions].defaultIncomingOptions);
      response = stream[kResponse] =
          new Http2ServerResponse(stream,
                                  server[kOptions].defaultOutgoingOptions);
      // finished will be true if the header block included flags to end
      // the stream (such as when sending a GET request). In such cases,
      // mark the kRequest stream finished so no data will be read.
      if (finished)
        request[kFinished] = true;

      if (headers.has('expect')) {
        // If there is an expect header that contains 100-continue,
        // and the server has a listener for the checkContinue event,
        // emit the checkContinue event instead of the request event.
        // This behavior matches the current http/1 API.
        if (/^100-continue$/i.test(headers.get('expect'))) {
          if (server.listenerCount('checkContinue') > 0) {
            request[kInFlight] = true;
            server.emit('checkContinue', request, response);
            request[kInFlight] = undefined;
            break;
          }
          response.writeContinue();
          // This falls through to the emit the request event
        } else {
          // If there is an expect header that contains anything
          // other than 100-continue, emit the checkExpectation
          // event if there are listeners or automatically return
          // a 417 and end the response. This behavior matches the
          // current http/1 API
          if (server.listenerCount('checkExpectation') > 0) {
            request[kInFlight] = true;
            server.emit('checkExpectation', request, response);
            request[kInFlight] = undefined;
          } else {
            response.writeHead(constants.HTTP_STATUS_EXPECTATION_FAILED);
            response.end();
          }
          break;
        }
      }
      // Handle CONNECT requests. If there is a connect listener, emit the
      // connect event rather than the request event, otherwise RST-STREAM
      // with the NGHTTP2_REFUSED_STREAM code.
      // TODO(jasnell): Still need to test that this is working correctly.
      // To do so we need a client that can send a proper http/2 connect
      // request.
      if (request.method === 'CONNECT') {
        if (server.listenerCount('connect') > 0) {
          request[kInFlight] = true;
          server.emit('connect', request, response);
          request[kInFlight] = undefined;
        } else {
          stream.refuse();
        }
        break;
      }
      request[kInFlight] = true;
      server.emit('request', request, response);
      request[kInFlight] = undefined;
      break;
    case constants.NGHTTP2_HCAT_HEADERS:
      if (!finished) {
        // When category === NGHTTP2_HCAT_HEADERS and finished is not
        // null, that means an extra HEADERS frame was sent after
        // the initial HEADERS frame that opened the request, without the
        // end stream flag set. Interstitial headers frames are not permitted
        // in the HTTP semantic binding per the HTTP/2 spec
        stream.protocolError();
        return;
      }
      // If finished, that means these are trailing headers
      stream[kRequest][kTrailers] = headers;
      break;
    default:
      stream.protocolError();
  }
}

function connectionListener(socket) {
  const options = this[kOptions];

  // Create the Http2Session instance that is unique to this socket.
  const session = createServerSession(options, socket);
  session[kServer] = this;
  socket[kServer] = this;

  session.on('error', sessionOnError(this, socket));

  // Disable TLS Negotiation on this socket. The HTTP/2 allows renegotiation to
  // happen up until the initial HTTP/2 session bootstrap. After that, it is
  // forbidden. Let's just turn it off entirely.
  if (typeof socket.disableRenegotiation === 'function')
    socket.disableRenegotiation();

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', socketOnTimeout(this, session));

  // Destroy the session if the socket is destroyed
  const destroySocket = socket.destroy;
  socket.destroy = function(error) {
    session.removeAllListeners();
    socket.removeAllListeners();
    freeSession(session._handle);
    socket.destroy = destroySocket;
    destroySocket.call(socket, error);
    socket[kServer] = undefined;
    session[kServer] = undefined;
  };
  socket.once('error', socketOnceError);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);
  session.on('headers', sessionOnHeaderComplete);
  session.on('streamClose', sessionOnStreamClose);
  session.localSettings = options.settings;
}

function initializeOptions(options) {
  options = options || {};
  options.allowHalfOpen = true;
  options.settings = options.settings || new http2.Http2Settings();
  if (!(options.settings instanceof http2.Http2Settings)) {
    throw new TypeError(
        'options.settings must be an instance of Http2Settings');
  }
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

class Http2SecureServerSession extends TLSServer {
  constructor(options, requestListener) {
    super(initializeTLSOptions(options), connectionListener);
    this[kOptions] = options;
    this.timeout = kDefaultSocketTimeout;
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', (err, conn) => {
      if (!this.emit('clientError', err, conn))
        conn.destroy(err);
    });
  }

  setTimeout(msecs, callback) {
    this.timeout = msecs;
    if (callback)
      this.on('timeout', callback);
    return this;
  }
}

class Http2ServerSession extends NETServer {
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
  return new Http2Session(constants.SESSION_TYPE_SERVER, options, socket);
}

function createClientSession(options, socket) {
  return new Http2Session(constants.SESSION_TYPE_CLIENT, options, socket);
}

function createSecureServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  if (typeof handler !== 'function')
    throw new TypeError('handler must be a function');
  return new Http2SecureServerSession(options, handler);
}

function createServer(options, handler) {
  if (typeof options === 'function') {
    handler = options;
    options = {};
  }
  if (typeof handler !== 'function')
    throw new TypeError('handler must be a function');
  return new Http2ServerSession(options, handler);
}


// Client Implementation

function acquireSocket(options, callback) {
  switch (options.protocol) {
    case 'http:':
      return net.connect(options, callback);
    case 'https:':
      return tls.connect(options, callback);
    default:
      throw new Error(`Protocol ${options.protocol} not supported.`);
  }
}

function clientSessionOnError(client, socket) {
  function fn(error) {
    if (client.listenerCount('sessionError') > 0) {
      client.emit('sessionError', error);
      return;
    }
    socket.destroy(error);
  }
  return fn;
}

function clientSessionOnHeaderComplete(stream, flags, headers, category) {
  const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
  const request = stream[kRequest];
  switch (category) {
    case constants.NGHTTP2_HCAT_RESPONSE:
      // TODO: Handle various types of responses appropriately
      const response = new Http2ClientResponse(stream, headers, {});
      stream[kResponse] = response;
      request.emit('response', response);
      break;
    case constants.NGHTTP2_HCAT_HEADERS:
      if (!finished) {
        stream.protocolError();
        return;
      }
      stream[kResponse][kTrailers] = headers;
      break;
    case constants.NGHTTP2_HCAT_PUSH_PROMISE:
      // TODO(jasnell): Complete this
      stream.cancel();
      break;
    default:
      stream.protocolError();
  }
}

function clientSessionOnStreamClose(stream, code) {
  const request = stream[kRequest];
  const response = stream[kResponse];
  if (response && !response.finished) {
    response.readable = false;
    response[kFinished] = true;
  }
  if (request && !request.finished) {
    request.end();
    request[kFinished] = true;
  }

  request[kStream] = undefined;
  response[kStream] = undefined;
  stream[kRequest] = undefined;
  stream[kResponse] = undefined;
  setImmediate(() => maybeDestroyStream(stream));
}

function initializeClientOptions(options) {
  if (typeof options === 'string') {
    //options = new URL(options);
    options = url.parse(options);
    if (!options.hostname)
      throw new Error('Unable to determine the domain name');
  } else {
    options = util._extend({}, options);
  }

  var defaultPort = 80;
  if (options.protocol === 'https:')
    defaultPort = 443;
  options.port = options.port || defaultPort || 80;

  options.hostname = options.host = options.hostname || 'localhost';
  options.method = (options.method || 'GET').toUpperCase();
  if (!common._checkIsHttpToken(options.method)) {
    throw new TypeError('Method must be a valid HTTP token');
  }
  options.path = options.path || '/';
  return initializeOptions(options);
}

class Http2ClientSession extends EventEmitter {
  constructor(options, callback) {
    super();
    this[kOptions] = initializeClientOptions(options);
    const socket = acquireSocket(options, () => {
      this[kSocket] = socket;

      const session = this[kSession] = createClientSession(options, socket);
      socket.once('error', (error) => {
        console.log(error);
      });
      socket.on('resume', socketOnResume);
      socket.on('pause', socketOnPause);
      socket.on('drain', socketOnDrain);
      session.on('error', clientSessionOnError(this, socket));
      session.on('headers', clientSessionOnHeaderComplete);
      session.on('streamClose', clientSessionOnStreamClose);
      session.localSettings = options.settings;
      if (typeof callback === 'function')
        callback(this);

    });
  }

  get session() {
    return this[kSession];
  }

  get socket() {
    return this[kSocket];
  }

  get(options, callback) {
    options = options || {};
    options.method = 'GET';
    this.request(options, callback).end();
  }

  request(options, callback) {
    options = options || {};
    const stream = new Http2Stream(this[kSession], -1, options);
    const req = new Http2ClientRequest(stream,
                                       initializeClientOptions(options),
                                       callback);
    return req;
  }

  static request(options, callback) {
    options = initializeClientOptions(options);
    createClient(options, (session) => {
      session.request(options, callback);
    });
  }

  static get(options, callback) {
    options = initializeClientOptions(options);
    createClient(options, (session) => {
      session.get(options, callback);
    });
  }
}

class Http2ClientRequest extends Http2Outgoing {
  constructor(stream, options, callback) {
    if (typeof options === 'string') {
      options = new URL(options);
      if (!options.hostname)
        throw new Error('Unable to determine the domain name');
    } else {
      options = util._extend({}, options);
    }

    var defaultPort = 80;
    if (options.protocol === 'https:')
      defaultPort = 443;
    options.port = options.port || defaultPort || 80;

    options.hostname = options.hostname || 'localhost';
    options.method = (options.method || 'GET').toUpperCase();
    if (!common._checkIsHttpToken(options.method)) {
      throw new TypeError('Method must be a valid HTTP token');
    }
    options.pathname = options.pathname || '/';

    super(stream, options);
    stream[kRequest] = this;

    var authority = options.hostname;
    if (options.port)
      authority += `:${options.port}`;
    const headers = this[kHeaders] = new Map();

    headers.set(constants.HTTP2_HEADER_SCHEME,
                options.protocol.slice(0, options.protocol.length - 1));
    headers.set(constants.HTTP2_HEADER_METHOD, options.method);
    headers.set(constants.HTTP2_HEADER_AUTHORITY, authority);
    headers.set(constants.HTTP2_HEADER_PATH, options.pathname);

    if (typeof callback === 'function')
      this.once('response', callback);
  }

  setHeader(name, value) {
    name = String(name).toLowerCase().trim();
    if (this[kHeaders].has(name)) {
      const existing = this[kHeaders].get(name);
      if (Array.isArray(existing)) {
        existing.push(String(value));
      } else {
        this[kHeaders].set(name, [existing, value]);
      }
    } else {
      this[kHeaders].set(name, value);
    }
  }

  setTrailer(name, value) {
    if (!this[kTrailers])
      this[kTrailers] = new Map();
    name = String(name).toLowerCase().trim();
    if (this[kTrailers].has(name)) {
      const existing = this[kTrailers].get(name);
      if (Array.isArray(existing)) {
        existing.push(String(value));
      } else {
        this[kTrailers].set(name, [existing, value]);
      }
    } else {
      this[kTrailers].set(name, value);
    }
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      const _handle = this.stream.session.request(mapToHeaders(this[kHeaders]), true);
      if (_handle instanceof http2.Http2Stream) {
        this[kId] = _handle.getId();
        this.stream.once('handle', () => {
          if (this[kTrailers] instanceof Map) {
            for (const v of this[kTrailers]) {
              const key = String(v[0]);
              const value = v[1];
              if (Array.isArray(value) && value.length > 0) {
                for (const item of value)
                  this.stream.addTrailer(key, String(item));
              } else {
                this.stream.addTrailer(key, String(value));
              }
            }
          }
        });
        this.stream._handle = _handle;
      }
    }
  }

  end() {
    super.end();
  }
}

class Http2ClientResponse extends Http2Incoming {
  constructor(stream, headers, options) {
    super(stream, headers, options);
  }

  get status() {
    return this.headers.get(constants.HTTP2_HEADER_STATUS) | 0;
  }
}

function createClient(options, callback) {
  return new Http2ClientSession(options, callback);
}

// Exports
module.exports = {
  get: Http2ClientSession.get,
  request: Http2ClientSession.request,
  Http2Settings: http2.Http2Settings,
  createClient: createClient,
  createServer: createServer,
  createSecureServer: createSecureServer,
  createServerSession: createServerSession,
  createClientSession: createClientSession
};
