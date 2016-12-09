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
const URL = url.URL;
const common = require('_http_common');
const WriteWrap = streamwrap.WriteWrap;
const ShutdownWrap = streamwrap.ShutdownWrap;
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
const kImplicitHeaders = Symbol('implicit-headers');
const kInFlight = Symbol('in-flight');
const kOptions = Symbol('options');
const kOwner = Symbol('owner');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
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
  var session = new http2.Http2Session();
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
    var owner = session[kOwner];
    owner[kHandle] = undefined;
    session[kOwner] = undefined;
    if (sessions.free(session) === false)
      session.close();
  }
}

function freeStream(stream) {
  if (stream) {
    stream.reset();
    var owner = stream[kOwner];
    owner.end();
    owner[kHandle] = undefined;
    stream[kOwner] = undefined;
    stream[kType] = undefined;
    stream.close();
  }
}

function onread(nread, buffer) {
  var stream = this[kOwner];
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
  var owner = this[kOwner];
  owner.emit('rststream', id, code);
}
function onGoaway(code, lastProcStreamID) {
  var owner = this[kOwner];
  owner.emit('goaway', code, lastProcStreamID);
}
function onHeaders(handle, flags, headers, category) {
  var stream = handle[kOwner];
  var owner = this[kOwner];
  if (!stream) {
    var id = handle.getId();
    stream = new Http2Stream(owner, id, {});
    stream._handle = handle;
    owner[kStreams].set(id, stream);
  }
  owner.emit('headers', stream, flags, headers, category);
}
function onStreamClose(id, code) {
  var owner = this[kOwner];
  var stream = owner[kStreams].get(id);
  if (stream) {
    owner.emit('streamClose', stream, code);
    owner[kStreams].delete(id);
    freeStream(stream[kHandle]);
  }
}
function onError(error) {
  var owner = this[kOwner];
  owner.emit('error', error);
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
    var session = stream[kSession];
    session[kStreams].delete(stream[kId]);
    freeStream(stream[kHandle]);
  }
}


class Http2Stream extends Duplex {
  constructor(session, id, options) {
    options.allowHalfOpen = true;
    super(options);
    this[kId] = id;
    this[kSession] = session;
    this.on('finish', onHandleFinish);
  }

  get _handle() {
    return this[kHandle];
  }

  set _handle(handle) {
    if (!(handle instanceof http2.Http2Stream))
      throw new TypeError('handle must be an Http2Stream');
    this[kHandle] = handle;
    handle.onread = onread;
    handle[kOwner] = this;
    this.emit('handle', handle);
  }

  get uid() {
    if (this[kHandle])
      return this[kHandle].getUid();
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
    var obj = {};
    if (this[kHandle])
      this[kHandle].getState(obj);
    return obj;
  }

  setLocalWindowSize(size) {
    if (this[kHandle]) {
      this[kHandle].setLocalWindowSize(size);
    } else {
      this.once('handle', this.setLocalWindowSize.bind(this, size));
    }
  }

  changeStreamPriority(parentId, priority, exclusive) {
    if (this[kHandle]) {
      this[kHandle].changeStreamPriority(parentId, priority, exclusive);
    } else {
      this.once('handle',
                this.changeStreamPriority.bind(this,
                                               parentId,
                                               priority,
                                               exclusive));
    }
  }

  respond(headers) {
    if (this[kHandle]) {
      this[kHandle].respond(headers);
    } else {
      this.once('handle', onHandleRespond(headers));
    }
  }

  sendContinue() {
    if (this[kHandle]) {
      this[kHandle].sendContinue();
    } else {
      this.once('handle', this.sendContinue.bind(this));
    }
  }

  sendPriority(parentId, priority, exclusive) {
    if (this[kHandle]) {
      this[kHandle].sendPriority(parentId, priority, exclusive);
    } else {
      this.once('handle',
                this.sendPriority.bind(this,
                                       parentId,
                                       priority,
                                       exclusive));
    }
  }

  sendRstStream(code) {
    if (this[kHandle]) {
      this[kHandle].sendRstStream(code);
    } else {
      this.once('handle', this.sendRstStream.bind(this, code));
    }
  }

  sendPushPromise(headers) {
    if (this[kHandle]) {
      return this[kHandle].sendPushPromise(mapToHeaders(headers));
    } else {
      this.once('handle', this.sendPushPromise.bind(this, headers));
    }
  }

  addTrailer(name, value, noindex) {
    if (this[kHandle]) {
      this[kHandle].addTrailer(name, value, noindex);
    } else {
      this.once('handle', this.addTrailer.bind(this, name, value, noindex));
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
    if (this[kHandle]) {
      unrefTimer(this);
      var req = new WriteWrap();
      req.handle = this[kHandle];
      req.callback = cb;
      req.oncomplete = afterDoStreamWrite;
      req.async = false;
      var enc = data instanceof Buffer ? 'buffer' : encoding;
      var err = createWriteReq(req, this[kHandle], data, enc);
      if (err)
        throw util._errnoException(err, 'write', req.error);
      this._bytesDispatched += req.bytes;
    } else {
      this.once('handle', onHandleWrite(data, encoding, cb));
    }
  }

  _writev(data, cb) {
    if (this[kHandle]) {
      unrefTimer(this);
      var req = new WriteWrap();
      req.handle = this[kHandle];
      req.callback = cb;
      req.oncomplete = afterDoStreamWrite;
      req.async = false;
      var chunks = new Array(data.length << 1);
      for (var i = 0; i < data.length; i++) {
        var entry = data[i];
        chunks[i * 2] = entry.chunk;
        chunks[i * 2 + 1] = entry.encoding;
      }
      var err = this[kHandle].writev(req, chunks);
      if (err)
        throw util._errnoException(err, 'write', req.error);
    } else {
      this.once('handle', onHandleWritev(data, cb));
    }
  }

  _read(n) {
    if (this[kHandle]) {
      this[kHandle].readStart();
    } else {
      this.once('handle', onHandleReadStart);
    }
  }
}

function afterShutdown() {}
function onHandleFinish() {
  var req = new ShutdownWrap();
  req.oncomplete = afterShutdown;
  req.handle = this[kHandle];
  this[kHandle].shutdown(req);
}

function onHandleReadStart() {
  this[kHandle].readStart();
}

function onHandleWrite(data, encoding, cb) {
  return function onWriteFinished() {
    this._write(data, encoding, cb);
  };
}

function onHandleWritev(chunks, cb) {
  return function onWriteFinished() {
    this._writev(chunks, cb);
  };
}

function onHandleRespond(headers) {
  return function(headers) {
    this[kHandle].respond();
  };
}

class Http2Session extends EventEmitter {
  constructor(type, options, socket) {
    super();
    this[kType] = type;
    this[kStreams] = new Map();
    var handle = sessions.alloc();
    this[kHandle] = handle;
    handle[kOwner] = this;
    handle.reinitialize(type, options, socket._handle._externalStream);
    this[kSocket] = socket;
  }

  reset() {
    if (this[kHandle])
      this[kHandle].reset();
  }

  get _handle() {
    return this[kHandle];
  }

  get uid() {
    if (this[kHandle])
      return this[kHandle].getUid();
  }

  get type() {
    return this[kType];
  }

  get state() {
    var obj = {};
    if (this[kHandle])
      this[kHandle].getState(obj);
    return obj;
  }

  setNextStreamID(id) {
    if (this[kHandle])
      this[kHandle].setNextStreamID(id);
  }

  setLocalWindowSize(size) {
    if (this[kHandle])
      this[kHandle].setLocalWindowSize(size);
  }

  get remoteSettings() {
    if (this[kHandle])
      return this[kHandle].getRemoteSettings();
  }

  get localSettings() {
    if (this[kHandle])
      return this[kHandle].getLocalSettings();
  }

  set localSettings(settings) {
    if (!(settings instanceof http2.Http2Settings))
      throw new TypeError('settings must be an instance of Http2Settings');
    if (this[kHandle]) {
      this[kHandle].setLocalSettings(settings);
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

    this[kHandle].startGracefulTerminate();
    process.nextTick(() => {
      this[kHandle].terminate(code || constants.NGHTTP2_NO_ERROR);
      callback();
    });
  }

  request(headers) {
    if (this[kHandle])
      return this[kHandle].request(headers);
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
  var owner = this[kOwner];
  var stream = owner[kRequest];
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
    options = initHttp2IncomingOptions(options);
    super(options);
    if (!(stream instanceof Http2Stream))
      throw new TypeError('stream argument must be an Http2Stream instance');
    if (typeof headers !== 'object')
      throw new TypeError('headers argument must be an object');
    this[kStream] = stream;
    this[kHeaders] = headers;
    this[kFinished] = false;
    var handle = stream[kHandle];
    handle.onread = incomingOnRead;
  }

  get finished() {
    return this[kStream] === undefined || this[kFinished];
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
    var stream = this[kStream];
    if (!stream) return;
    stream.setTimeout(msecs, callback);
    return this;
  }

  _read(n) {
    var stream = this[kStream];
    var handle = stream[kHandle];
    handle.readStart();
  }
}

// Represents an incoming HTTP Request on the Server.
class Http2ServerRequest extends Http2Incoming {
  constructor(stream, headers, options) {
    super(stream, headers, options);
  }

  get method() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_METHOD];
  }

  get authority() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_AUTHORITY];
  }

  get scheme() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_SCHEME];
  }

  get url() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_PATH];
  }
}

function onHttp2OutgoingPipe() {
  if (!this[kHeadersSent]) {
    var beginSend = this[kBeginSend];
    beginSend.call(this);
  }
}

function onHttp2OutgoingFinish() {
  this[kFinished] = true;
  this[kStream].end();
  var beginSend = this[kBeginSend];
  beginSend.call(this);
}

// Represents an outbound HTTP message.
class Http2Outgoing extends Writable {
  constructor(stream, options) {
    super(initHttp2OutgoingOptions(options));
    this[kStream] = stream;
    this[kFinished] = false;
    this[kHeaders] = [];
    this[kHeadersSent] = false;
    this.on('pipe', onHttp2OutgoingPipe);
    this.on('finish', onHttp2OutgoingFinish);
  }

  get stream() {
    return this[kStream];
  }

  get finished() {
    var stream = this[kStream];
    return stream === undefined || this[kFinished];
  }

  get headersSent() {
    return this[kHeadersSent];
  }

  setHeader(name, value, noindex) {
    var stream = this[kStream];
    if (this[kHeadersSent])
      throw new Error(
        'Cannot set headers after the HTTP message has been sent');
    if (!stream)
      throw new Error('Cannot set header on a closed stream');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP/1 headers are not permitted');
    if (value === undefined || value === null) {
      throw new TypeError('Value must not be undefined or null');
    }
    this[kHeaders].push([name, value, Boolean(noindex)]);
    return this;
  }

  setTrailer(name, value, noindex) {
    var stream = this[kStream];
    if (this[kHeadersSent])
      throw new Error(
        'Cannot set trailers after the HTTP message has been sent');
    if (!stream)
      throw new Error('Cannot set trailer on a closed stream');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP/1 headers are not permitted');
    if (value === undefined || value === null) {
      throw new TypeError('Value must not be undefined or null');
    }
    stream.addTrailer(name, value, Boolean(noindex));
    return this;
  }

  addHeaders(headers) {
    var keys;
    if (headers) {
      keys = Object.keys(headers);
      for (var i = 0; i < keys.length; i++)
        this.setHeader(keys[i], headers[keys[i]]);
    }
    return this;
  }

  addTrailers(headers) {
    if (!headers) return;
    var keys = Object.keys(headers);
    for (var i = 0; i < keys.length; i++)
      this.setTrailer(keys[i], headers[keys[i]]);
    return this;
  }

  // Set the timeout on the underlying Http2Stream object
  setTimeout(msecs, callback) {
    var stream = this[kStream];
    if (!stream) return;
    stream.setTimeout(msecs, callback);
    return this;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string')
      chunk = Buffer.from(chunk, encoding);
    var stream = this[kStream];
    var beginSend = this[kBeginSend];
    if (stream) {
      beginSend.call(this);
      stream.write(chunk, encoding, callback);
    } else {
      this[kFinished] = true;
      callback();
    }
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      var implicitHeaders = this[kImplicitHeaders];
      if (typeof implicitHeaders === 'function') {
        implicitHeaders.call(this);
      }
      this[kHeadersSent] = true;
      var stream = this[kStream];
      stream.respond(this[kHeaders]);
    }
  }
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
    var stream = this[kStream];
    if (!stream) return false;
    var session = stream[kSession];
    return session.remoteSettings.enablePush;
  }

  writeContinue() {
    var stream = this[kStream];
    if (stream) {
      stream.sendContinue();
    }
  }

  // TODO(jasnell): It would be useful to have a variation on writeHead
  // that causes the Writable side to close automatically in the case
  // where there is no data to send. This would allow us to optimize
  // the HTTP/2 frames by only sending the response HEADERS frame and
  // no DATA frames. Otherwise, the current API would result in have to
  // send at least one possibly empty DATA frame every time...
  writeHead(statusCode, headers) {
    if (typeof statusCode === 'object') {
      headers = statusCode;
      statusCode = constants.HTTP_STATUS_OK;
    }
    this.statusCode = statusCode || constants.HTTP_STATUS_OK;
    this.addHeaders(headers);
    return this;
  }

  createPushResponse() {
    var beginSend = this[kBeginSend];
    if (!this.pushSupported)
      return;
    if (!this[kHeadersSent]) {
      beginSend.call(this);
    }
    return new Http2PushResponse(this);
  }

  [kImplicitHeaders]() {
    // Set implicit headers.. will be called by [kBeginSend]()
    var headers = this[kHeaders];
    if (this.sendDate)
      headers.unshift(['date', utcDate()]);
    headers.unshift([constants.HTTP2_HEADER_STATUS, this[kStatusCode]]);
  }
}

// Http2PushResponse objects are used to prepare push streams.
// TODO(jasnell): The API on this is still largely undetermined.
class Http2PushResponse extends EventEmitter {
  constructor(response) {
    super();
    this[kResponse] = response;
    var headers = Object.create(null);
    var stream = response[kStream];
    this[kHeaders] = headers;
    headers[constants.HTTP2_HEADER_METHOD] = 'GET';
    headers[constants.HTTP2_HEADER_AUTHORITY] =
      stream[kRequest].authority;
    headers[constants.HTTP2_HEADER_SCHEME] =
      stream[kRequest].scheme;
  }

  get path() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_PATH];
  }

  set path(val) {
    var headers = this[kHeaders];
    headers[constants.HTTP2_HEADER_PATH] = String(val);
  }

  get method() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_METHOD];
  }

  set method(val) {
    var headers = this[kHeaders];
    headers[constants.HTTP2_HEADER_METHOD] = String(val);
  }

  get authority() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_AUTHORITY];
  }

  set authority(val) {
    var headers = this[kHeaders];
    headers[constants.HTTP2_HEADER_AUTHORITY] = String(val);
  }

  get scheme() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_SCHEME];
  }

  set scheme(val) {
    var headers = this[kHeaders];
    headers[constants.HTTP2_HEADER_SCHEME] = String(val);
  }

  get headers() {
    return this[kHeaders];
  }

  push(callback) {
    if (typeof callback !== 'function')
      throw new TypeError('callback must be a function');
    var res = this[kResponse];
    var parent = res[kStream];
    var headers = this[kHeaders];
    var ret = parent.sendPushPromise(headers);
    if (ret) {
      var id = ret.getId();
      var stream = new Http2Stream(parent[kSession], id, {});
      var session = parent[kSession];
      stream._handle = ret;
      session[kStreams].set(id, stream);

      stream.readable = false;
      var request =
          stream[kRequest] =
              new Http2ServerRequest(stream, headers);
      var response =
          stream[kResponse] =
              new Http2ServerResponse(stream, res[kOptions]);
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

// Converts an object into an http2.Http2Headers object.
// The Http2Headers object maintains an internal array
// of nghttp2_nv objects that contain a copy of the
// header value pairs as an std::vector. To avoid
// that vector having to copy and reallocate, we count
// the number of expected items up front (it's less
// expensive to count than it is to reallocate).
function mapToHeaders(map) {
  var keys = Object.keys(map);
  var size = keys.length;
  for (var i = 0; i < keys.length; i++) {
    if (Array.isArray(keys[i])) {
      size += keys[i].length - 1;
    }
  }
  var ret = new http2.Http2Headers(size);

  for (i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = map[key];
    if (Array.isArray(value) && value.length > 0) {
      for (var k = 0; k < value.length; k++) {
        ret.add(key, String(value[k]));
      }
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
  var needPause = 0 > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}

function sessionOnStreamClose(stream, code) {
  var request = stream[kRequest];
  var response = stream[kResponse];
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
  setImmediate(maybeDestroyStream, stream);
}

function sessionOnError(error) {
  var session = this;
  var server = session[kServer];
  var socket = session[kSocket];

  if (server.listenerCount('sessionError') > 0) {
    server.emit('sessionError', error);
    return;
  }
  socket.destroy(error);
}

function socketOnTimeout() {
  var socket = this;
  var server = socket[kServer];

  if (!server.emit('timeout', this)) {
    // Session timed out, attempt a graceful exit
    server[kSession].gracefulTerminate(this.destroy.bind(this));
  }
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
  var finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
  var server = this[kServer];
  var options = server[kOptions];
  var request;
  var response;
  switch (category) {
    case constants.NGHTTP2_HCAT_REQUEST:
      request = stream[kRequest] =
          new Http2ServerRequest(stream, headers,
                                 options.defaultIncomingOptions);
      response = stream[kResponse] =
          new Http2ServerResponse(stream,
                                  options.defaultOutgoingOptions);
      if (finished)
        request[kFinished] = true;

      if (headers.expect) {
        if (/^100-continue$/i.test(headers.expect)) {
          if (server.listenerCount('checkContinue') > 0) {
            request[kInFlight] = true;
            server.emit('checkContinue', request, response);
            request[kInFlight] = undefined;
            break;
          }
          response.writeContinue();
          // fallthrough
        } else {
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
      if (headers[constants.HTTP2_HEADER_METHOD] === 'CONNECT') {
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
        stream.protocolError();
        return;
      }
      request = stream[kRequest];
      request[kTrailers] = headers;
      break;
    default:
      stream.protocolError();
  }
}

function connectionListener(socket) {
  // Turn off the Nagle's for this socket...
  // highly recommended for http/2 implementations
  // TODO(jasnell): May want to make this a configuration option?
  socket.setNoDelay();
  var options = this[kOptions];

  // Create the Http2Session instance that is unique to this socket.
  var session = createServerSession(options, socket);
  session[kServer] = this;
  socket[kServer] = this;
  this[kSession] = session;

  session.on('error', sessionOnError);

  // Disable TLS Negotiation on this socket. The HTTP/2 allows renegotiation to
  // happen up until the initial HTTP/2 session bootstrap. After that, it is
  // forbidden. Let's just turn it off entirely.
  if (typeof socket.disableRenegotiation === 'function')
    socket.disableRenegotiation();

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', socketOnTimeout);

  // Destroy the session if the socket is destroyed
  var destroySocket = socket.destroy;
  socket.destroy = function(error) {
    session.removeAllListeners();
    socket.removeAllListeners();
    freeSession(session[kHandle]);
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

function onErrorSecureServerSession(err, conn) {
  if (!this.emit('clientError', err, conn))
    conn.destroy(err);
}

class Http2SecureServerSession extends TLSServer {
  constructor(options, requestListener) {
    super(initializeTLSOptions(options), connectionListener);
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
  var finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
  var request = stream[kRequest];
  var response;
  switch (category) {
    case constants.NGHTTP2_HCAT_RESPONSE:
      response = new Http2ClientResponse(stream, headers, {});
      stream[kResponse] = response;
      request.emit('response', response);
      break;
    case constants.NGHTTP2_HCAT_HEADERS:
      if (!finished) {
        stream.protocolError();
        return;
      }
      response = stream[kResponse];
      response[kTrailers] = headers;
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
  var request = stream[kRequest];
  var response = stream[kResponse];
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
  setImmediate(maybeDestroyStream, stream);
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
    var socket = acquireSocket(options, () => {
      this[kSocket] = socket;

      var session = this[kSession] = createClientSession(options, socket);
      // TODO remove this
      socket.once('error', console.log);
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
    var stream = new Http2Stream(this[kSession], -1, options);
    var req = new Http2ClientRequest(stream,
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
    var headers = this[kHeaders] = Object.create(null);

    headers[constants.HTTP2_HEADER_SCHEME] =
      options.protocol.slice(0, options.protocol.length - 1);
    headers[constants.HTTP2_HEADER_METHOD] = options.method;
    headers[constants.HTTP2_HEADER_AUTHORITY] = authority;
    headers[constants.HTTP2_HEADER_PATH] = options.pathname;

    if (typeof callback === 'function')
      this.once('response', callback);
  }

  setHeader(name, value) {
    name = String(name).toLowerCase().trim();
    var headers = this[kHeaders];
    var existing = headers[name];
    if (existing) {
      if (Array.isArray(existing)) {
        existing.push(String(value));
      } else {
        headers[name] = [existing, value];
      }
    } else {
      headers[name] = value;
    }
  }

  setTrailer(name, value) {
    var trailers = this[kTrailers];
    if (!trailers)
      trailers = this[kTrailers] = Object.create(null);
    name = String(name).toLowerCase().trim();
    var existing = trailers[name];
    if (existing) {
      if (Array.isArray(existing)) {
        existing.push(String(value));
      } else {
        trailers[name] = [existing, value];
      }
    } else {
      trailers[name] = value;
    }
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      var stream = this[kStream];
      var session = stream[kSession];
      var implicitHeaders = this[kImplicitHeaders];
      if (typeof implicitHeaders === 'function')
        implicitHeaders.call(this);
      var _handle = session.request(mapToHeaders(this[kHeaders]), true);
      if (_handle instanceof http2.Http2Stream) {
        this[kId] = _handle.getId();
        stream.once('handle', addTrailers);
        stream._handle = _handle;
      }
    }
  }

  end() {
    super.end();
  }
}

function addTrailers() {
  var request = this[kRequest];
  var trailers = request[kTrailers];
  if (trailers) {
    // key is coerced on a string on set
    for (var key in trailers) {
      var value = trailers[key];
      if (Array.isArray(value) && value.length > 0) {
        for (var i = 0; i < value.length; i++)
          this.addTrailer(key, String(value[i]));
      } else {
        this.addTrailer(key, String(value));
      }
    }
  }
}

class Http2ClientResponse extends Http2Incoming {
  constructor(stream, headers, options) {
    super(stream, headers, options);
  }

  get status() {
    var headers = this[kHeaders];
    return headers[constants.HTTP2_HEADER_STATUS] | 0;
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
