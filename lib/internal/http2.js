'use strict';

const http2 = process.binding('http2');
const util = require('util');
const debug = util.debuglog('http2');
const Buffer = require('buffer').Buffer;
const assert = require('assert');
const EventEmitter = require('events');
const internalHttp = require('internal/http');
const TLSServer = require('tls').Server;
const NETServer = require('net').Server;
const stream = require('stream');
const Writable = stream.Writable;
const PassThrough = stream.PassThrough;
const constants = http2.constants;
const utcDate = internalHttp.utcDate;

const kOptions = Symbol('options');
const kHandle = Symbol('handle');
const kType = Symbol('type');
const kStream = Symbol('stream');
const kHeaders = Symbol('headers');
const kHeadersSent = Symbol('headers-sent');
const kTrailersSent = Symbol('trailers-sent');
const kSession = Symbol('session');
const kOutgoingData = Symbol('outgoing-data');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kFinished = Symbol('finished');
const kSocket = Symbol('socket');
const kTrailers = Symbol('trailers');
const kChunks = Symbol('chunks');
const kProvider = Symbol('provider');
const kPaused = Symbol('paused');
const kResume = Symbol('resume');
const kBeginSend = Symbol('begin-send');
const kEndStream = Symbol('end-stream');
const kHasTrailers = Symbol('has-trailers');
const kExpectContinue = Symbol('expect-continue');
const kResponseFlags = Symbol('response-flags');
const kResponseFlag_SendDate = 0x1;

const kDefaultSocketTimeout = 2 * 60 * 1000;

// The process.binding('http2').Http2Session object will
// emit events as callbacks. To allow this to happen,
// it has to inherit from EventEmitter.
util.inherits(http2.Http2Session, EventEmitter);

// If rv (the return value from an internal nghttp2 method) is
// negative, then the value indicates an error condition. In
// such cases, create an appropriate error object and emit it
// on emitter in the next tick.
function checkSuccessOrEmitError(emitter, rv, message) {
  if (rv < 0) {
    message = message || `HTTP2Error: ${http2.nghttp2ErrorString(rv)}`;
    debug(`Emitting Error: ${message}`);
    const err = new Error(message);
    Error.captureStackTrace(checkSuccessOrEmitError);
    err.code = rv;
    err.errno = rv;
    process.nextTick(() => emitter.emit('error', err));
    return false;
  }
  return true;
}

Object.defineProperty(exports, 'constants', {
  configurable: false,
  enumerable: true,
  value: constants
});

// Effectively  a wrapper for process.binding('http').Http2Session
// that ensures that events are emitted in nextTick. Also performs
// type checking and other tasks that are easier/better done in
// JavaScript than in the native code.
// TODO(jasnell): It should be possible to do this without creating
// a wrapper object. Explore opportunities to improve this.
class Http2Session extends EventEmitter {
  constructor(type) {
    debug(`Creating new Http2Session [Type ${type}]`);
    super();
    type |= 0;
    if (type !== constants.SESSION_TYPE_SERVER &&
        type !== constants.SESSION_TYPE_CLIENT) {
      throw new TypeError('Invalid session type');
    }

    const session = new http2.Http2Session(type);
    EventEmitter.call(session);

    session.on('canClose', () => {
      debug('Http2Session::canClose');
    });

    session.on('error', (error) => {
      debug(`Http2Session::error [${error.message}]`);
      process.nextTick(() => this.emit('error', error));
    });

    session.on('send', (buffer) => {
      debug(`Http2Session::send [${buffer.length}]`);
      process.nextTick(() => this.emit('send', buffer));
    });

    session.on('begin-headers', (stream, category) => {
      debug(`Http2Session::begin-headers [${stream.id}, ${category}]`);
      if (!stream.session) {
        debug('Http2Session::begin-headers [New Stream]');
        Object.defineProperty(stream, 'session', {
          enumerable: true,
          configurable: true,
          value: this
        });
      }
      process.nextTick(() => this.emit('begin-headers', stream, category));
    });

    session.on('header', (stream, name, value) => {
      debug(`Http2Session::header [${stream.id}, "${name}": "${value}""]`);
      process.nextTick(() => this.emit('header', stream, name, value));
    });

    session.on('headers-complete', (stream, flags) => {
      const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
      debug(
        `Http2Session::headers-complete [${stream.id}, ${finished}, ${flags}]`);
      process.nextTick(() => this.emit('headers-complete', stream, finished));
    });

    session.on('stream-close', (stream, code) => {
      debug(`Http2Session::stream-close [${stream.id}, ${code}]`);
      process.nextTick(() => this.emit('stream-close', stream, code));
    });

    session.on('data-chunk', (stream, flags, data) => {
      debug(
        `Http2Session::data-chunk [${stream.id}, ${flags}, ${data.length}]`);
      // streamID is the numeric stream ID the data belongs to
      // flags is the data flags
      // data is the Buffer containing the data
      process.nextTick(() => this.emit('data-chunk', stream, data));
    });

    session.on('data', (stream, flags, length, padding) => {
      // stream is the Http2Stream object the data belongs to
      // flags is the frame flags
      // length is the amount of data
      // padding is the amount of padding in the data
      const finished = Boolean(flags & constants.NGHTTP2_DATA_FLAG_EOF ||
                               flags & constants.NGHTTP2_FLAG_END_STREAM);
      debug(
        `Http2Session::data [${stream.id}, ${flags}, ${length}, ${padding}]`);
      process.nextTick(() => this.emit('data-end', stream, finished, padding));
    });

    session.on('frame-sent', (streamID, type, flags) => {
      // streamID is the stream the frame belongs to
      // type is the frame type
      // flags are the frame flags
      debug(`Http2Session::frame-sent [${streamID}, ${type}, ${flags}]`);
      process.nextTick(() => this.emit('frame-sent', streamID, type, flags));
    });

    session.on('goaway', (code, lastStreamID, data) => {
      // code is the error code
      // lastStreamID is the last processed stream ID
      // data is the optional additional application data
      debug(`Http2Session::goaway [${code}, ${lastStreamID}, ${data}]`);
      process.nextTick(() => this.emit('goaway', code, lastStreamID, data));
    });

    session.on('rst-stream', (stream, code) => {
      // stream is the stream identifier. by this time, the underlying
      // Http2Stream object has been unreferenced and the nghttp2_stream
      // has been destroyed. The only reference we have left is the id
      // code is the RstStream code
      debug(`Http2Session::rst-stream [${stream}, ${code}]`);
      process.nextTick(() => this.emit('rst-stream', stream, code));
    });

    this[kHandle] = session;
  }

  get type() {
    if (this._handle)
      return this._handle.type;
  }

  get root() {
    if (this._handle)
      return this._handle.root;
  }

  get localWindowSize() {
    if (this._handle)
      return this._handle.localWindowSize;
  }

  set localWindowSize(val) {
    if (this._handle)
      this._handle.localWindowSize = val;
  }

  get inflateDynamicTableSize() {
    if (this._handle)
      return this._handle.inflateDynamicTableSize;
  }

  get deflateDynamicTableSize() {
    if (this._handle)
      return this._handle.deflateDynamicTableSize;
  }

  get remoteWindowSize() {
    if (this._handle)
      return this._handle.remoteWindowSize;
  }

  get outboundQueueSize() {
    if (this._handle)
      return this._handle.outboundQueueSize;
  }

  get lastProcStreamID() {
    if (this._handle)
      return this._handle.lastProcStreamID;
  }

  get effectiveRecvDataLength() {
    if (this._handle)
      return this._handle.effectiveRecvDataLength;
  }

  get effectiveLocalWindowSize() {
    if (this._handle)
      return this._handle.effectiveLocalWindowSize;
  }

  get nextStreamID() {
    if (this._handle)
      return this._handle.nextStreamID;
  }

  set nextStreamID(id) {
    if (this._handle)
      this._handle.nextStreamID = id;
  }

  get wantRead() {
    if (this._handle)
      return this._handle.wantRead;
  }

  get wantWrite() {
    if (this._handle)
      return this._handle.wantWrite;
  }

  get localSettings() {
    if (this._handle)
      return this._handle.localSettings;
  }

  set localSettings(settings) {
    if (!(settings instanceof http2.Http2Settings))
      throw new TypeError('settings must be an instance of Http2Settings');
    if (this._handle) {
      this._handle.localSettings = settings;
      this.sendData();
    }
  }

  get remoteSettings() {
    if (this._handle)
      return this._handle.remoteSettings;
  }

  get _handle() {
    return this[kHandle];
  }

  destroy() {
    debug('Http2Session::destroy');
    if (this._handle) {
      this._handle.destroy();
      this[kHandle] = null;
    }
  }

  terminate(code) {
    code |= 0;
    debug(`Http2Session::terminate [${code}]`);
    if (this._handle) {
      checkSuccessOrEmitError(this, this._handle.terminate(code));
    }
  }

  gracefulTerminate(callback) {
    if (typeof callback !== 'function')
      throw new TypeError('callback must be a function');
    debug('Http2Session::gracefulTerminate');
    if (this._handle) {
      // Begin graceful termination process. See:
      // https://nghttp2.org/documentation/nghttp2_submit_shutdown_notice.html
      // For detail. This process results in sending two GOAWAY frames to the
      // client. The second one is the actual GOAWAY that will terminate the
      // session. The second terminate and the passed in callback are invoked
      // on nextTick (TODO(jasnell): setImmediate might be better)).
      if (checkSuccessOrEmitError(this, this._handle.gracefulTerminate())) {
        process.nextTick(() => {
          this.terminate(constants.NGHTTP2_NO_ERROR);
          callback();
        });
      }
    }
  }

  /**
   * When a chunk of data is received by the Socket, the receiveData
   * method passes that data on to the underlying nghttp2_session. The
   * data argument must be a Buffer.
   **/
  receiveData(data) {
    if (!Buffer.isBuffer(data))
      throw new TypeError('data must be a Buffer');
    debug(`Http2Session::receiveData [${data.length}]`);
    if (this._handle)
      checkSuccessOrEmitError(this, this._handle.receiveData(data));
  }

  /**
   * Prompts the nghttp2_session to serialize and send (via callbacks) any
   * http/2 frames currently in it's outgoing queue.
   **/
  sendData() {
    debug('Http2Session::sendData');
    if (this._handle)
      checkSuccessOrEmitError(this, this._handle.sendData());
  }

  createIdleStream(stream, parent, weight, exclusive) {
    // TODO(jasnell): Implement this
    // This is used to prepare a stream for use... for instance, when using
    // push streams. It's not sure if we're really need this but we'll see
  }

}

class Headers extends Map {
  constructor(type) {
    super();
    this[kType] = type;
  }

  set(name, value) {
    if (!this.has(name))
      super.set(name, value);
    else {
      const existing = this.get(name);
      if (Array.isArray(existing))
        existing.push(value);
      else
        super.set(name, [existing, value]);
    }
  }
}


// Represents an incoming HTTP/2 message.
// TODO(jasnell): This should not be a PassThrough. It needs to be
// just a Readable so that the Writable methods are not accessible
// to users. For now, this is the easiest thing to just get it working.
class Http2Incoming extends PassThrough {
  constructor(stream, headers, socket) {
    super({});
    this[kStream] = stream;
    this[kSocket] = socket;
    this[kHeaders] = headers;
    this[kFinished] = false;
  }

  get stream() {
    return this[kStream];
  }

  get headers() {
    return this[kHeaders];
  }

  get socket() {
    return this[kSocket];
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

  setTimeout(msecs, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  }

}


class Http2ServerRequest extends Http2Incoming {
  constructor(stream, headers, socket) {
    super(stream, headers, socket);
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


// class Http2ClientResponse extends Http2Incoming {
//   constructor(stream, headers, socket) {
//     super(stream, headers, socket);
//   }

//   get status() {
//     return this.headers.get(constants.HTTP2_HEADER_STATUS) | 0;
//   }
// }

class Http2Outgoing extends Writable {
  constructor(stream, socket) {
    super({});
    this[kStream] = stream;
    this[kSocket] = socket;
    this[kFinished] = false;
    this[kHeaders] = new Map();
    this[kTrailers] = new Map();
    this[kHeadersSent] = false;
    this[kTrailersSent] = false;
    this[kChunks] = [];

    debug(`Http2Outgoing::constructor [${stream.id}]`);
    // The Http2DataProvider objects wraps a nghttp2_data_provider internally
    // that supplies outbound data to the stream. The Http2ServerResponse
    // object is a Writable stream that stores the chunks of written data into
    // a simple this[kchunks] array (currently). The Http2DataProvider object
    // simply harvests the chunks from that array. TODO: Make this more
    // efficient
    this[kProvider] = new http2.Http2DataProvider(stream);
    // This callback is invoked from node_http2.cc while the outgoing data
    // frame is being processed. The buffer argument is a pre-allocated, fixed
    // sized buffer to read the data into. flags is an object that supports
    // two properties used to indicate if the data has concluded or not.
    // The callback must return the actual number of bytes written up to but
    // not exceeding buffer.length
    this[kProvider]._read = (buffer, flags) => {
      debug(`Http2DataProvider::_read [${stream.id}, ${buffer.length}]`);
      const chunks = this[kChunks];
      if (chunks.length === 0) {
        if (!this[kFinished]) {
          // The end() method has not yet been called but there's
          // currently no data in the queue, defer the data frame
          // until additional data is written.
          this[kPaused] = true;
          debug(`Http2DataProvider::_read [${stream.id}, DEFERRED]`);
          return constants.NGHTTP2_ERR_DEFERRED;
        } else {
          // There is no more data in the queue and end() has
          // been called. Set the flags. Note: this will cause
          // an extra empty data frame to be sent. See below.
          this[kEndStream](flags);
          debug(`Http2DataProvider::_read [${stream.id}, NO MORE DATA]`);
          return 0;
        }
      } else {
        if (this[kFinished]) {
          // Finish has been called so there will
          // not be any more data queued. Set the
          // flags to avoid another data frame write.
          // Assuming that finish has been called before
          // all of the data could be harvested, this ensures
          // that we do not have to send an extra empty data
          // frame to signal the end of the data. However,
          // it's not always possible to know this in advance.
          debug(`Http2DataProvider::_read [${stream.id}, CALL kEndStream()]`);
          this[kEndStream](flags);
        }
        // Consume as much of the currently buffered
        // data as possible per data frame up to buffer.length
        debug(`Http2DataProvider::_read [${stream.id}, COPYING BUFFERS]`);
        const ret = copyBuffers(buffer, chunks);
        debug(`Http2DataProvider::_read [${stream.id}, COPIED ${ret}]`);
        return ret;
      }
    };

    // If this Writable is connected to a pipe, resume any deferred data
    // frames and initiate the response if it hasn't been initiated already.
    this.on('pipe', () => {
      debug(`Http2Outgoing::pipe [${stream.id}]`);
      this[kResume]();
      this[kBeginSend]();
    });
  }

  get stream() {
    return this[kStream];
  }

  get socket() {
    return this[kSocket];
  }

  get finished() {
    return this[kFinished];
  }

  get headersSent() {
    return this[kHeadersSent];
  }

  get trailersSent() {
    return this[kTrailersSent];
  }

  setHeader(name, value) {
    debug(
      `Http2Outgoing::setHeader [${this.stream.id}, "${name}": "${value}"]`);
    // TODO(jasnell): Enable the following check later
    // if (this.headersSent)
    //   throw new Error('Cannot set headers after they are sent');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP headers are not permitted');
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      this[kHeaders].delete(name);
      return this;
    }

    if (Array.isArray(value)) {
      this[kHeaders].set(name, value.map((i) => String(i)));
    } else {
      this[kHeaders].set(name, String(value));
    }
    return this;
  }

  setTrailer(name, value) {
    debug(
      `Http2Outgoing::setTrailer [${this.stream.id}, "${name}": "${value}"]`);
    if (this.trailersSent)
      throw new Error('Cannot set trailers after they are sent');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP headers are not permitted');
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      this[kTrailers].delete(name);
      return this;
    }

    if (Array.isArray(value)) {
      this[kTrailers].set(name, value.map((i) => String(i)));
    } else {
      this[kTrailers].set(name, String(value));
    }
    return this;
  }

  addHeaders(headers) {
    for (const key of headers)
      this.setHeader(key, headers[key]);
    return this;
  }

  addTrailers(headers) {
    for (const key of headers)
      this.setTrailer(key, headers[key]);
    return this;
  }

  getHeader(name) {
    return this[kHeaders].get(name);
  }

  getTrailer(name) {
    return this[kTrailers].get(name);
  }

  removeHeader(name) {
    debug(`Http2Outgoing::removeHeader [${this.stream.id}, "${name}"]`);
    if (this.headersSent)
      throw new Error('Cannot remove headers after they are sent');
    this[kHeaders].delete(name);
    return this;
  }

  removeTrailer(name) {
    debug(`Http2Outgoing::removeTrailer [${this.stream.id}, "${name}"]`);
    if (this.trailersSent)
      throw new Error('Cannot remove trailers after they are sent');
    this[kTrailers].delete(name);
    return this;
  }

  setTimeout(msecs, callback) {
    if (callback)
      this.on('timeout', callback);
    if (!this.socket) {
      this.once('socket', (socket) => socket.setTimeout(msecs));
    } else {
      this.socket.setTimeout(msecs);
    }
    return this;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string')
      chunk = Buffer.from(chunk, encoding);
    debug(`Http2Outgoing::_write [${this.stream.id}, ${chunk.length}]`);
    const state = this.stream.state;
    if (!this.socket.destroyed &&
        state !== constants.NGHTTP2_STREAM_STATE_CLOSED &&
        state !== constants.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
      debug(`Http2Outgoing::_write WRITING [${this.stream.id}]`);
      if (chunk.length > 0)
        this[kChunks].push(chunk);
      this[kResume]();
      this[kBeginSend]();
      this.stream.session.sendData();
    } else {
      debug('Http2Outgoing::_write NOT WRITING, STREAM CLOSED ' +
            `[${this.stream.id}]`);
      if (!this[kFinished]) {
        this[kFinished] = true;
        super.end();
      }
    }
    callback();
  }

  end(data, encoding, callback) {
    debug(`Http2Outgoing::end [${this.stream.id}]`);
    this[kFinished] = true;
    const state = this.stream.state;
    if (!this.socket.destroyed &&
        state !== constants.NGHTTP2_STREAM_STATE_CLOSED &&
        state !== constants.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
      super.end(data, encoding, callback);
      this[kResume]();
      this[kBeginSend]();
    }
  }

  [kBeginSend]() {
    debug(`Http2Outgoing::kBeginSend [${this.stream.id}]`);
    if (!this[kHeadersSent]) {
      debug(`Http2Outgoing::kBeginSend [${this.stream.id}, SENDING HEADERS]`);
      this[kHeadersSent] = true;
      const stream = this.stream;
      checkSuccessOrEmitError(
          stream.session,
          stream.respond(mapToHeaders(this[kHeaders]), this[kProvider]));
    }
  }

  [kResume]() {
    debug(`Http2Outgoing::kResume [${this.stream.id}]`);
    if (this[kPaused]) {
      debug(`Http2Outgoing::kBeginSend [${this.stream.id}, RESUMING]`);
      this[kPaused] = false;
      const stream = this.stream;
      const session = stream.session;
      checkSuccessOrEmitError(session, stream.resumeData());
      session.sendData();
    }
  }

  [kEndStream](flags) {
    debug(`Http2Outgoing::kEndStream [${this.stream.id}]`);
    this[kTrailersSent] = true;
    flags[constants.FLAG_ENDDATA] = true;
    // TODO(jasnell): kHasTrailers is currently not set anywhere
    if (this[kHasTrailers]) {
      debug(`Http2Outgoing::kEndStream [${this.stream.id}, HAS TRAILERS]`);
      flags[constants.FLAG_NOENDSTREAM] = true;
      const stream = this.stream;
      checkSuccessOrEmitError(
          stream.session,
          stream.sendTrailers(mapToHeaders(this[kTrailers])));
    } else {
      flags[constants.FLAG_ENDSTREAM] = true;
    }
  }
}


class Http2ServerResponse extends Http2Outgoing {
  constructor(stream, socket) {
    super(stream, socket);
    this[kResponseFlags] = kResponseFlag_SendDate;
    this.statusCode = constants.HTTP_STATUS_OK;
  }

  get sendDate() {
    return (this[kResponseFlags] & kResponseFlag_SendDate) ===
           kResponseFlag_SendDate;
  }

  set sendDate(bool) {
    bool = Boolean(bool);
    if (bool) this[kResponseFlags] |= kResponseFlag_SendDate;
    else this[kResponseFlags] &= ~kResponseFlag_SendDate;
  }

  get statusCode() {
    this[kHeaders].get(constants.HTTP2_HEADER_STATUS);
  }

  set statusCode(code) {
    code |= 0;
    if (code === constants.HTTP_STATUS_SWITCHING_PROTOCOLS)
      throw new RangeError(
        `Status code ${constants.HTTP_STATUS_SWITCHING_PROTOCOLS}` +
        ' is not supported by HTTP/2');
    if (code < 100 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    this[kHeaders].set(constants.HTTP2_HEADER_STATUS, code);
  }

  writeContinue() {
    checkSuccessOrEmitError(this[kSession], this[kStream].sendContinue());
  }

  writeHead(statusCode, headers) {
    this.statusCode = statusCode || constants.HTTP_STATUS_OK;
    if (headers) {
      const keys = Object.keys(headers);
      for (var key of keys)
        this.setHeader(key, headers[key]);
    }
    return this;
  }

  createPushResponse() {
    this[kResume]();
    this[kBeginSend]();
    return new Http2PushResponse(this);
  }

  [kBeginSend]() {
    if (!this[kHeadersSent] && this.sendDate)
      this.setHeader('date', utcDate());
    super[kBeginSend]();
  }
}

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
    debug(`Http2PushResponse::push [${parent.id}, ${this[kHeaders]}]`);
    const ret = parent.sendPushPromise(mapToHeaders(this[kHeaders]));
    if (!isNaN(ret)) {
      // If the return value is a number, it is an error
      checkSuccessOrEmitError(parent.session, ret);
      return;
    }
    debug(`Http2PushResponse::push [${parent.id}, CREATED ${ret.id}]`);
    Object.defineProperty(ret, 'session', {
      enumerable: true,
      configurable: false,
      value: parent.session
    });
    ret[kRequest] =
        new Http2ServerRequest(ret, this[kHeaders], this[kResponse].socket);
    ret[kResponse] = new Http2ServerResponse(ret, this[kResponse].socket);
    ret[kRequest][kFinished] = true;
    ret[kRequest].end();
    callback(ret[kRequest], ret[kResponse]);
  }
}

// TODO(jasnell): improve performance on these
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
// TODO(jasnell): improve performance on this.
function isIllegalConnectionSpecificHeader(name, value) {
  if (/^(?:connection|upgrade|http2-settings)$/i.test(name))
    return true;
  if (/^te$/i.test(name) && !/^trailers$/i.test(value))
    return true;
  return false;
}

// Converts a Map objects to an array of Http2Header objects for serialization.
// TODO(jasnell): need to determine if this is the best approach. It may not
// performant enough to represent each header pair as a separate object like
// this. The reason to do so currently is because nghttp2 represents each as a
// separate struct, and for each instance, a decision must be made with regards
// to how the individual header is handled with regards to HPACK.
function mapToHeaders(map) {
  const ret = [];
  if (!(map instanceof Map))
    return ret;
  for (const v of map) {
    const key = v[0];
    const value = v[1];
    if (Array.isArray(value)) {
      for (const item of value)
        ret.push(new http2.Http2Header(key, String(item)));
    } else {
      ret.push(new http2.Http2Header(key, String(value)));
    }
  }
  return ret;
}


// class Http2ClientRequest extends Http2Outgoing {
//   constructor(stream, socket) {
//     super(stream, socket);
//   }
// }

// Copies data from the given chunks to the buffer, up to buffer.length,
// Removes the written data from chunks. Returns the total number of
// bytes copied. This method is called when chunking data into individual
// HTTP/2 data frames. The buffer represents the total amount of data that
// can be included in the frame, chunks is the data pending to write to
// those data frames.
// TODO(jasnell): Improve performance on this
function copyBuffers(buffer, chunks, offset) {
  if (chunks.length === 0) return 0;
  var current = chunks[0];
  offset |= 0;
  if (current.length <= buffer.length - offset) {
    var copied = current.copy(buffer, offset, 0);
    chunks.shift();
    if (chunks.length > 0)
      copied += copyBuffers(buffer, chunks, offset + copied);
    return copied;
  } else {
    const len = buffer.length - offset;
    current.copy(buffer, offset, 0, len);
    chunks[0] = current.slice(len);
    return len;
  }
}

// The HTTP/2 Server Connection Listener. This is used for both the TLS and
// non-TLS variants. For every socket, there is exactly one Http2Session.
// TODO(jasnell): Currently, a new Http2Session instance is created for every
// socket. We should investigate whether it would be possible to use pooling
// like we do with http-parser instances currently. It might not be possible
// due to long term connection state management, but it's worth investigating
// for performance.
function connectionListener(socket) {
  debug('New HTTP2 Server Connection');
  const options = this[kOptions];

  // Create the Http2Session instance that is unique to this socket.
  debug('Creating and associating Http2Session');
  const session =
      socket[kSession] =
        createServerSession(socket, options);
  debug(`Created Http2Session [UID: ${session._handle.uid}]`);

  // `outgoingData` is an approximate amount of bytes queued through all
  // inactive responses. If more data than the high watermark is queued - we
  // need to pause TCP socket/HTTP parser, and wait until the data will be
  // sent to the client.
  socket[kOutgoingData] = 0;
  // TODO(jasnell): Complete this
  // function updateOutgoingData(delta) {
  //   socket[kOutgoingData] += delta;
  //   if (socket._paused &&
  //       socket[kOutgoingData] < socket._writableState.highWaterMark) {
  //     return socketOnDrain(socket);
  //   }
  // }

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', () => {
    debug(`Socket Timeout for Http2Session [UID: ${session._handle.uid}]`);
    if (!this.emit('timeout', socket)) {
      debug('Socket Timeout not handled, destroying socket');
      // Session timed out, attempt a graceful exit
      session.gracefulTerminate(() => socket.destroy());
    }
  });

  // Destroy the session if the socket is destroyed
  const destroySocket = socket.destroy;
  socket.destroy = function(error) {
    if (session._handle) {
      debug(`Destroying socket and Http2Session [UID: ${session._handle.uid}]`);
      session.destroy();
    }
    destroySocket.call(socket, error);
  };

  socket.once('error', (error) => {
    // If the socket experiences an error, there's not much that
    // we're going to be able to do as the error could have a
    // fatal impact on any number of open in-flight requests.
    // In the http/1 implementation, we emit a clientError that
    // gives the user code an opportunity to send a graceful
    // HTTP error response. For here, since there may be any
    // number of open streams, we'll notify the server of the
    // failure allow it to do whatever it will. If no socketError
    // listeners are registered, destroy the socket.
    debug(`Socket::error [UID: ${session._handle.uid}, ${error.message}]`);
    if (!this.emit('socketError', error, socket)) {
      debug('socketError event not handled. destroy socket ' +
            `and Http2Session [UID: ${session._handle.uid}]`);
      socket.destroy(error);
    }
  });
  //socket.on('end', () => {});
  socket.on('data', (data) => {
    // Pass data on to the session, then automatically send any
    // buffered data waiting to be sent.
    assert(Buffer.isBuffer(data));
    debug(`Socket::data [UID: ${session._handle.uid}, ${data.length}]`);
    session.receiveData(data);
    session.sendData();
  });
  socket.on('resume', () => {
    debug(`Socket::resume [UID: ${session._handle.uid}]`);
    if (socket._paused) {
      socket.pause();
      return;
    }
    if (socket._handle && !socket._handle.reading) {
      socket._handle.reading = true;
      socket._handle.readStart();
    }
  });
  socket.on('pause', () => {
    debug(`Socket::pause [UID: ${session._handle.uid}]`);
    if (socket._handle && socket._handle.reading) {
      socket._handle.reading = false;
      socket._handle.readStop();
    }
  });
  socket.on('drain', () => socketOnDrain(socket));

  // Wire the Http2Session events up.
  session.on('send', (data) => {
    if (!socket.destroyed) {
      debug(`Http2Server::send [UID: ${session._handle.uid}, ${data.length}]`);
      socket.write(data);
    }
  });

  session.on('begin-headers', (stream, category) => {
    // Each time this is called, a new block of header pairs
    // is being processed. Create a new headers map to store
    // them in.
    debug('Http2Server::begin-headers [NEW HEADERS MAP]');
    stream[kHeaders] = new Headers(category);
  });
  session.on('header', (stream, name, value) => {
    assert(stream[kHeaders]);
    stream[kHeaders].set(name, value);
  });
  session.on('headers-complete', (stream, finished) => {
    const headers = stream[kHeaders];
    assert(headers);
    // This is a server, so the only header categories supported are
    // NGHTTP2_HCAT_REQUEST and NGHGTTP2_HCAT_HEADERS. Other categories
    // must result in a Protocol error per the spec.
    switch (headers[kType]) {
      case constants.NGHTTP2_HCAT_REQUEST:
        // header blocks in this category represent a new request.
        debug(
          `Http2Server: Initialize new request for Http2Stream [${stream.id}]`);
        assert(!stream[kRequest]);
        stream[kRequest] = new Http2ServerRequest(stream, headers, socket);
        stream[kResponse] = new Http2ServerResponse(stream, socket);
        // finished will be true if the header block included flags to end
        // the stream (such as when sending a GET request). In such cases,
        // mark the kRequest stream finished so no data will be read.
        if (finished) {
          debug(`Http2Server: Request is complete [${stream.id}]`);
          stream[kRequest][kFinished] = true;
          stream[kRequest].end();
        }
        if (headers.has('expect')) {
          debug('Http2Server: Request has expect header');
          // If there is an expect header that contains 100-continue,
          // and the server has a listener for the checkContinue event,
          // emit the checkContinue event instead of the request event.
          // This behavior matches the current http/1 API.
          if (/^100-continue$/i.test(headers.get('expect'))) {
            debug('Http2Server: Request has expect = 100-continue');
            stream[kResponse][kExpectContinue] = true;
            if (this.listenerCount('checkContinue') > 0) {
              debug('Http2Server: Emitting checkContinue');
              process.nextTick(() => {
                this.emit('checkContinue',
                          stream[kRequest],
                          stream[kResponse]);
              });
              break;
            }
            debug('Http2Server: Calling writeContinue()');
            stream[kResponse].writeContinue();
          } else {
            // If there is an expect header that contains anything
            // other than 100-continue, emit the checkExpectation
            // event if there are listeners or automatically return
            // a 417 and end the response. This behavior matches the
            // current http/1 API
            if (this.listenerCount('checkExpectation') > 0) {
              debug('Http2Server: Emitting checkExpectation');
              process.nextTick(() => {
                this.emit('checkExpectation',
                          stream[kRequest],
                          stream[kResponse]);
              });
            } else {
              debug('Http2Server: Return expectation failed HTTP response');
              stream[kResponse].writeHead(
                  constants.HTTP_STATUS_EXPECTATION_FAILED);
              stream[kResponse].end();
            }
            break;
          }
        }
        debug(`Http2Server: Emit request for Http2Stream [${stream.id}]`);
        process.nextTick(() => {
          this.emit('request', stream[kRequest], stream[kResponse]);
        });
        break;
      case constants.NGHTTP2_HCAT_HEADERS:
        if (!finished) {
          // When category === NGHTTP2_HCAT_HEADERS and finished is not
          // null, that means an extra HEADERS frame was sent after
          // the initial HEADERS frame that opened the request, without the
          // end stream flag set. Interstitial headers frames are not permitted
          // in the HTTP semantic binding per the HTTP/2 spec
          checkSuccessOrEmitError(
              session, stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR));
          return;
        }
        // If finished, that means these are trailing headers
        const request = stream[kRequest];
        assert(request);
        debug(`Http2Server: Setting trailers for Http2Stream [${stream.id}]`);
        request[kTrailers] = headers;
        break;
      default:
        debug(`Http2Server: Protocol error for Http2Stream [${stream.id}]`);
        checkSuccessOrEmitError(
            session,
            stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR));
    }
  });

  session.on('data-chunk', (stream, chunk) => {
    const request = stream[kRequest];
    if (!request) {
      const err = new Error('Invalid Http2Session State');
      process.nextTick(() => session.emit('error', err));
      return;
    }
    debug('Http2Server: Data-chunk for Http2Stream ' +
          `[${stream.id}, ${chunk.length}]`);
    // TODO(jasnell): to properly handle padding, we should actually buffer
    // this data and not write it to the request until the data-end event is
    // emitted. See below.
    request.write(chunk);
  });
  session.on('data-end', (stream, finished, padding) => {
    // TODO: How to handle padding???? data-end will be triggered after the
    // completion of each individual data frame. The spec allows each data
    // frame to contain additional padding bytes that must be stripped from
    // the data before passing on to the user. This means that we should not
    // actually pass the data on to the request until data-end and the padding
    // can be stripped. To accomplish this, the data-chunk event and this
    // event need to be modified to buffer the data and strip the padding.
    debug('Http2Server: Complete data frame received for Http2Stream ' +
          `[${stream.id}, ${finished}, ${padding}]`);
    const request = stream[kRequest];
    assert(request);
    if (finished) {
      request[kFinished] = finished;
      request.end();
    }
  });
  session.on('stream-close', (stream, code) => {
    debug(`Http2Server: Http2Stream Closed [${stream.id}, ${code}]`);
    if (stream[kRequest] && !stream[kRequest].finished) {
      debug(`Http2Server::stream-close closing request [${stream.id}]`);
      stream[kRequest].end();
      stream[kRequest][kFinished] = true;
    }
    if (stream[kResponse] & !stream[kResponse].finished) {
      debug(`Http2Server::stream-close closing response [${stream.id}]`);
      stream[kRequest].end();
      stream[kResponse][kFinished] = true;
    }
  });
  session.localSettings = options.settings;
}

function socketOnDrain(socket) {
  debug('Draining socket');
  const needPause = socket[kOutgoingData] > socket._writableState.highWaterMark;
  if (socket._paused && !needPause) {
    socket._paused = false;
    socket.resume();
  }
}

function initializeOptions(options) {
  options = options || {};
  options.allowHalfOpen = true;
  options.settings = options.settings || new http2.Http2Settings();
  if (!(options.settings instanceof http2.Http2Settings)) {
    throw new TypeError(
        'options.settings must be an instance of Http2Settings');
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

class Http2ClientSession {
  constructor(options, callback) {
    this[kOptions] = initializeOptions(options);
    this[kSession] = createClientSession(options);
  }
}

// There are several differences between this and _http_agent. Namely,
// sockets are always assumed to be long lived and always have an associated
// Http2Session.
// class Http2Agent extends EventEmitter {
//   constructor(options) {
//     super();
//     this[kSockets] = new WeakMap();
//     this.on('free', (socket, options) => {});
//   }
// }

function createServerSession(options) {
  return new Http2Session(constants.SESSION_TYPE_SERVER, options);
}

function createClientSession(options) {
  return new Http2Session(constants.SESSION_TYPE_CLIENT, options);
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

function createClient(options, callback) {
  return new Http2ClientSession(options, callback);
}

module.exports.Http2Header = http2.Http2Header;
module.exports.Http2Settings = http2.Http2Settings;
module.exports.createClient = createClient;
module.exports.createServer = createServer;
module.exports.createSecureServer = createSecureServer;
module.exports.createServerSession = createServerSession;
module.exports.createClientSession = createClientSession;
