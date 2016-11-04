'use strict';

const http2 = process.binding('http2');
const util = require('util');
const Buffer = require('buffer').Buffer;
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
const kType = Symbol('type');
const kStream = Symbol('stream');
const kHeaders = Symbol('headers');
const kHeadersSent = Symbol('headers-sent');
const kTrailersSent = Symbol('trailers-sent');
const kSession = Symbol('session');
const kRequest = Symbol('request');
const kResponse = Symbol('response');
const kFinished = Symbol('finished');
const kTrailers = Symbol('trailers');
const kChunks = Symbol('chunks');
const kProvider = Symbol('provider');
const kPaused = Symbol('paused');
const kResume = Symbol('resume');
const kBeginSend = Symbol('begin-send');
const kEndStream = Symbol('end-stream');
const kHasTrailers = Symbol('has-trailers');
const kInFlight = Symbol('in-flight');
const kExpectContinue = Symbol('expect-continue');
const kResponseFlags = Symbol('response-flags');
const kResponseFlag_SendDate = 0x1;

const kDefaultSocketTimeout = 2 * 60 * 1000;
const kRenegTest = /TLS session renegotiation disabled for this socket/;

Object.defineProperty(exports, 'constants', {
  configurable: false,
  enumerable: true,
  value: constants
});

// The process.binding('http2').Http2Session object will
// emit events as callbacks. To allow this to happen,
// it has to inherit from EventEmitter.
util.inherits(http2.Http2Session, EventEmitter);


http2.Http2Session.prototype.gracefulTerminate = function(callback, code) {
  if (typeof callback !== 'function')
    throw new TypeError('callback must be a function');
    // Begin graceful termination process. See:
    // https://nghttp2.org/documentation/nghttp2_submit_shutdown_notice.html
    // For detail. This process results in sending two GOAWAY frames to the
    // client. The second one is the actual GOAWAY that will terminate the
    // session. The second terminate and the passed in callback are invoked
    // on nextTick (TODO(jasnell): setImmediate might be better)).
  if (this.startGracefulTerminate() >= 0) {
    process.nextTick(() => {
      this.terminate(code || constants.NGHTTP2_NO_ERROR);
      callback();
    });
  }
};

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
  constructor(stream, headers) {
    super({});
    this[kStream] = stream;
    this[kHeaders] = headers;
    this[kFinished] = false;
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

  setTimeout(msecs, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  }
}


class Http2ServerRequest extends Http2Incoming {
  constructor(stream, headers) {
    super(stream, headers);
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

function getProvider(outgoing) {
  const provider = new http2.Http2DataProvider();
  provider._read = (buffer, flags) => {
    const chunks = outgoing[kChunks];
    if (chunks.length === 0) {
      if (!outgoing[kFinished]) {
        outgoing[kPaused] = true;
        return constants.NGHTTP2_ERR_DEFERRED;
      } else {
        outgoing[kEndStream](flags);
        return 0;
      }
    } else {
      if (outgoing[kFinished])
        outgoing[kEndStream](flags);
      const ret = copyBuffers(buffer, chunks);
      return ret;
    }
  };
  return provider;
}

class Http2Outgoing extends Writable {
  constructor(stream) {
    super({});
    this[kStream] = stream;
    this[kHeaders] = new Map();
    this[kTrailers] = new Map();
    this[kFinished] = false;
    this[kHeadersSent] = false;
    this[kTrailersSent] = false;
    this[kChunks] = [];

    this[kProvider] = getProvider(this);

    // If this Writable is connected to a pipe, resume any deferred data
    // frames and initiate the response if it hasn't been initiated already.
    this.on('pipe', () => {
      this[kResume]();
      this[kBeginSend]();
    });
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

  get trailersSent() {
    return this[kTrailersSent];
  }

  setHeader(name, value) {
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
    if (this.headersSent)
      throw new Error('Cannot remove headers after they are sent');
    this[kHeaders].delete(name);
    return this;
  }

  removeTrailer(name) {
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

    const state = this.stream ? this.stream.state :
                                constants.NGHTTP2_STREAM_STATE_CLOSED;
    if (state !== constants.NGHTTP2_STREAM_STATE_CLOSED &&
        state !== constants.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
      if (chunk.length > 0)
        this[kChunks].push(chunk);
      this[kResume]();
      this[kBeginSend]();
      this.stream.session.sendData();
    } else {
      if (!this[kFinished]) {
        this[kFinished] = true;
        super.end();
      }
    }
    callback();
  }

  end(data, encoding, callback) {
    this[kFinished] = true;
    const state = this.stream ? this.stream.state :
                                constants.NGHTTP2_STREAM_STATE_CLOSED;
    var ret = true;
    if (state !== constants.NGHTTP2_STREAM_STATE_CLOSED &&
        state !== constants.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
      ret = super.end(data, encoding, callback);
      this[kResume]();
      this[kBeginSend]();
    }
    return ret;
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      this.stream.respond(mapToHeaders(this[kHeaders]), this[kProvider]);
    }
  }

  [kResume]() {
    if (this.stream) {
      if (this[kPaused]) {
        this[kPaused] = false;
        this.stream.resumeData();
        this.stream.session.sendData();
      }
    }
  }

  [kEndStream](flags) {
    this[kTrailersSent] = true;
    flags[constants.FLAG_ENDDATA] = true;
    // TODO(jasnell): kHasTrailers is currently not set anywhere
    if (this[kHasTrailers]) {
      flags[constants.FLAG_NOENDSTREAM] = true;
      const stream = this.stream;
      stream.sendTrailers(mapToHeaders(this[kTrailers]));
    } else {
      flags[constants.FLAG_ENDSTREAM] = true;
    }
    this[kProvider] = null;
  }
}


class Http2ServerResponse extends Http2Outgoing {
  constructor(stream) {
    super(stream);
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
    this[kStream].sendContinue();
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

  get pushSupported() {
    if (!this.stream) return false;
    return this.stream.session.remoteSettings.enablePush;
  }

  createPushResponse() {
    if (!this.pushSupported)
      return;
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
    const ret = parent.sendPushPromise(mapToHeaders(this[kHeaders]));
    if (ret) {
      ret[kRequest] =
          new Http2ServerRequest(ret, this[kHeaders]);
      ret[kResponse] = new Http2ServerResponse(ret);
      ret[kRequest][kFinished] = true;
      ret[kRequest].end();
      callback(ret[kRequest], ret[kResponse]);
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
// TODO(jasnell): improve performance on this.
function isIllegalConnectionSpecificHeader(name, value) {
  if (/^(?:connection|upgrade|http2-settings)$/i.test(name))
    return true;
  if (/^te$/i.test(name) && !/^trailers$/i.test(value))
    return true;
  return false;
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
  const options = this[kOptions];

  // Create the Http2Session instance that is unique to this socket.
  const session = createServerSession(options);

  session.on('error', (err) => {
    if (this.listenerCount('sessionError') > 0) {
      this.emit('sessionError', err);
      return;
    }
    socket.destroy(err);
  });

  // Disable TLS Negotiation on this socket. The HTTP/2 allows renegotiation to
  // happen up until the initial HTTP/2 session bootstrap. After that, it is
  // forbidden. Let's just turn it off entirely.
  if (typeof socket.disableRenegotiation === 'function')
    socket.disableRenegotiation();

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', () => {
    if (!this.emit('timeout', socket)) {
      // Session timed out, attempt a graceful exit
      session.gracefulTerminate(() => socket.destroy());
    }
  });

  // Destroy the session if the socket is destroyed
  const destroySocket = socket.destroy;
  socket.destroy = function(error) {
    session.removeAllListeners();
    session.destroy();
    socket.removeAllListeners();
    socket.destroy = destroySocket;
    destroySocket.call(socket, error);
  };

  socket.once('error', (error) => {
    if (kRenegTest.test(error.message)) {
      // A tls renegotiation attempt was made. There's no need
      // to propogate the error and there's nothing more we can
      // do with the connection. Destroy it and move on.
      socket.destroy();
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
    if (!this.emit('socketError', error, socket)) {
      socket.destroy(error);
    }
  });

  socket.on('data', (data) => {
    // Pass data on to the session, then automatically send any
    // buffered data waiting to be sent.
    session.receiveData(data);
    session.sendData();
  });

  socket.on('resume', () => {
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
    if (socket._handle && socket._handle.reading) {
      socket._handle.reading = false;
      socket._handle.readStop();
    }
  });

  socket.on('drain', () => {
    const needPause = 0 > socket._writableState.highWaterMark;
    if (socket._paused && !needPause) {
      socket._paused = false;
      socket.resume();
    }
  });

  // Wire the Http2Session events up.
  session.on('send', (data) => {
    if (!socket.destroyed)
      socket.write(data);
  });

  session.on('begin-headers', (stream, category) => {
    stream[kHeaders] = new Headers(category);
  });
  session.on('header', (stream, name, value) => {
    stream[kHeaders].set(name, value);
  });
  session.on('headers-complete', (stream, flags) => {
    const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
    const headers = stream[kHeaders];
    delete stream[kHeaders];

    // This is a server, so the only header categories supported are
    // NGHTTP2_HCAT_REQUEST and NGHGTTP2_HCAT_HEADERS. Other categories
    // must result in a Protocol error per the spec.
    switch (headers[kType]) {
      case constants.NGHTTP2_HCAT_REQUEST:
        // header blocks in this category represent a new request.
        stream[kRequest] = new Http2ServerRequest(stream, headers);
        stream[kResponse] = new Http2ServerResponse(stream);
        // finished will be true if the header block included flags to end
        // the stream (such as when sending a GET request). In such cases,
        // mark the kRequest stream finished so no data will be read.
        if (finished) {
          stream[kRequest][kFinished] = true;
          stream[kRequest].end();
        }
        if (headers.has('expect')) {
          // If there is an expect header that contains 100-continue,
          // and the server has a listener for the checkContinue event,
          // emit the checkContinue event instead of the request event.
          // This behavior matches the current http/1 API.
          if (/^100-continue$/i.test(headers.get('expect'))) {
            stream[kResponse][kExpectContinue] = true;
            if (this.listenerCount('checkContinue') > 0) {
              stream[kRequest][kInFlight] = true;
              this.emit('checkContinue',
                        stream[kRequest],
                        stream[kResponse]);
              delete stream[kRequest][kInFlight];
              break;
            }
            stream[kResponse].writeContinue();
            // This falls through to the emit the request event
          } else {
            // If there is an expect header that contains anything
            // other than 100-continue, emit the checkExpectation
            // event if there are listeners or automatically return
            // a 417 and end the response. This behavior matches the
            // current http/1 API
            if (this.listenerCount('checkExpectation') > 0) {
              stream[kRequest][kInFlight] = true;
              this.emit('checkExpectation',
                        stream[kRequest],
                        stream[kResponse]);
              delete stream[kRequest][kInFlight];
            } else {
              stream[kResponse].writeHead(
                  constants.HTTP_STATUS_EXPECTATION_FAILED);
              stream[kResponse].end();
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
        if (stream[kRequest].method === 'CONNECT') {
          if (this.listenerCount('connect') > 0) {
            stream[kRequest][kInFlight] = true;
            this.emit('connect', stream[kRequest], stream[kResponse]);
            delete stream[kRequest][kInFlight];
          } else {
            stream.sendRstStream(constants.NGHTTP2_REFUSED_STREAM);
          }
          break;
        }
        stream[kRequest][kInFlight] = true;
        this.emit('request', stream[kRequest], stream[kResponse]);
        delete stream[kRequest][kInFlight];
        break;
      case constants.NGHTTP2_HCAT_HEADERS:
        if (!finished) {
          // When category === NGHTTP2_HCAT_HEADERS and finished is not
          // null, that means an extra HEADERS frame was sent after
          // the initial HEADERS frame that opened the request, without the
          // end stream flag set. Interstitial headers frames are not permitted
          // in the HTTP semantic binding per the HTTP/2 spec
          stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR);
          return;
        }
        // If finished, that means these are trailing headers
        const request = stream[kRequest];
        request[kTrailers] = headers;
        break;
      default:
        stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR);
    }
  });

  session.on('data-chunk', (stream, flags, chunk) => {
    const request = stream[kRequest];
    if (!request) {
      const err = new Error('Invalid Http2Session State');
      session.emit('error', err);
      return;
    }
    // TODO(jasnell): to properly handle padding, we should actually buffer
    // this data and not write it to the request until the data-end event is
    // emitted. See below.
    request.write(chunk);
  });
  session.on('data', (stream, flags, padding) => {
    const finished = Boolean(flags & constants.NGHTTP2_DATA_FLAG_EOF ||
                          flags & constants.NGHTTP2_FLAG_END_STREAM);
    // TODO: How to handle padding???? data-end will be triggered after the
    // completion of each individual data frame. The spec allows each data
    // frame to contain additional padding bytes that must be stripped from
    // the data before passing on to the user. This means that we should not
    // actually pass the data on to the request until data-end and the padding
    // can be stripped. To accomplish this, the data-chunk event and this
    // event need to be modified to buffer the data and strip the padding.
    const request = stream[kRequest];
    if (finished) {
      request[kFinished] = finished;
      request.end();
    }
  });
  session.on('stream-close', (stream, code) => {
    if (stream[kRequest] && !stream[kRequest].finished) {
      stream[kRequest].end();
      stream[kRequest][kFinished] = true;
      if (stream[kRequest][kInFlight])
        stream[kRequest].emit('aborted');
    }
    if (stream[kResponse] && !stream[kResponse].finished) {
      stream[kResponse].end();
      stream[kResponse][kFinished] = true;
    }

    delete stream[kRequest][kStream];
    delete stream[kResponse][kStream];
    delete stream[kRequest];
    delete stream[kResponse];
  });
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

function createServerSession(options) {
  const session =
    new http2.Http2Session(constants.SESSION_TYPE_SERVER, options);
  EventEmitter.call(session);
  return session;
}

function createClientSession(options) {
  const session =
    new http2.Http2Session(constants.SESSION_TYPE_CLIENT, options);
  EventEmitter.call(session);
  return session;
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

// class Http2ClientRequest extends Http2Outgoing {
//   constructor(stream, socket) {
//     super(stream, socket);
//   }
// }

// class Http2ClientResponse extends Http2Incoming {
//   constructor(stream, headers, socket) {
//     super(stream, headers, socket);
//   }

//   get status() {
//     return this.headers.get(constants.HTTP2_HEADER_STATUS) | 0;
//   }
// }

function createClient(options, callback) {
  return new Http2ClientSession(options, callback);
}

// Exports
module.exports = {
  Http2Settings: http2.Http2Settings,
  createClient: createClient,
  createServer: createServer,
  createSecureServer: createSecureServer,
  createServerSession: createServerSession,
  createClientSession: createClientSession
};
