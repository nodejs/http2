'use strict';

const http2 = process.binding('http2');
const util = require('util');
const Buffer = require('buffer').Buffer;
const EventEmitter = require('events');
const internalHttp = require('internal/http');
const TLSServer = require('tls').Server;
const NETServer = require('net').Server;
const stream = require('stream');
const BufferList = require('internal/streams/BufferList');
const Writable = stream.Writable;
const PassThrough = stream.PassThrough;
const constants = http2.constants;
const utcDate = internalHttp.utcDate;

const kOptions = Symbol('options');
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

function onHttp2OutgoingPipe() {
  if (this[kHeadersSent])
    this[kResume]();
  else
    this[kBeginSend]();
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
    this[kChunks] = new BufferList();
    this[kProvider] = getProvider(this);
    this.on('pipe', onHttp2OutgoingPipe);
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

  _writev(chunks, callback) {
    const state = this.stream ? this.stream.state :
                                constants.NGHTTP2_STREAM_STATE_CLOSED;
    if (state !== constants.NGHTTP2_STREAM_STATE_CLOSED &&
        state !== constants.NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL) {
      for (var n = 0; n < chunks.length; n++)
        this[kChunks].push(chunks[n]);
      if (this[kHeadersSent])
        this[kResume]();
      else
        this[kBeginSend]();
    } else {
      this[kFinished] = true;
      super.end();
    }
    callback();
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
      if (this[kHeadersSent])
        this[kResume]();
      else
        this[kBeginSend]();
    } else {
      this[kFinished] = true;
      super.end();
    }
    callback();
  }

  end(data, encoding, callback) {
    if (this[kFinished])
      return false;
    this[kFinished] = true;
    const ret = super.end(data, encoding, callback);
    if (this[kHeadersSent])
      this[kResume]();
    else
      this[kBeginSend]();
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
      this.stream.resumeData();
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
    if (this[kHeadersSent])
      this[kResume]();
    else
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
function copyBuffers(buffer, list, offset) {
  // list head will be null if there are no buffers;
  if (list.length === 0) return 0;
  offset |= 0;
  var remaining = buffer.length - offset;
  var copied = 0;
  do {
    // pop the first one;
    const head = list.shift();
    if (head.length > remaining) {
      // the head has more than we need...
      // copy just a bit, unshift the rest back onto the list... then be done
      const n = head.copy(buffer, offset, 0, remaining);
      list.unshift(head.slice(remaining));
      remaining -= n;
      copied += n;
    } else {
      // head either has exactly what we need or not enough.
      const n = head.copy(buffer, offset, 0, head.length);
      offset += n;
      remaining -= n;
      copied += n;
    }
  } while (list.head && remaining);
  return copied;
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

function sessionOnDataChunk(stream, flags, chunk) {
  const request = stream[kRequest];
  if (!request) {
    const err = new Error('Invalid Http2Session State');
    this.emit('error', err);
    return;
  }
  // TODO(jasnell): to properly handle padding, we should actually buffer
  // this data and not write it to the request until the data-end event is
  // emitted. See below.
  request.write(chunk);
}

function sessionOnData(stream, flags, padding) {
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
}

function sessionOnStreamClose(stream, code) {
  const request = stream[kRequest];
  const response = stream[kResponse];
  if (request && !request.finished) {
    request.end();
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
}

function sessionOnError(server, socket) {
  function fn(error) {
    if (server.listenerCount('sessionError') > 0) {
      server.emit('sessionError', error);
      return;
    }
    socket.destroy(error);
  };
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

function socketOnceError(server) {
  function fn(error) {
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
    if (!server.emit('socketError', error, this)) {
      this.destroy(error);
    }
  }
  return fn;
}

function sessionOnSend(socket) {
  function fn(data) {
    if (!socket.destroyed)
      socket.write(data);
  }
  return fn;
}

function sessionOnHeaderComplete(server) {
  function fn(stream, flags, headers, category) {
    const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);

    // This is a server, so the only header categories supported are
    // NGHTTP2_HCAT_REQUEST and NGHGTTP2_HCAT_HEADERS. Other categories
    // must result in a Protocol error per the spec.
    var request;
    var response;
    switch (category) {
      case constants.NGHTTP2_HCAT_REQUEST:
        // header blocks in this category represent a new request.
        request = stream[kRequest] = new Http2ServerRequest(stream, headers);
        response = stream[kResponse] = new Http2ServerResponse(stream);
        // finished will be true if the header block included flags to end
        // the stream (such as when sending a GET request). In such cases,
        // mark the kRequest stream finished so no data will be read.
        if (finished) {
          request[kFinished] = true;
          request.end();
        }
        if (headers.has('expect')) {
          // If there is an expect header that contains 100-continue,
          // and the server has a listener for the checkContinue event,
          // emit the checkContinue event instead of the request event.
          // This behavior matches the current http/1 API.
          if (/^100-continue$/i.test(headers.get('expect'))) {
            response[kExpectContinue] = true;
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
            stream.sendRstStream(constants.NGHTTP2_REFUSED_STREAM);
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
          stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR);
          return;
        }
        // If finished, that means these are trailing headers
        stream[kRequest][kTrailers] = headers;
        break;
      default:
        stream.sendRstStream(constants.NGHTTP2_PROTOCOL_ERROR);
    }
  }
  return fn;
}

function connectionListener(socket) {
  const options = this[kOptions];

  // Create the Http2Session instance that is unique to this socket.
  const session = createServerSession(options, socket);

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
    socket.destroy = destroySocket;
    destroySocket.call(socket, error);
  };
  socket.once('error', socketOnceError(this));
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);
  session.on('send', sessionOnSend(socket));
  session.on('headers', sessionOnHeaderComplete(this));
  session.on('data-chunk', sessionOnDataChunk);
  session.on('data', sessionOnData);
  session.on('stream-close', sessionOnStreamClose);
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

function createServerSession(options, socket) {
  const session =
    new http2.Http2Session(constants.SESSION_TYPE_SERVER,
                           options,
                           socket._handle._externalStream);
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
