'use strict';

const http2 = process.binding('http2');
const Buffer = require('buffer').Buffer;
const assert = require('assert');
const EventEmitter = require('events');
const internalHttp = require('internal/http');
const TLSServer = require('tls').Server;
const NETServer = require('net').Server;
const stream = require('stream');
const Writable = stream.Writable;
const Readable = stream.Readable;
const PassThrough = stream.PassThrough;
const constants = http2.constants;
const utcDate = internalHttp.utcDate;

const kOptions = Symbol('options');
const kHandle = Symbol('handle');
const kType = Symbol('type');
const kStream = Symbol('stream');
const kStreams = Symbol('streams');
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
const kResponseFlags = Symbol('response-flags');
const kResponseFlag_SendDate = 0x1;

function checkSuccessOrEmitError(emitter, rv, message) {
  if (rv < 0) {
    const err = new Error(message ||
                          `HTTP2Error: ${http2.nghttp2ErrorString(rv)}`);
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

class Http2Session extends EventEmitter {
  constructor(type) {
    super();
    type |= 0;
    if (type !== constants.SESSION_TYPE_SERVER &&
        type !== constants.SESSION_TYPE_CLIENT) {
      throw new TypeError('Invalid session type');
    }

    this[kStreams] = new Map();
    const session = new http2.Http2Session(type);

    session[constants.CALLBACK_ONSEND] = (buffer) => {
      process.nextTick(() => this.emit('send', buffer));
    };

    // Called at the beginning of a new block of headers.
    session[constants.CALLBACK_ONBEGINHEADERS] = (stream, category) => {
      // stream is the Http2Stream object the headers belong to
      // category is the header type category from constants
      if ((type === constants.SESSION_TYPE_SERVER &&
           category === constants.NGHTTP2_HCAT_RESPONSE ||
           category === constants.NGHTTP2_HCAT_PUSH_RESPONSE) ||
          (type === constants.SESSION_TYPE_CLIENT &&
           category === constants.NGHTTP2_HCAT_REQUEST)) {
        this.rstStream(stream, constants.NGHTTP2_PROTOCOL_ERROR);
        return;
      }
      if (category === constants.NGHTTP2_HCAT_REQUEST ||
          category === constants.NGHTTP2_HCAT_RESPONSE) {
        this[kStreams].set(stream.id, stream);
      }
      process.nextTick(() => this.emit('begin-headers', stream, category));
    };

    session[constants.CALLBACK_ONHEADER] = (stream, name, value) => {
      // stream is the Http2Stream object the header belongs to
      // name is the header name
      // value is the header value
      process.nextTick(() => this.emit('header', stream, name, value));
    };

    session[constants.CALLBACK_ONHEADERS] = (stream, flags) => {
      // stream is the Http2Stream object the headers belong to
      // flags is the header flags from constant
      // if this is a server, emit a request
      // if this ia a client, emit a response
      const finished = Boolean(flags & constants.NGHTTP2_FLAG_END_STREAM);
      process.nextTick(() => this.emit('headers-complete', stream, finished));
    };

    session[constants.CALLBACK_ONSTREAMCLOSE] = (stream, code) => {
      // stream is the Http2Stream object that is being closed.
      // code is the error code
      this[kStreams].delete(stream.id);
      process.nextTick(() => this.emit('stream-close', stream.id, code));
    };

    session[constants.CALLBACK_ONDATACHUNK] = (streamID, flags, data) => {
      // streamID is the numeric stream ID the data belongs to
      // flags is the data flags
      // data is the Buffer containing the data
      const stream = this[kStreams].get(streamID);
      process.nextTick(() => this.emit('data-chunk', stream, data));
    };

    session[constants.CALLBACK_ONDATA] = (stream, flags, length, padding) => {
      // stream is the Http2Stream object the data belongs to
      // flags is the frame flags
      // length is the amount of data
      // padding is the amount of padding in the data
      const finished = Boolean(flags & constants.NGHTTP2_DATA_FLAG_EOF ||
                               flags & constants.NGHTTP2_FLAG_END_STREAM);
      process.nextTick(() => this.emit('data-end', stream, finished, padding));
    };

    session[constants.CALLBACK_ONFRAMESEND] = (streamID, type, flags) => {
      // streamID is the stream the frame belongs to
      // type is the frame type
      // flags are the frame flags
      process.nextTick(() => this.emit('frame-sent', streamID, type, flags));
    };

    session[constants.CALLBACK_ONGOAWAY] = (code, lastStreamID, data) => {
      // code is the error code
      // lastStreamID is the last processed stream ID
      // data is the optional additional application data
      process.nextTick(() => this.emit('goaway', code, lastStreamID, data));
    };
    session[constants.CALLBACK_ONRSTSTREAM] = (stream, code) => {
      // stream is the stream object
      // code is the RstStream code
      this[kStreams].delete(stream.id);
      process.nextTick(() => this.emit('rst-stream', stream, code));
    };

    //session[constants.CALLBACK_ONPRIORITY] = () => {};
    //session[constants.CALLBACK_ONSETTINGS] = () => {};
    //session[constants.CALLBACK_ONPING] = () => {};
    this[kHandle] = session;
  }

  get localWindowSize() {
    return this._handle.localWindowSize;
  }

  get inflateDynamicTableSize() {
    return this._handle.inflateDynamicTableSize;
  }

  get deflateDynamicTableSize() {
    return this._handle.deflateDynamicTableSize;
  }

  get remoteWindowSize() {
    return this._handle.remoteWindowSize;
  }

  get outboundQueueSize() {
    return this._handle.outboundQueueSize;
  }

  get lastProcStreamID() {
    return this._handle.lastProcStreamID;
  }

  get effectiveRecvDataLength() {
    return this._handle.effectiveRecvDataLength;
  }

  get effectiveLocalWindowSize() {
    return this._handle.effectiveLocalWindowSize;
  }

  get nextStreamID() {
    return this._handle.nextStreamID;
  }

  set nextStreamID(id) {
    this._handle.nextStreamID = id;
  }

  get _handle() {
    return this[kHandle];
  }

  resumeData(stream) {
    checkSuccessOrEmitError(this, this._handle.resumeData(stream));
  }

  respond(stream, headers, provider) {
    checkSuccessOrEmitError(
        this,
        this._handle.respond(stream, headers, provider));
  }

  destroy() {
    this._handle.destroy();
    this[kHandle] = null;
  }

  terminate(code) {
    // TODO(jasnell): lastProcStreamID?
    code |= 0;
    checkSuccessOrEmitError(this, this._handle.terminate(code));
  }

  sendConnectionHeader() {
    if (checkSuccessOrEmitError(this,
                                this._handle.sendConnectionHeader())) {
      this.sendData();
    }
  }

  /**
   * When a chunk of data is received by the Socket, the receiveData
   * method passes that data on to the underlying nghttp2_session. The
   * data argument must be a Buffer.
   **/
  receiveData(data) {
    checkSuccessOrEmitError(this, this._handle.receiveData(data));
  }

  /**
   * Prompts the nghttp2_session to serialize and send (via callbacks) any
   * http/2 frames currently in it's outgoing queue.
   **/
  sendData() {
    checkSuccessOrEmitError(this, this._handle.sendData());
  }

  changeStreamPriority(stream, parent, weight, exclusive) {
    // TODO(jasnell): Implement this
  }

  consume(stream, size) {
    stream = Number.isNaN(stream) ? stream.id : stream;
    size |= 0;
    checkSuccessOrEmitError(this, this._handle.consume(stream, size));
  }

  consumeSession(size) {
    size |= 0;
    checkSuccessOrEmitError(this, this._handle.consume(stream, size));
  }

  consumeStream(stream, size) {
    stream = Number.isNaN(stream) ? stream.id : stream;
    size |= 0;
    checkSuccessOrEmitError(this, this._handle.consume(stream, size));
  }

  rstStream(stream, code) {
    stream = isNaN(stream) ? stream.id : stream;
    code |= 0;
    checkSuccessOrEmitError(this, this._handle.rstStream(stream, code));
  }

  createIdleStream(stream, parent, weight, exclusive) {
    // TODO(jasnell): Implement this
    // This is used to prepare a stream for use... for instance, when using
    // push streams.
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
  constructor(session, stream, headers, socket) {
    super({});
    this[kSession] = session;
    this[kStream] = stream;
    this[kSocket] = socket;
    this[kHeaders] = headers;
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

  setTimeout(msecs, callback) {
    if (callback)
      this.on('timeout', callback);
    this.socket.setTimeout(msecs);
    return this;
  }

}


class Http2ServerRequest extends Http2Incoming {
  constructor(session, stream, headers, socket) {
    super(session, stream, headers, socket);
  }

  get method() {
    return this.headers.get(':method');
  }

  get authority() {
    return this.headers.get(':authority');
  }

  get scheme() {
    return this.headers.get(':scheme');
  }

  get url() {
    return this.headers.get(':path');
  }

  get httpVersion() {
    return '2.0';
  }
}


class Http2ClientResponse extends Http2Incoming {
  constructor(session, stream, headers, socket) {
    super(session, stream, headers, socket);
  }

  get status() {
    return this.headers.get(':status') | 0;
  }

  get httpVersion() {
    return '2.0';
  }
}

class Http2Outgoing extends Writable {
  constructor(session, stream, socket) {
    super({});
    this[kSession] = session;
    this[kStream] = stream;
    this[kSocket] = socket;
    this[kFinished] = false;
    this[kHeaders] = new Map();
    this[kTrailers] = new Map();
    this[kHeadersSent] = false;
    this[kTrailersSent] = false;
    this[kChunks] = [];

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
    this[kProvider][constants.CALLBACK_ONDATA] = (buffer, flags) => {
      const chunks = this[kChunks];
      if (chunks.length === 0) {
        if (!this[kFinished]) {
          // The end() method has not yet been called but there's
          // currently no data in the queue, defer the data frame
          // until additional data is written.
          this[kPaused] = true;
          return constants.NGHTTP2_ERR_DEFERRED;
        } else {
          // There is no more data in the queue and end() has
          // been called. Set the flags. Note: this will cause
          // an extra empty data frame to be sent. See below.
          this[kEndStream](flags);
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
          this[kEndStream](flags);
        }
        // Consume as much of the currently buffered
        // data as possible per data frame up to buffer.length
        return copyBuffers(buffer, chunks);
      }
    };

    // If this Writable is connected to a pipe, resume any deferred data
    // frames and initiate the response if it hasn't been initiated already.
    this.on('pipe', () => {
      this[kResume]();
      this[kBeginSend]();
    });
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
    // if (this.headersSent)
    //   throw new Error('Cannot set headers after they are sent');
    name = String(name).toLowerCase().trim();
    if (isPseudoHeader(name))
      throw new Error('Cannot set HTTP/2 pseudo-headers this way');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP headers are not permitted');
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      this[kHeaders].delete(name);
      return this;
    }
    // Cannot add headers that start with the :-prefix
    if (name[0] === ':')
      throw new TypeError('Cannot add HTTP/2 pseudo-headers');
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
      throw new Error('Cannot set HTTP/2 pseudo-headers this way');
    if (isIllegalConnectionSpecificHeader(name, value))
      throw new Error('Connection-specific HTTP headers are not permitted');
    // Delete the current value if it's null
    if (value === undefined || value === null) {
      this[kTrailers].delete(name);
      return this;
    }
    // Cannot add headers that start with the :-prefix
    if (name[0] === ':')
      throw new TypeError('Cannot add HTTP/2 pseudo-headers');
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
    this.socket.setTimeout(msecs);
    return this;
  }

  _write(chunk, encoding, callback) {
    if (typeof chunk === 'string')
      chunk = Buffer.from(chunk, encoding);
    if (chunk.length > 0)
      this[kChunks].push(chunk);
    callback();
    this[kResume]();
    this[kBeginSend]();
    this[kSession].sendData(this[kStream]);
  }

  end(data, encoding, callback) {
    super.end(data, encoding, callback);
    this[kFinished] = true;
    this[kResume]();
    this[kBeginSend]();
  }

  [kBeginSend]() {
    if (!this[kHeadersSent]) {
      this[kHeadersSent] = true;
      this[kSession].respond(this[kStream],
                             mapToHeaders(this[kHeaders]),
                             this[kProvider]);
    }
  }

  [kResume]() {
    if (this[kPaused]) {
      this[kPaused] = false;
      this[kSession].resumeData(this[kStream]);
      this[kSession].sendData(this[kStream]);
    }
  }

  [kEndStream](flags) {
    this[kTrailersSent] = true;
    flags[Http2Session.kFlagEndData] = true;
    // TODO(jasnell): kHasTrailers is currently not set anywhere
    if (this[kHasTrailers]) {
      flags[constants.FLAG_NOENDSTREAM] = true;
      this[kSession].sendTrailers(this[kStream],
                                  mapToHeaders(this[kTrailers]));
    } else {
      flags[constants.FLAG_ENDSTREAM] = true;
    }
  }
}


class Http2ServerResponse extends Http2Outgoing {
  constructor(session, stream, socket) {
    super(session, stream, socket);
    this[kResponseFlags] = kResponseFlag_SendDate;
    this.statusCode = 200;
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
    this[kHeaders].get(':status');
  }

  set statusCode(code) {
    code |= 0;
    if (code === 101)
      throw new RangeError('Status code 101 is not supported by HTTP/2');
    if (code < 100 || code > 999)
      throw new RangeError(`Invalid status code: ${code}`);
    this[kHeaders].set(':status', code);
  }

  writeContinue() {
    checkSuccessOrEmitError(this, this[kSession].sendContinue(this[kStream]));
  }

  writeHead(statusCode, headers) {
    this.statusCode = statusCode;
    const keys = Object.keys(headers);
    for (var key of keys)
      this.setHeader(key, headers[key]);
    return this;
  }

  [kBeginSend]() {
    if (this.sendDate)
      this.setHeader('date', utcDate());
    super[kBeginSend]();
  }
}

// TODO(jasnell): improve performance on these
// The HTTP/2 spec forbids request pseudo-headers from appearing within
// responses, and response pseudo-headers from appearing with requests.
// Improper use must be handled as malformed messages.
function isPseudoHeader(name) {
  return String(name)[0] === ':';
}

function isRequestPseudoHeader(name) {
  return /:method|:scheme|:authority|:path/i.test(name);
}

function isResponsePseudoHeader(name) {
  return /:status/i.test(name);
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


class Http2ClientRequest extends Http2Outgoing {
  constructor(session, stream, socket) {
    super(session, stream, socket);
  }
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
  const session =
      socket[kSession] =
        createServerSession(socket);

  // `outgoingData` is an approximate amount of bytes queued through all
  // inactive responses. If more data than the high watermark is queued - we
  // need to pause TCP socket/HTTP parser, and wait until the data will be
  // sent to the client.
  socket[kOutgoingData] = 0;
  function updateOutgoingData(delta) {
    socket[kOutgoingData] += delta;
    if (socket._paused &&
        socket[kOutgoingData] < socket._writableState.highWaterMark)
      return socketOnDrain();
  }

  // For many stream errors, simply doing an rst-stream should be sufficient,
  // however, first we will emit a clientError event and give the developer
  // an opportunity to respond more appropriately.
  function clientErrorOrRstStream(emitter, stream, code) {
    if (!emitter.emit('clientError', stream, code))
      session.rstStream(stream, code);
  }

  // Set up the timeout listener
  if (this.timeout)
    socket.setTimeout(this.timeout);
  socket.on('timeout', () => {
    if (!this.emit('timeout', socket)) {
      socket.destroy();
    }
  });

  // Destroy the session if the socket is destroyed
  const destroySocket = socket.destroy;
  socket.destroy = function() {
    session.destroy();
    destroySocket.call(socket);
  };

  // Terminate the session if socket.end() is called
  const endSocket = socket.end;
  socket.end = function(data, encoding) {
    // needs to write the data, then terminate the session,
    // *then* end the socket
    socket.write(data, encoding, () => {
      session.terminate();
      // end the socket somehow
    });
  };

  socket.on('error', socketOnError);
  socket.on('close', socketOnClose);
  socket.on('end', socketOnEnd);
  socket.on('data', socketOnData);
  socket.on('resume', socketOnResume);
  socket.on('pause', socketOnPause);
  socket.on('drain', socketOnDrain);

  // Wire the Http2Session events up.
  session.on('send', (data) => socket.write(data));

  session.on('begin-headers', (stream, category) => {
    // Each time this is called, a new block of header pairs
    // is being processed. Create a new headers map to store
    // them in.
    stream[kHeaders] = new Headers(category);
  });
  session.on('header', (stream, name, value) => {
    const headers = stream[kHeaders];
    assert(headers);
    if (name[0] === ':' && isResponsePseudoHeader(name)) {
      // Response pseudo-headers must not appear within an HTTP request
      clientErrorOrRstStream(this, stream, constants.REFUSED_STREAM);
      return;
    }
    headers.set(name, value);
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
        assert(!stream[kRequest]);
        stream[kRequest] = new Http2ServerRequest(session, stream,
                                                  headers, socket);
        stream[kResponse] = new Http2ServerResponse(session, stream, socket);
        // finished will be true if the header block included flags to end
        // the stream (such as when sending a GET request). In such cases,
        // mark the kRequest stream finished so no data will be read.
        if (finished) {
          stream[kRequest][kFinished] = true;
          stream[kRequest].end();
        }
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
          clientErrorOrRstStream(this, stream, constants.REFUSED_STREAM);
          return;
        }
        const request = stream[kRequest];
        assert(request);
        request[kTrailers] = headers;
        break;
      default:
        session.rstStream(stream, constants.NGHTTP2_PROTOCOL_ERROR);
    }
  });

  session.on('data-chunk', (stream, chunk) => {
    const request = stream[kRequest];
    if (!request) {
      const err = new Error('Invalid Http2Session State');
      process.nextTick(() => session.emit('error', err));
      return;
    }
    // TODO(jasnell): This needs to make sure that that data isn't received
    // on an already completed stream.
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
    const request = stream[kRequest];
    if (!request) {
      const err = new Error('Invalid Http2Session State');
      process.nextTick(() => session.emit('error', err));
      return;
    }
    if (finished) {
      request[kFinished] = finished;
      request.end();
    }
  });
  session.on('stream-close', (stream, code) => {});
  session.on('rst-stream', (stream, code) => {});
  session.on('goaway', (code) => {});

  // Now that the socket is setup, send the HTTP/2 server handshake
  session.sendConnectionHeader();
}

function socketOnError(error) {
  const session = this[kSession];
}

function socketOnClose() {
  const session = this[kSession];
}

function socketOnEnd() {
  const session = this[kSession];
}

function socketOnData(data) {
  const session = this[kSession];
  const err = session.receiveData(data);
  if (err) {
    throw err;
  }
  session.sendData();
}

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
  const needPause = this[kOutgoingData] > this._writableState.highWaterMark;
  if (this._paused && !needPause) {
    this._paused = false;
    this.resume();
  }
}

function initializeOptions(options) {
  options = options || {};
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
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
    this.on('tlsClientError', (err, conn) => {
      if (!this.emit('clientError', err, conn))
        conn.destroy(err);
    });
  }
}

class Http2ServerSession extends NETServer {
  constructor(options, requestListener) {
    super(connectionListener);
    this[kOptions] = initializeOptions(options);
    if (typeof requestListener === 'function')
      this.on('request', requestListener);
  }
}

class Http2ClientSession {
  constructor(options, callback) {
    this[kOptions] = initializeOptions(options);
    this[kSession] = createClientSession(options);
  }
}

function createServerSession() {
  return new Http2Session(constants.SESSION_TYPE_SERVER);
}

function createClientSession() {
  return new Http2Session(constants.SESSION_TYPE_CLIENT);
}

function createSecureServer(options, handler) {
  return new Http2SecureServerSession(options, handler);
}

function createServer(options, handler) {
  return new Http2ServerSession(options, handler);
}

function createClient(options, callback) {
  return new Http2ClientSession(options, callback);
}

module.exports.Http2Settings = http2.Http2Settings;
module.exports.createClient = createClient;
module.exports.createServer = createServer;
module.exports.createSecureServer = createSecureServer;
module.exports.createServerSession = createServerSession;
module.exports.createClientSession = createClientSession;
