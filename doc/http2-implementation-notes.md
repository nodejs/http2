**Note:** This is currently in a massive state of flux.

## Overview

The HTTP/2 implementation is built around the nghttp2 library, which does most
of the heavy lifting. The nghttp2 library has been added into deps/nghttp2.
The `src/node_http2.cc` class is largely a wrapper for that nghttp2 API.
Defined within that file the following classes (currently):

* `node::http2::Http2Header` - Wraps the `nghttp_nv` struct used to represent header name-value pairs.
* `node::http2::Http2DataProvider` - Wraps the data provider construct used by nghttp2 to provide data to data frames
* `node::http2::Http2Stream` - Represents an nghttp2 stream
* `node::http2::Http2Session` - Wraps the nghttp2_session struct.

The code within `lib/internal/http2.js` provides the actual implementation of
the HTTP/2 server. At this point in time, the client code has not yet been
implemented.

**Note**: My process up to this point has been on getting something working then
iterating on the design and implementation to improve it. As such, the current
implementation leaves much to be desired. I will be iterating and refining it
as we move forward.

The server is implemented as follows:

First we create either a `net.Server` or a `tls.Server`, depending on whether
TLS is being used or not. This server instance is passed a connectionListener
callback. When a new socket connection is established and the callback is
invoked, a new `Http2Session` object instance is created and associated with
that socket. Because the HTTP/2 session lives for lifetime of socket connection,
this session is persistent.

A series of event handlers and registered on both the socket and the
`Http2Session` to facilitate the flow of data back and forth between the two.
Note, however, that the performance of this could be improved by moving the
socket handling into the native layer. Doing so would allow us to skip the
boundary crossing that has to occur.


## class HTTP2.Http2Session : EventEmitter {}

### Event: `'send'`

The `'send'` event is emitted whenever the `HTTP2.Http2Session` instance has
data prepared to send to a remote peer. The event callback is invoked with a
single `Buffer` argument containing the serialized frames to be sent.

```js
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('send', (buffer) => socket.write(buffer));
```

### Event: `'begin-headers'`

The `'begin-headers'` event is emitted at the beginning of a new HEADERS
frame. The event callback is invoked with two arguments: an `Http2Stream`
object representing the associated HTTP/2 stream, and a category identifying
the type of HEADERS frame received. This type is determined by the underlying
nghttp2 library based on the HTTP/2 stream state.

```js
const constants = require('http').HTTP2.constants;
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('begin-headers', (stream, category) => {
  console.log(stream.id);
  switch (category) {
    case constants.NGHTTP2_HCAT_REQUEST:
    case constants.NGHTTP2_HCAT_RESPONSE:
    case constants.NGHTTP2_HCAT_PUSH_RESPONSE:
    case constants.NGHTTP2_HCAT_HEADERS:
  }
});
```

### Event: `'header'`

The `'header'` event is emitted once for each header name-value pair received
during the processing of a HEADERS frame. The event may be called zero-or-more
times following the emission of the `'begin-headers'` event. The callback is
invoked with three arguments: an `Http2Stream` object representing the
associated HTTP/2 stream, the header field name passed as a String, and the
header field value passed as a String.

```js
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('header', (stream, name, value) => {
  console.log('Header Field:', name);
  console.log('Header Value:', value);
});
```

### Event: `'headers-complete'`

The `'headers-complete'` event is emitted once a complete HEADERS frame has
been processed and all `'header'` events have been emitted. The callback is
invoked with two arguments: an `Http2Stream` object representing the
associated HTTP/2 stream, and a `finished` boolean used to indicate if the
HEADERS block concluded the HTTP/2 stream or not.

```js
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('headers-complete', (stream, finished) => {
  // ... 
});
```

### Event: `'stream-close'`

The `'stream-close'` event is emitted whenever an HTTP/2 stream is closed,
either by normal or early termination. The callback is invoked with two
arguments: an `Http2Stream` object representing the associated HTTP/2 stream,
and an Unsigned 32-bit integer that represents the error code (if any).

```js
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('stream-close', (stream, code) => {
  console.log(`Stream ${stream.id} closed with code ${code}`);
});
```

### Event: `'data-chunk'`

The `'data-chunk'` event is emitted whenever a chunk of data from a DATA frame
has been received. The callback is invoked with two arguments: an
`Http2Stream` object representing the associated stream, and a `Buffer`
instance containing the chunk of data.

```js
const session = getSessionSomehow();
const socket = getSocketSomehow();
session.on('data-chunk', (stream, chunk) => {
  // ...
});
```

### Event: `'data-end'`

The `'data-end'` event is emitted whenever a complete DATA frame has been
processed. This event will follow zero-or-more `'data-chunk'` events. The
callback is invoked with three arguments: an `Http2Stream` object representing
the associated HTTP/2 stream, a boolean indicating whether or not the DATA
frame completed the stream, and a non-negative integer indicating the number
of padding bytes included in the data frame.

### Event: `'frame-sent'`

The `'frame-sent'` event is emitted whenever a compete HTTP/2 frame has been
sent.

### Event: `'goaway'`

The `'goaway'` event is emitted when a GOAWAY frame is received.

### Event: `'rst-stream'`

The `'rst-stream'` event is emitted when a RST-STREAM frame is received.

### Property: `session.localWindowSize` (Read-only)
### Property: `session.inflateDynamicTableSize` (Read-only)
### Property: `session.deflateDynamicTableSize` (Read-only)
### Property: `session.remoteWindowSize` (Read-only)
### Property: `session.outboundQueueSize` (Read-only)
### Property: `session.lastProcStreamID` (Read-only)
### Property: `session.effectiveRecvDataLength` (Read-only)
### Property: `session.effectiveLocalWindowSize` (Read-only)
### Property: `session.nextStreamID` (Read-Write)
### Method: `session.resumeData(stream)`
### Method: `session.respond(stream, headers, provider)`
### Method: `session.destroy()`
### Method: `session.terminate(code)`
### Method: `session.sendConnectionHeader()`
### Method: `session.receiveData(data)`
### Method: `session.sendData()`
### Method: `session.changeStreamPriority(stream, parent, weight, exclusive)`
### Method: `session.consume(stream, size)`
### Method: `session.consumeSession(size)`
### Method: `session.consumeStream(stream, size)`
### Method: `session.rstStream(stream, code)`
### Method: `session.createIdleStream(stream, parent, weight, exclusive)`

## HTTP2.Http2Stream

### Property: `stream.id` (Read-only)

## HTTP2.Http2Request : extends stream.Readable

### Property: `request.headers` (Read-only)
### Property: `request.method` (Read-only)
### Property: `request.authority` (Read-only)
### Property: `request.scheme` (Read-only)
### Property: `request.url` (Read-only)
### Property: `request.httpVersion` (Read-only)
### Property: `request.socket` (Read-only)
### Property: `request.trailers` (Read-only)
### Method: `request.setTimeout(msec, callback)`

## HTTP2.Http2Response : ends stream.Writable

### Property: `response.sendDate` (Read-Write)
### Property: `response.socket` (Read-only)
### Property: `response.finished` (Read-only)
### Property: `response.headersSent` (Read-only)
### Property: `response.statusCode` (Read-Write)
### Method: `response.setHeader(name, value)`
### Method: `response.setTrailer(name, value)`
### Method: `response.addHeaders(headers)`
### Method: `response.addTrailers(headers)`
### Method: `response.getHeader(name)`
### Method: `response.getTrailer(name)`
### Method: `response.removeHeader(name)`
### Method: `response.removeTrailer(name)`
### Method: `response.setTimeout(msec, callback)`
### Method: `response.writeContinue()`
### Method: `response.writeHeader(statusCode, headers)`
### Method: `response.write()`
### Method: `response.end()`

## HTTP2.createServerSession(options)

## HTTP2.createClientSession(options)

## HTTP2.createServer(options, callback)

## HTTP2.createSecureServer(options, callback)

## HTTP2.createClient(options)
