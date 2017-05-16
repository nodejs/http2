# HTTP2

> Stability: 1 - Experimental

The `http2` module provides an implementation of the [HTTP/2][] protocol. It
can be accessed using:

```js
const http2 = require('http2');
```

## Core API

The Core API provides a low-level interface designed specifically around
support for HTTP/2 protocol features. It is specifically *not* designed for
compatibility with the existing [HTTP/1][] module API.

The following illustrates a simple, plain-text HTTP/2 server:

```js
const http2 = require('http2');

// Create a plain-text HTTP/2 server
const server = http2.createServer();

server.on('stream', (stream, headers) => {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('<h1>Hello World</h1>');
});

server.listen(80);
```

The following illustrates an HTTP/2 client:

```js
const http2 = require('http2');

const client = http2.connect('http://localhost:80');

const req = client.request({ ':path': '/'});

req.on('response', (headers) => {
  console.log(headers[':status']);
  console.log(headers['date']);
});

let data = '';
req.setEncoding('utf8');
req.on('data', (d) => data += d);
req.on('end', () => client.destroy());
req.end();
```

### Class: Http2Session

* Extends: {EventEmitter}

Instances of the `http2.Http2Session` class represent an active communications
session between an HTTP/2 client and server. Instances of this class are *not*
intended to be constructed directly by user code.

Every `Http2Session` instance is associated with exactly one [`net.Socket`][] or
[`tls.TLSSocket`][] when it is created. When either the `Socket` or the
`Http2Session` are destroyed, both will be destroyed.

Each `Http2Session` instance will exhibit slightly different behaviors
depending on whether it is operating as a server or a client. The
`http2session.type` property can be used to determine the mode in which an
`Http2Session` is operating. On the server side, user code should rarely
have occasion to work with the `Http2Session` object directly, with most
actions typically taken through interactions with either the `Http2Server` or
`Http2Stream` objects.

#### Event: 'close'

The `'close'` event is emitted once the `Http2Session` has been terminated.

#### Event: 'connect'

The `'connect'` event is emitted once the `Http2Session` has been successfully
connected to the remote peer and communication may begin.

*Note*: User code will typically not listen for this event directly.

#### Event: 'error'

(TODO: fill in detail)

#### Event: 'selectPadding'

(TODO: fill in detail)

#### Event: 'stream'

The `'stream'` event is emitted when a new `Http2Stream` is created. When
invoked, the handler function will receive a reference to the `Http2Stream`
object, a [Headers Object][], and numeric flags associated with the creation
of the stream.

```js
session.on('stream', (stream, headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

*Note*: User code will typically not listen for this event directly, and would
instead register a handler for the `'stream'` event emitted by the `net.Server`
or `tls.Server` instances returned by `http2.createServer()` and
`http2.createSecureServer()`, respectively, as in the example below:

```js
const http2 = require('http2');

// Create a plain-text HTTP/2 server
const server = http2.createServer();

server.on('stream', (stream, headers) => {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('<h1>Hello World</h1>');
});

server.listen(80);
```

#### Event: 'streamError'

The `'streamError'` event is emitted when an `'error'` event on an `Http2Stream`
is not handled by a listener on the `Http2Stream` object. If a listener is not
registered for this event, an `'error'` event will be emitted.

#### Event: 'timeout'

(TODO: fill in detail)

#### http2session.destroy()

Immediately terminates the `Http2Session` and the associated `net.Socket` or
`tls.TLSSocket`.

#### http2session.destroyed

* Value: {boolean}

Will be `true` if this `Http2Session` instance has been destroyed and must no
longer be used, otherwise `false`.

#### http2session.localSettings

* Value: {[Settings Object][]}

An object describing the current local settings of this `Http2Session`.
(TODO: fill in detail)

#### http2session.remoteSettings

* Value: {[Settings Object][]}

An object describing the current remote settings of this `Http2Session`.
(TODO: fill in detail)

#### http2session.request(headers[, options])

* `headers` {[Headers Object][]}
* `options` {Object}
  * `endStream` {boolean} `true` if the `Http2Stream` *writable* side should
    be closed initially, such as when sending a `GET` request that should not
    expect a payload body.
  * `exclusive` {boolean} (TODO: fill in detail)
  * `parent` {number} (TODO: fill in detail)
  * `weight` {number} (TODO: fill in detail)

For HTTP/2 Client `Http2Session` instances only, the `http2session.request()`
creates and returns an `Http2Stream` instance that can be used to send an
HTTP/2 request to the connected server.

This method is only available if `http2session.type` is equal to
`http2.constants.NGHTTP2_SESSION_CLIENT`.

(TODO: fill in detail)

#### http2session.rstStream(stream, code)

* stream {Http2Stream}
* code {number}

Sends an `RST-STREAM` frame to the connected HTTP/2 peer, causing the given
`Http2Stream` to be closed on both sides using error code `code`.

#### http2session.setTimeout(msecs, callback)

* `msecs` {number}
* `callback` {Function}

(TODO: fill in detail)

#### http2session.shutdown(options[, callback])

* `options` {Object}
  * `graceful` {boolean} `true` to attempt a polite shutdown of the
    `Http2Session`.
  * `immediate` {boolean} `true` to force the shutdown to occur immediately,
    regardless of any data transfer that may be pending.
  * `errorCode` {number} The HTTP/2 Error Code to return. Note that this is
    *not* the same thing as an HTTP Response Status Code.
  * `lastStreamID` {number} The Stream ID of the last successfully processed
    `Http2Stream` on this `Http2Session`.
  * `opaqueData` {Buffer} A `Buffer` instance containing arbitrary additional
    data to send to the peer upon disconnection. This is used, typically, to
    provide additional data for debugging failures, if necessary.
* `callback` {Function}

Attempts to shutdown this `Http2Session` using HTTP/2 defined procedures.
If specified, the given `callback` function will be invoked once the shutdown
process has completed.

#### http2session.socket

* Value: {net.Socket|tls.TLSSocket}

A reference to the [`net.Socket`][] or [`tls.TLSSocket`][] to which this
`Http2Session` instance is bound.

#### http2session.state

* Value: {Object}
  * `effectiveLocalWindowSize` {number}
  * `effectiveRecvDataLength` {number}
  * `nextStreamID` {number}
  * `localWindowSize` {number}
  * `lastProcStreamID` {number}
  * `remoteWindowSize` {number}
  * `outboundQueueSize` {number}
  * `deflateDynamicTableSize` {number}
  * `inflateDynamicTableSize` {number}

An object describing the current status of this `Http2Session`.

#### http2session.submitPriority(stream, options)

* `stream` {Http2Stream}
* `options` {Object}
  * `exclusive` {boolean} (TODO: fill in detail)
  * `parent` {number} (TODO: fill in detail)
  * `weight` {number} (TODO: fill in detail)

Updates the priority for the given `Http2Stream` instance. If `options.silent`
is `false`, causes a new `PRIORITY` frame to be sent to the connected HTTP/2
peer.

#### http2session.submitSettings(settings)

* `settings` {[Settings Object][]}
* Returns {undefined}

Updates the current local settings for this `Http2Session` and sends a new
`SETTINGS` frame to the connected HTTP/2 peer.

#### http2session.type

* Value: {number}

The `http2session.type` will be equal to
`http2.constants.NGHTTP2_SESSION_SERVER` if this `Http2Session` instance is a
server, and `http2.constants.NGHTTP2_SESSION_CLIENT` if the instance is a
client.

### Class: Http2Stream

* Extends: {Duplex}

Each instance of the `Http2Stream` class represents a bidirectional HTTP/2
communications stream over an `Http2Session` instance. Any single `Http2Session`
may have up to 2<sup>31</sup>-1 `Http2Stream` instances over its lifetime.

User code will not construct `Http2Stream` instances directly. Rather, these
are created, managed, and provided to user code through the `Http2Session`
instance. On the server, `Http2Stream` instances are created either in response
to an incoming HTTP request (and handed off to user code via the `'stream'`
event), or in response to a call to the `http2stream.pushStream()` method.
On the client, `Http2Stream` instances are created and returned when either the
`http2session.request()` method is called, or in response to an incoming
`'push'` event.

#### Event: 'aborted'

The `'aborted'` event is emitted whenever a `Http2Stream` instance is
abnormally aborted in mid-communication.

#### Event: 'error'

(TODO: fill in detail)

#### Event: 'fetchTrailers'

The `'fetchTrailers`' event is emitted by the `Http2Stream` immediately after
queuing the last chunk of payload data to be sent. The listener callback is
passed a single object (with a `null` prototype) that the listener may used
to specify the trailing header fields to send to the peer.

```js
stream.on('fetchTrailers', (trailers) => {
  trailers['ABC'] = 'some value to send';
});
```

#### Event: 'headers'

The `'headers'` event is emitted when a block of headers has been received
on the `Http2Stream`, and the block does not correspond with an HTTP request,
response or push request. The listener callback is passed the [Headers Object][]
and flags associated with the headers.

```js
stream.on('headers', (headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

#### Event: 'push'

The `'push'` event is emitted when response headers for a Server Push stream
are received. The listener callback is passed the [Headers Object][] and flags
associated with the headers.

```js
stream.on('push', (headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

#### Event: 'request'

The `'request'` event is emitted when a block of headers associated with an
HTTP request is received. The listener callback is passed the [Headers Object][]
and flags associated with the headers.

```js
stream.on('request', (headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

This is emitted only when `http2session.type` is equal to
`http2.constants.NGHTTP_SESSION_SERVER`.

#### Event: 'response'

The `'response'` event is emitted when a block of headers associated with an
HTTP response is received. The listener callback is passed the
[Headers Object][] and flags associated with the headers.

```js
stream.on('response', (headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

This is emitted only when `http2session.type` is equal to
`http2.constants.NGHTTP_SESSION_CLIENT`.

#### Event: 'streamClosed'

The `'streamClosed'` event is emitted when the `Http2Stream` is closed.

#### Event: 'timeout'

(TODO: fill in detail)

#### Event: 'trailers'

The `'trailers'` event is emitted when a block of headers associated with
trailing header fields is received. The listener callback is passed the
[Headers Object][] and flags associated with the headers.

```js
stream.on('trailers', (headers, flags) => {
  // TODO(jasnell): Fill in example
});
```

#### http2stream.priority(options)

* `options` {Object}
  * `exclusive` {boolean} (TODO: fill in detail)
  * `parent` {number} (TODO: fill in detail)
  * `weight` {number} (TODO: fill in detail)

Updates the priority for this `Http2Stream` instance. If `options.silent`
is `false`, causes a new `PRIORITY` frame to be sent to the connected HTTP/2
peer.

#### http2stream.rstStream(code)

* `code` {number}

Sends an `RST-STREAM` frame to the connected HTTP/2 peer, causing this
`Http2Stream` to be closed on both sides using error code `code`.

#### http2stream.rstWithNoError()

Shortcut for `http2stream.rstStream()` using error code `NO_ERROR`.

#### http2stream.rstWithProtocolError() {

Shortcut for `http2stream.rstStream()` using error code `PROTOCOL_ERROR`.

#### http2stream.rstWithCancel() {

Shortcut for `http2stream.rstStream()` using error code `CANCEL`.

#### http2stream.rstWithRefuse() {

Shortcut for `http2stream.rstStream()` using error code `REFUSED_STREAM`.

#### http2stream.rstWithInternalError() {

Shortcut for `http2stream.rstStream()` using error code `INTERNAL_ERROR`.

#### http2stream.sendHeaders(headers)

* `headers` {[Headers Object][]}

Sends a `HEADERS` frame to the connected HTTP/2 peer.
(TODO: fill in detail)

#### http2stream.session

* Value: {Http2Sesssion}

A reference to the `Http2Session` instance that owns this `Http2Stream`.

#### http2stream.setTimeout(msecs, callback)

* `msecs` {number}
* `callback` {Function}

(TODO: fill in detail)

#### http2stream.state

* Value: {Object}
  * `localWindowSize` {number}
  * `state` {number}
  * `streamLocalClose` {number}
  * `streamRemoteClose` {number}
  * `sumDependencyWeight` {number}
  * `weight` {number}

A current state of this `Http2Stream`.

### Class: ServerHttp2Stream

* Extends: {Http2Stream}

#### http2stream.pushStream(headers[, options], callback)

* `headers` {[Headers Object][]}
* `options` {Object}
  * `exclusive` {boolean} (TODO: fill in detail)
  * `parent` {number} (TODO: fill in detail)
  * `weight` {number} (TODO: fill in detail)
* `callback` {Function}

Initiates a push stream.
(TODO: fill in detail)

#### http2stream.respond([headers[, options]])

* `headers` {[Headers Object][]}
* `options` {Object}

Initiates a response.
(TODO: fill in detail)

### Class: Http2Server

* Extends: {net.Server}

#### Event: 'selectPadding'

The `'selectPadding'` event is emitted when a `'selectPadding'` event is
emitted by an `'Http2Session`' object associated with the server.

#### Event: 'sessionError'

The `'sessionError'` event is emitted when an `'error'` event is emitted by
an `Http2Session` object. If no listener is registered for this event, an
`'error'` event is emitted.

#### Event: 'socketError'

The `'socketError`' event is emitted when an `'error'` event is emitted by
a `Socket` associated with the server. If no listener is registered for this
event, an `'error'` event is emitted.

#### Event: 'stream'

The `'stream'` event is emitted when a `'stream'` event has been emitted by
an `Http2Session` associated with the server.

#### Event: 'timeout'

(TODO: fill in detail)

### Class: Http2SecureServer

* Extends: {tls.Server}

#### Event: 'selectPadding'

The `'selectPadding'` event is emitted when a `'selectPadding'` event is
emitted by an `'Http2Session`' object associated with the server.

#### Event: 'sessionError'

The `'sessionError'` event is emitted when an `'error'` event is emitted by
an `Http2Session` object. If no listener is registered for this event, an
`'error'` event is emitted.

#### Event: 'socketError'

The `'socketError`' event is emitted when an `'error'` event is emitted by
a `Socket` associated with the server. If no listener is registered for this
event, an `'error'` event is emitted.

#### Event: 'stream'

The `'stream'` event is emitted when a `'stream'` event has been emitted by
an `Http2Session` associated with the server.

#### Event: 'timeout'

(TODO: fill in detail)

### http2.getDefaultSettings()

* Returns: {[Settings Object][]}

Returns an object containing the default settings for an `Http2Session`
instance. This method returns a new object instance every time it is called
so instances returned may be safely modified for use.

### http2.getPackedSettings(settings)

* `settings` {[Settings Object][]}
* Returns: {Buffer}

Returns a [Buffer][] instance containing serialized representation of the given
HTTP/2 settings as specified in the [HTTP/2][] specification. This is intended
for use with the `HTTP2-Settings` header field.

```js
const http2 = require('http2');

const packed = http2.getPackedSettings({ enablePush: false });

console.log(packed.toString('base64'));
// Prints: AAIAAAAA
```

### http2.createServer(options[, onRequestHandler])

* `options` {Object}
* `options` {Object}
  * `maxDefaultDynamicTableSize` {number} (TODO: Add detail)
  * `maxReservedRemoteStreams` {number} (TODO: Add detail)
  * `maxSendHeaderBlockLength` {number} (TODO: Add detail)
  * `noHttpMessaging` {boolean} (TODO: Add detail)
  * `noRecvClientMagic` {boolean} (TODO: Add detail)
  * `paddingStrategy` {number} (TODO: Add detail)
  * `peerMaxConcurrentStreams` {number} (TODO: Add detail)
  * `settings` {[Settings Object][]} The initial settings to send to the
    remote peer upon connection.
* `onRequestHandler` {Function} See [Compatibility API][]
* Returns: `http2.Http2Server`

Returns a `net.Server` instance that creates and manages `Http2Session`
instances.

```js
const http2 = require('http2');

// Create a plain-text HTTP/2 server
const server = http2.createServer();

server.on('stream', (stream, headers) => {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('<h1>Hello World</h1>');
});

server.listen(80);
```

### http2.createSecureServer(options[, onRequestHandler])

* `options` {Object}
  * `maxDefaultDynamicTableSize` {number} (TODO: Add detail)
  * `maxReservedRemoteStreams` {number} (TODO: Add detail)
  * `maxSendHeaderBlockLength` {number} (TODO: Add detail)
  * `noHttpMessaging` {boolean} (TODO: Add detail)
  * `noRecvClientMagic` {boolean} (TODO: Add detail)
  * `paddingStrategy` {number} (TODO: Add detail)
  * `peerMaxConcurrentStreams` {number} (TODO: Add detail)
  * `allowHTTP1` {boolean} Incoming client connections that do not support
    HTTP/2 will be downgraded to HTTP/1.x when set to `true`. The default value
    is `false`, which rejects non-HTTP/2 client connections.
  * `settings` {[Settings Object][]} The initial settings to send to the
    remote peer upon connection.
  * ...: Any [`tls.createServer()`][] options can be provided. For
    servers, the identity options (`pfx` or `key`/`cert`) are usually required.
* `onRequestHandler` {Function} See [Compatibility API][]
* Returns `http2.Http2SecureServer`

Returns a `tls.Server` instance that creates and manages `Http2Session`
instances.

```js
const http2 = require('http2');

const options = {
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem')
};

// Create a plain-text HTTP/2 server
const server = http2.createSecureServer(options);

server.on('stream', (stream, headers) => {
  stream.respond({
    'content-type': 'text/html',
    ':status': 200
  });
  stream.end('<h1>Hello World</h1>');
});

server.listen(80);
```

### http2.connect(authority, options, listener)

* Returns `Http2Session`

Returns a HTTP/2 client `Http2Session` instance.
(TODO: fill in detail)

### http2.constants

(TODO: Fill in details)

### Headers Object

Headers are represented as own-properties on JavaScript objects. The property
keys will be serialized to lower-case. Property values should be strings (if
they are not they will be coerced to strings) or an Array of strings (in order
to send more than one value per header field).

For example:

```js
const headers = {
  ':status': '200',
  'content-type': 'text-plain',
  'ABC': ['has', 'more', 'than', 'one', 'value']
};

stream.respond(headers);
```

*Note*: Header objects passed to callback functions will have a `null`
prototype. This means that normal JavaScript object methods such as
`Object.prototype.toString()` and `Object.prototype.hasOwnProperty()` will
not work.

(TODO: Fill in more detail)

### Settings Object

The `http2.getDefaultSettings()`, `http2.getPackedSettings()`,
`http2.createServer()`, `http2.createSecureServer()`,
`http2session.submitSettings()`, `http2session.localSettings`, and
`http2session.remoteSettings` APIs either return or receive as input an
object that defines configuration settings for an `Http2Session` object.
These objects are ordinary JavaScript objects containing the following
properties.

* `headerTableSize` {number} Specifies the maximum number of bytes used for
  header compression. The default value is 4,096 octets. The minimum allowed
  value is 0. The maximum allowed value is 2<sup>32</sup>-1.
* `enablePush` {boolean} Specifies `true` if HTTP/2 Push Streams are to be
  permitted on the `Http2Session` instances.
* `initialWindowSize` {number} Specifies the *senders* initial window size
  for stream-level flow control. The default value is 65,535 bytes. The minimum
  allowed value is 0. The maximum allowed value is 2<sup>32</sup>-1.
* `maxFrameSize` {number} Specifies the size of the largest frame payload.
  The default and the minimum allowed value is 16,384 bytes. The maximum
  allowed value is 2<sup>24</sup>-1.
* `maxConcurrentStreams` {number} Specifies the maximum number of concurrent
  streams permitted on an `Http2Session`. There is no default value which
  implies, at least theoretically, 2<sup>31</sup>-1 streams may be open
  concurrently at any given time in an `Http2Session`. The minimum value is
  0. The maximum allowed value is 2<sup>31</sup>-1.
* `maxHeaderListSize` {number} Specifies the maximum size (uncompressed octets)
  of header list that will be accepted. There is no default value. The minimum
  allowed value is 0. The maximum allowed value is 2<sup>32</sup>-1.

All additional properties on the settings object are ignored.

## Compatibility API

TBD


[HTTP/2]: https://tools.ietf.org/html/rfc7540
[HTTP/1]: http.html
[`net.Socket`]: net.html
[`tls.TLSSocket`]: tls.html
[`tls.createServer()`]: tls.html#tls_tls_createserver_options_secureconnectionlistener
[Compatibility API: #http2_compatibility_api
[Headers Object]: #http2_headers_object
[Settings Object]: #http2_settings_object
