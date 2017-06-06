'use strict';

const common = require('../common');
const h2 = require('http2');

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustCall((stream) => {
  stream.respond({ ':status': 200 });

  // The first pushStream will complete as normal
  stream.pushStream({
    ':scheme': 'http',
    ':path': '/foobar',
    ':authority': `localhost:${server.address().port}`,
  }, common.mustCall((pushedStream) => {
    pushedStream.respond({ ':status': 200 });
    pushedStream.end();
    pushedStream.on('aborted', common.mustNotCall());
  }));

  // The second pushStream will be aborted because the client
  // will reject it due to the maxReservedRemoteStreams option
  // being set to only 1
  stream.pushStream({
    ':scheme': 'http',
    ':path': '/foobar',
    ':authority': `localhost:${server.address().port}`,
  }, common.mustCall((pushedStream) => {
    pushedStream.respond({ ':status': 200 });
    pushedStream.on('aborted', common.mustCall());
  }));

  stream.end('hello world');
}));
server.listen(0);

server.on('listening', common.mustCall(() => {

  // Setting the maxSendHeaderBlockLength, then attempting to send a
  // headers block that is too big should cause a 'frameError' to
  // be emitted, and will cause the stream to be shutdown automatically
  // without the js layer being notified at all.
  const options = {
    maxReservedRemoteStreams: 1
  };

  const client = h2.connect(`http://localhost:${server.address().port}`,
                            options);

  const req = client.request({ ':path': '/' });

  // Because maxReservedRemoteStream is 1, the stream event
  // must only be emitted once, even tho the server sends
  // two push streams.
  client.on('stream', common.mustCall((stream) => {
    stream.resume();
    stream.on('end', common.mustCall());
  }));

  req.on('response', common.mustCall());

  req.resume();
  req.on('end', common.mustCall(() => {
    server.close();
    client.destroy();
  }));
  req.end();

}));
