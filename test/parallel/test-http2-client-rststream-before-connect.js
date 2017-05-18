'use strict';

const common = require('../common');
const h2 = require('http2');

const server = h2.createServer();

// we use the lower-level API here
server.on('stream', common.mustNotCall());

server.listen(0);

server.on('listening', common.mustCall(() => {

  const client = h2.connect(`http://localhost:${server.address().port}`);

  const req = client.request({ ':path': '/' });
  client.rstStream(req, 0);

  req.on('response', common.mustNotCall());
  req.resume();
  req.on('end', common.mustCall(() => {
    server.close();
    client.destroy();
  }));
  req.end();

}));
