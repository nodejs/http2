// Flags: --expose-http2
'use strict';

const { mustCall, expectsError } = require('../common');
const { createServer, connect } = require('http2');

// Http2ServerResponse should throw when writing if the stream is closed

const server = createServer();
server.listen(0, mustCall(() => {
  const port = server.address().port;
  server.once('request', mustCall((request, response) => {
    response.stream.on('finish', mustCall(() => {
      try {
        response.writeHead(200);
        throw new Error();
      } catch (error) {
        const code = 'ERR_HTTP2_STREAM_CLOSED';
        const message = 'The stream is already closed';
        expectsError({code, message})(error);
      }
      server.close();
    }));
    response.end();
  }));

  const url = `http://localhost:${port}`;
  const client = connect(url, mustCall(() => {
    const headers = {
      ':path': '/',
      ':method': 'GET',
      ':scheme': 'http',
      ':authority': `localhost:${port}`
    };
    const request = client.request(headers);
    request.on('end', mustCall(() => {
      client.destroy();
    }));
    request.end();
    request.resume();
  }));
}));
