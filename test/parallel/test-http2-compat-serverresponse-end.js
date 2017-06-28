// Flags: --expose-http2
'use strict';

const { throws } = require('assert');
const { mustCall } = require('../common');
const { createServer, connect } = require('http2');

// Http2ServerResponse should throw when writing if the stream is closed

const server = createServer();
server.listen(0, mustCall(() => {
  const port = server.address().port;
  server.once('request', mustCall((request, response) => {
    response.stream.on('finish', mustCall(() => {
      throws(
        () => { response.writeHead(200); },
        /The stream is already closed/
      );
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
