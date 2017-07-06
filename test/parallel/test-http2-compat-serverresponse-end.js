// Flags: --expose-http2
'use strict';

const { mustCall, mustNotCall } = require('../common');
const { createServer, connect } = require('http2');

// Http2ServerResponse.end

{
  const server = createServer(mustCall((request, response) => {
    response.end(mustCall(() => {
      server.close();
    }));
    response.end(mustNotCall());
  }));
  server.listen(0, mustCall(() => {
    const {port} = server.address();
    const url = `http://localhost:${port}`;
    const client = connect(url, mustCall(() => {
      const headers = {
        ':path': '/',
        ':method': 'GET',
        ':scheme': 'http',
        ':authority': `localhost:${port}`
      };
      const request = client.request(headers);
      request.on('data', mustNotCall());
      request.on('end', mustCall(() => client.destroy()));
      request.end();
      request.resume();
    }));
  }));
}
