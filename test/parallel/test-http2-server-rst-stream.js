'use strict';

const common = require('../common');
const assert = require('assert');
const http2 = require('http2');

function checkRstCode(rstMethod, expectRstCode) {
  const server = http2.createServer();
  server.on('stream', (stream, headers, flags) => {
    stream.respond({
      'content-type': 'text/html',
      ':status': 200
    });
    stream.end('test');
    stream[rstMethod]();
  });

  server.listen(0, common.mustCall(() => {
    const port = server.address().port;
    const client = http2.connect(`http://localhost:${port}`);

    const headers = { ':path': '/' };
    const req = client.request(headers);

    req.setEncoding('utf8');
    req.on('streamClosed', common.mustCall(function(actualRstCode) {
      assert.strictEqual(
        expectRstCode, actualRstCode, `${rstMethod} is not match rstCode`);
      server.close();
      client.destroy();
    }));
    req.on('data', common.mustNotCall(() => {}));
    req.on('end', common.mustCall(() => {}));
    req.end();
  }));
}

const {
  NGHTTP2_CANCEL, NGHTTP2_NO_ERROR, NGHTTP2_PROTOCOL_ERROR,
  NGHTTP2_REFUSED_STREAM, NGHTTP2_INTERNAL_ERROR
} = http2.constants;

checkRstCode('rstStream', NGHTTP2_NO_ERROR);
checkRstCode('rstWithNoError', NGHTTP2_NO_ERROR);
checkRstCode('rstWithProtocolError', NGHTTP2_PROTOCOL_ERROR);
checkRstCode('rstWithCancel', NGHTTP2_CANCEL);
checkRstCode('rstWithRefuse', NGHTTP2_REFUSED_STREAM);
checkRstCode('rstWithInternalError', NGHTTP2_INTERNAL_ERROR);
