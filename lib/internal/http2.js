'use strict';

const http2 = process.binding('http2');

exports.HTTP2Session = http2.Http2Session;
