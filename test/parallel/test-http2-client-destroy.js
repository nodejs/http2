'use strict';

const common = require('../common');
const assert = require('assert');
const h2 = require('http2');

const server = h2.createServer();
server.listen(0);

server.on('listening', common.mustCall(function() {
  const port = this.address().port;

  const destroyCallbacks = [
    (client) => client.destroy(),
    (client) => client.socket.destroy()
  ];

  let remaining = destroyCallbacks.length;

  destroyCallbacks.forEach((destroyCallback) => {
    const client = h2.connect(`http://localhost:${port}`);
    client.on('connect', common.mustCall(() => {
      const socket = client.socket;

      assert(client.socket, 'client session has associated socket');
      assert(!client.destroyed,
             'client has not been destroyed before destroy is called');
      assert(!socket.destroyed,
             'socket has not been destroyed before destroy is called');

      // Ensure that 'close' event is emitted
      client.on('close', common.mustCall(() => {}));

      destroyCallback(client);

      assert(!client.socket, 'client.socket undefined after destroy is called');
      assert(client.destroyed,
             'client marked as destroyed after destroy is called');
      assert(socket.destroyed,
             'socket marked as destroyed after destroy is called');

      if (--remaining === 0) {
        server.close();
      }
    }));
  });
}));
