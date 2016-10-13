'use strict';

const core = require('internal/http2/core');
//const compat = require('internal/http2/compat');

// Exports
module.exports = {
  constants: core.constants,
  getDefaultSettings: core.getDefaultSettings,
  getPackedSettings: core.getPackedSettings,
  createServer: core.createServer,
  createSecureServer: core.createSecureServer,
  createServerSession: core.createServerSession,
  connect: core.connect,
  secureConnect: core.secureConnect
};
