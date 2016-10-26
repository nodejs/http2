'use strict';

require('../common');
const assert = require('assert');
const HTTP2 = require('http').HTTP2;

const settings = new HTTP2.Http2Settings();
assert(settings);
assert.strictEqual(settings.maxHeaderListSize, undefined);
assert.strictEqual(settings.maxFrameSize, undefined);
assert.strictEqual(settings.initialWindowSize, undefined);
assert.strictEqual(settings.maxConcurrentStreams, undefined);
assert.strictEqual(settings.enablePush, undefined);
assert.strictEqual(settings.headerTableSize, undefined);

// Verify value is unsigned
settings.maxHeaderListSize = -1;
assert.strictEqual(settings.maxHeaderListSize, 4294967295);
// Verify value cannot be deleted
assert.throws(() => delete settings.maxHeaderListSize);
// Verify value can be unset using undefined
settings.maxHeaderListSize = undefined;
assert.strictEqual(settings.maxHeaderListSize, undefined);

// Verify value is unsigned and cannot exceed the maximum frame size
const MAX_FRAME_SIZE = 16777215;
const MIN_FRAME_SIZE = 16384;
settings.maxFrameSize = -1;
assert.strictEqual(settings.maxFrameSize, MAX_FRAME_SIZE);
// Verify value cannot be below the minimum max frame size
settings.maxFrameSize = 1;
assert.strictEqual(settings.maxFrameSize, MIN_FRAME_SIZE);
// Verify value cannot be deleted
assert.throws(() => delete settings.maxFrameSize);
// Verify value can be unset using undefined
settings.maxFrameSize = undefined;
assert.strictEqual(settings.maxFrameSize, undefined);

// Verify value is unsigned and cannot exceed maximum initial window size
const MAX_INITIAL_WINDOW_SIZE = 2147483647;
settings.initialWindowSize = -1;
assert.strictEqual(settings.initialWindowSize, MAX_INITIAL_WINDOW_SIZE);
// Verify value cannot be deleted
assert.throws(() => delete settings.initialWindowSize);
// Verify value can be unset using undefined
settings.initialWindowSize = undefined;
assert.strictEqual(settings.initialWindowSize, undefined);

// Verify value is unsigned
settings.maxConcurrentStreams = -1;
assert.strictEqual(settings.maxConcurrentStreams, 4294967295);
// Verify value cannot be deleted
assert.throws(() => delete settings.maxConcurrentStreams);
// Verify value can be unset using undefined
settings.maxConcurrentStreams = undefined;
assert.strictEqual(settings.maxConcurrentStreams, undefined);

// Verify value is unsigned
settings.headerTableSize = -1;
assert.strictEqual(settings.headerTableSize, 4294967295);
// Verify value cannot be deleted
assert.throws(() => delete settings.headerTableSize);
// Verify value can be unset using undefined
settings.headerTableSize = undefined;
assert.strictEqual(settings.headerTableSize, undefined);

// Verify value is boolean
settings.enablePush = 1;
assert.strictEqual(settings.enablePush, true);
settings.enablePush = 0;
assert.strictEqual(settings.enablePush, false);
// Verify value cannot be deleted
assert.throws(() => delete settings.enablePush);
// Verify value can be unset using undefined
settings.enablePush = undefined;
assert.strictEqual(settings.enablePush, undefined);

settings.reset();
assert.strictEqual(settings.maxHeaderListSize, undefined);
assert.strictEqual(settings.maxFrameSize, undefined);
assert.strictEqual(settings.initialWindowSize, undefined);
assert.strictEqual(settings.maxConcurrentStreams, undefined);
assert.strictEqual(settings.enablePush, undefined);
assert.strictEqual(settings.headerTableSize, undefined);

settings.setDefaults();
assert.strictEqual(settings.maxHeaderListSize, undefined);
assert.strictEqual(settings.maxFrameSize, 16384);
assert.strictEqual(settings.initialWindowSize, 65535);
assert.strictEqual(settings.maxConcurrentStreams, undefined);
assert.strictEqual(settings.enablePush, true);
assert.strictEqual(settings.headerTableSize, 4096);

// The pack() method returns a buffer that can be used to
// serialize the settings for the HTTP2-Settings HTTP/1 header.
const packed = 'AAEAABAAAAIAAAABAAQAAP//AAUAAEAA';
const packedSettings = settings.pack();
assert(packedSettings);
assert.strictEqual(packedSettings.length, 24);
assert.strictEqual(packedSettings.toString('base64'), packed);
