'use strict';

const binding = process.binding('http2');
const errors = require('internal/errors');

// The following ArrayBuffer instances are used to share memory more efficiently
// with the native binding side for a number of methods. These are not intended
// to be used directly by users in any way. The ArrayBuffers are created on
// the native side with values that are filled in on demand, the js code then
// reads those values out. The set of IDX constants that follow identify the
// relevant data positions within these buffers.
const defaultSettings = new Uint32Array(binding.defaultSettingsArrayBuffer);
const settingsBuffer = new Uint32Array(binding.settingsArrayBuffer);

// Note that Float64Array is used here because there is no Int64Array available
// and these deal with numbers that can be beyond the range of Uint32 and Int32.
// The values set on the native side will always be integers. This is not a
// unique example of this, this pattern can be found in use in other parts of
// Node.js core as a performance optimization.
const sessionState = new Float64Array(binding.sessionStateArrayBuffer);
const streamState = new Float64Array(binding.streamStateArrayBuffer);

const IDX_SETTINGS_HEADER_TABLE_SIZE = 0;
const IDX_SETTINGS_ENABLE_PUSH = 1;
const IDX_SETTINGS_INITIAL_WINDOW_SIZE = 2;
const IDX_SETTINGS_MAX_FRAME_SIZE = 3;
const IDX_SETTINGS_MAX_CONCURRENT_STREAMS = 4;
const IDX_SETTINGS_MAX_HEADER_LIST_SIZE = 5;

const IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE = 0;
const IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH = 1;
const IDX_SESSION_STATE_NEXT_STREAM_ID = 2;
const IDX_SESSION_STATE_LOCAL_WINDOW_SIZE = 3;
const IDX_SESSION_STATE_LAST_PROC_STREAM_ID = 4;
const IDX_SESSION_STATE_REMOTE_WINDOW_SIZE = 5;
const IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE = 6;
const IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE = 7;
const IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE = 8;
const IDX_STREAM_STATE = 0;
const IDX_STREAM_STATE_WEIGHT = 1;
const IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT = 2;
const IDX_STREAM_STATE_LOCAL_CLOSE = 3;
const IDX_STREAM_STATE_REMOTE_CLOSE = 4;
const IDX_STREAM_STATE_LOCAL_WINDOW_SIZE = 5;

binding.refreshDefaultSettings();

function getDefaultSettings() {
  const holder = Object.create(null);
  holder.headerTableSize =
    defaultSettings[IDX_SETTINGS_HEADER_TABLE_SIZE];
  holder.enablePush =
    !!defaultSettings[IDX_SETTINGS_ENABLE_PUSH];
  holder.initialWindowSize =
    defaultSettings[IDX_SETTINGS_INITIAL_WINDOW_SIZE];
  holder.maxFrameSize =
    defaultSettings[IDX_SETTINGS_MAX_FRAME_SIZE];
  return holder;
}

// remote is a boolean. true to fetch remote settings, false to fetch local.
// this is only called internally
function getSettings(session, remote) {
  const holder = Object.create(null);
  if (remote)
    binding.refreshRemoteSettings(session);
  else
    binding.refreshLocalSettings(session);

  holder.headerTableSize =
    settingsBuffer[IDX_SETTINGS_HEADER_TABLE_SIZE];
  holder.enablePush =
    !!settingsBuffer[IDX_SETTINGS_ENABLE_PUSH];
  holder.initialWindowSize =
    settingsBuffer[IDX_SETTINGS_INITIAL_WINDOW_SIZE];
  holder.maxFrameSize =
    settingsBuffer[IDX_SETTINGS_MAX_FRAME_SIZE];
  holder.maxConcurrentStreams =
    settingsBuffer[IDX_SETTINGS_MAX_CONCURRENT_STREAMS];
  holder.maxHeaderListSize =
    settingsBuffer[IDX_SETTINGS_MAX_HEADER_LIST_SIZE];
  return holder;
}

function getSessionState(session) {
  const holder = Object.create(null);
  binding.refreshSessionState(session);
  holder.effectiveLocalWindowSize =
    sessionState[IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE];
  holder.effectiveRecvDataLength =
    sessionState[IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH];
  holder.nextStreamID =
    sessionState[IDX_SESSION_STATE_NEXT_STREAM_ID];
  holder.localWindowSize =
    sessionState[IDX_SESSION_STATE_LOCAL_WINDOW_SIZE];
  holder.lastProcStreamID =
    sessionState[IDX_SESSION_STATE_LAST_PROC_STREAM_ID];
  holder.remoteWindowSize =
    sessionState[IDX_SESSION_STATE_REMOTE_WINDOW_SIZE];
  holder.outboundQueueSize =
    sessionState[IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE];
  holder.deflateDynamicTableSize =
    sessionState[IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE];
  holder.inflateDynamicTableSize =
    sessionState[IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE];
  return holder;
}

function getStreamState(session, stream) {
  const holder = Object.create(null);
  binding.refreshStreamState(session, stream);
  holder.state =
    streamState[IDX_STREAM_STATE];
  holder.weight =
    streamState[IDX_STREAM_STATE_WEIGHT];
  holder.sumDependencyWeight =
    streamState[IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT];
  holder.localClose =
    streamState[IDX_STREAM_STATE_LOCAL_CLOSE];
  holder.remoteClose =
    streamState[IDX_STREAM_STATE_REMOTE_CLOSE];
  holder.localWindowSize =
    streamState[IDX_STREAM_STATE_LOCAL_WINDOW_SIZE];
  return holder;
}

function isIllegalConnectionSpecificHeader(name, value) {
  switch (name) {
    case 'connection':
    case 'upgrade':
    case 'http2-settings':
      return true;
    case 'te':
      return value !== 'trailers';
    default:
      return false;
  }
}

function assertIllegalConnectionSpecificHeader(name, value, ctor) {
  if (isIllegalConnectionSpecificHeader(name, value)) {
    var err = new errors.Error('ERR_HTTP2_INVALID_CONNECTION_HEADERS');
    Error.captureStackTrace(err, ctor);
    throw err;
  }
}

function mapToHeaders(map) {
  var ret = [];
  var keys = Object.keys(map);
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var value = map[key];
    var val;
    if (typeof key === 'symbol' || value === undefined || !key)
      continue;
    var isArray = Array.isArray(value);
    if (key[0] === ':') {
      if (isArray) {
        if (value.length > 1)
          throw new errors.Error('ERR_HTTP2_PSEUDO_HEADERS_SINGLE_VALUE');
        value = value[0];
      }
      val = String(value);
      assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
      ret.unshift([key, val]);
    } else {
      if (isArray) {
        for (var k = 0; k < value.length; k++) {
          val = String(value[k]);
          assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
          ret.push([key, val]);
        }
      } else {
        val = String(value);
        assertIllegalConnectionSpecificHeader(key, val, mapToHeaders);
        ret.push([key, val]);
      }
    }
  }

  return ret;
}

function emitErrorIfNecessary(emitter, ret) {
  if (ret < 0) {
    const err = new Error(binding.nghttp2ErrorString(ret));
    err.code = 'ERR_HTTP2_ERROR';
    err.name = 'Name [ERR_HTTP2_ERROR]';
    err.errno = ret;
    Error.captureStackTrace(err, emitErrorIfNecessary);
    emitter.emit('error', err);
    return true;
  }
  return false;
}

function assertIsObject(value, name, types) {
  if (value !== undefined &&
      (value === null ||
       typeof value !== 'object' ||
       Array.isArray(value))) {
    const err = errors.TypeError('ERR_INVALID_ARG_TYPE',
                                 name,
                                 types || 'object');
    Error.captureStackTrace(err, assertIsObject);
    throw err;
  }
}

module.exports = {
  assertIsObject,
  isIllegalConnectionSpecificHeader,
  emitErrorIfNecessary,
  getDefaultSettings,
  getSessionState,
  getSettings,
  getStreamState,
  mapToHeaders
};
