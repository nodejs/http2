'use strict';

const binding = process.binding('http2');
const errors = require('internal/errors');

const {
  HTTP2_HEADER_STATUS,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_AGE,
  HTTP2_HEADER_AUTHORIZATION,
  HTTP2_HEADER_CONTENT_ENCODING,
  HTTP2_HEADER_CONTENT_LANGUAGE,
  HTTP2_HEADER_CONTENT_LENGTH,
  HTTP2_HEADER_CONTENT_LOCATION,
  HTTP2_HEADER_CONTENT_MD5,
  HTTP2_HEADER_CONTENT_RANGE,
  HTTP2_HEADER_CONTENT_TYPE,
  HTTP2_HEADER_DATE,
  HTTP2_HEADER_ETAG,
  HTTP2_HEADER_EXPIRES,
  HTTP2_HEADER_FROM,
  HTTP2_HEADER_IF_MATCH,
  HTTP2_HEADER_IF_NONE_MATCH,
  HTTP2_HEADER_IF_MODIFIED_SINCE,
  HTTP2_HEADER_IF_RANGE,
  HTTP2_HEADER_IF_UNMODIFIED_SINCE,
  HTTP2_HEADER_LAST_MODIFIED,
  HTTP2_HEADER_MAX_FORWARDS,
  HTTP2_HEADER_PROXY_AUTHORIZATION,
  HTTP2_HEADER_RANGE,
  HTTP2_HEADER_REFERER,
  HTTP2_HEADER_RETRY_AFTER,
  HTTP2_HEADER_USER_AGENT,

  HTTP2_HEADER_CONNECTION,
  HTTP2_HEADER_UPGRADE,
  HTTP2_HEADER_HTTP2_SETTINGS,
  HTTP2_HEADER_TE,
  HTTP2_HEADER_TRANSFER_ENCODING,
  HTTP2_HEADER_HOST,
  HTTP2_HEADER_KEEP_ALIVE,
  HTTP2_HEADER_PROXY_CONNECTION
} = binding.constants;

const kValidPseudoHeaders = new Set([
  HTTP2_HEADER_STATUS,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_PATH
]);

const kSingleValueHeaders = new Set([
  HTTP2_HEADER_STATUS,
  HTTP2_HEADER_METHOD,
  HTTP2_HEADER_AUTHORITY,
  HTTP2_HEADER_SCHEME,
  HTTP2_HEADER_PATH,
  HTTP2_HEADER_AGE,
  HTTP2_HEADER_AUTHORIZATION,
  HTTP2_HEADER_CONTENT_ENCODING,
  HTTP2_HEADER_CONTENT_LANGUAGE,
  HTTP2_HEADER_CONTENT_LENGTH,
  HTTP2_HEADER_CONTENT_LOCATION,
  HTTP2_HEADER_CONTENT_MD5,
  HTTP2_HEADER_CONTENT_RANGE,
  HTTP2_HEADER_CONTENT_TYPE,
  HTTP2_HEADER_DATE,
  HTTP2_HEADER_ETAG,
  HTTP2_HEADER_EXPIRES,
  HTTP2_HEADER_FROM,
  HTTP2_HEADER_IF_MATCH,
  HTTP2_HEADER_IF_MODIFIED_SINCE,
  HTTP2_HEADER_IF_NONE_MATCH,
  HTTP2_HEADER_IF_RANGE,
  HTTP2_HEADER_IF_UNMODIFIED_SINCE,
  HTTP2_HEADER_LAST_MODIFIED,
  HTTP2_HEADER_MAX_FORWARDS,
  HTTP2_HEADER_PROXY_AUTHORIZATION,
  HTTP2_HEADER_RANGE,
  HTTP2_HEADER_REFERER,
  HTTP2_HEADER_RETRY_AFTER,
  HTTP2_HEADER_USER_AGENT
]);

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
    case HTTP2_HEADER_CONNECTION:
    case HTTP2_HEADER_UPGRADE:
    case HTTP2_HEADER_HOST:
    case HTTP2_HEADER_HTTP2_SETTINGS:
    case HTTP2_HEADER_KEEP_ALIVE:
    case HTTP2_HEADER_PROXY_CONNECTION:
    case HTTP2_HEADER_TRANSFER_ENCODING:
      return true;
    case HTTP2_HEADER_TE:
      const val = Array.isArray(value) ? value.join(', ') : value;
      return val !== 'trailers';
    default:
      return false;
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
    key = String(key).toLowerCase();
    const isArray = Array.isArray(value);
    if (isArray) {
      switch (value.length) {
        case 0:
          continue;
        case 1:
          value = String(value[0]);
          break;
        default:
          if (kSingleValueHeaders.has(key))
            throw new errors.Error('ERR_HTTP2_HEADER_SINGLE_VALUE', key);
      }
    }
    if (key[0] === ':') {
      if (!kValidPseudoHeaders.has(key))
        throw new errors.Error('ERR_HTTP2_INVALID_PSEUDOHEADER', key);
      ret.unshift([key, String(value)]);
    } else {
      if (isIllegalConnectionSpecificHeader(key, value))
        throw new errors.Error('ERR_HTTP2_INVALID_CONNECTION_HEADERS');
      if (isArray) {
        for (var k = 0; k < value.length; k++) {
          val = String(value[k]);
          ret.push([key, val]);
        }
      } else {
        val = String(value);
        ret.push([key, val]);
      }
    }
  }

  return ret;
}

class NghttpError extends Error {
  constructor(ret) {
    super(binding.nghttp2ErrorString(ret));
    this.code = 'ERR_HTTP2_ERROR';
    this.name = 'Error [ERR_HTTP2_ERROR]';
    this.errno = ret;
  }
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

function assertWithinRange(name, value, min = 0, max = Infinity) {
  if (value !== undefined &&
      (typeof value !== 'number' || value < min || value > max)) {
    // TODO: use internal.errors
    const err = new RangeError(`"${name}" is out of range`);
    Error.captureStackTrace(err, assertWithinRange);
    throw err;
  }
}

module.exports = {
  assertIsObject,
  assertWithinRange,
  getDefaultSettings,
  getSessionState,
  getSettings,
  getStreamState,
  mapToHeaders,
  NghttpError
};
