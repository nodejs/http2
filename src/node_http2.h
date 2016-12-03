#ifndef SRC_NODE_HTTP2_H_
#define SRC_NODE_HTTP2_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "nghttp2/nghttp2.h"
#include "uv.h"

#include "node_http2_core.h"
#include "env.h"
#include "env-inl.h"
#include "node_crypto_bio.h"
#include "stream_base.h"
#include "stream_base-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include "vector"
#include "map"
#include "memory"

namespace node {
namespace http2 {

using v8::Context;
using v8::EscapableHandleScope;
using v8::Exception;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Map;
using v8::Name;
using v8::Object;
using v8::Persistent;
using v8::String;
using v8::Value;

#define HTTP2_HEADER_STATUS ":status"
#define HTTP2_HEADER_METHOD ":method"
#define HTTP2_HEADER_AUTHORITY ":authority"
#define HTTP2_HEADER_SCHEME ":scheme"
#define HTTP2_HEADER_PATH ":path"

#define HTTP_STATUS_CODES(V)                                                  \
  V(CONTINUE, 100)                                                            \
  V(SWITCHING_PROTOCOLS, 101)                                                 \
  V(PROCESSING, 102)                                                          \
  V(OK, 200)                                                                  \
  V(CREATED, 201)                                                             \
  V(ACCEPTED, 202)                                                            \
  V(NON_AUTHORITATIVE_INFORMATION, 203)                                       \
  V(NO_CONTENT, 204)                                                          \
  V(RESET_CONTENT, 205)                                                       \
  V(PARTIAL_CONTENT, 206)                                                     \
  V(MULTI_STATUS, 207)                                                        \
  V(ALREADY_REPORTED, 208)                                                    \
  V(IM_USED, 226)                                                             \
  V(MULTIPLE_CHOICES, 300)                                                    \
  V(MOVED_PERMANENTLY, 301)                                                   \
  V(FOUND, 302)                                                               \
  V(SEE_OTHER, 303)                                                           \
  V(NOT_MODIFIED, 304)                                                        \
  V(USE_PROXY, 305)                                                           \
  V(TEMPORARY_REDIRECT, 307)                                                  \
  V(PERMANENT_REDIRECT, 308)                                                  \
  V(BAD_REQUEST, 400)                                                         \
  V(UNAUTHORIZED, 401)                                                        \
  V(PAYMENT_REQUIRED, 402)                                                    \
  V(FORBIDDEN, 403)                                                           \
  V(NOT_FOUND, 404)                                                           \
  V(METHOD_NOT_ALLOWED, 405)                                                  \
  V(NOT_ACCEPTABLE, 406)                                                      \
  V(PROXY_AUTHENTICATION_REQUIRED, 407)                                       \
  V(REQUEST_TIMEOUT, 408)                                                     \
  V(CONFLICT, 409)                                                            \
  V(GONE, 410)                                                                \
  V(LENGTH_REQUIRED, 411)                                                     \
  V(PRECONDITION_FAILED, 412)                                                 \
  V(PAYLOAD_TOO_LARGE, 413)                                                   \
  V(URI_TOO_LONG, 414)                                                        \
  V(UNSUPPORTED_MEDIA_TYPE, 415)                                              \
  V(RANGE_NOT_SATISFIABLE, 416)                                               \
  V(EXPECTATION_FAILED, 417)                                                  \
  V(TEAPOT, 418)                                                              \
  V(MISDIRECTED_REQUEST, 421)                                                 \
  V(UNPROCESSABLE_ENTITY, 422)                                                \
  V(LOCKED, 423)                                                              \
  V(FAILED_DEPENDENCY, 424)                                                   \
  V(UNORDERED_COLLECTION, 425)                                                \
  V(UPGRADE_REQUIRED, 426)                                                    \
  V(PRECONDITION_REQUIRED, 428)                                               \
  V(TOO_MANY_REQUESTS, 429)                                                   \
  V(REQUEST_HEADER_FIELDS_TOO_LARGE, 431)                                     \
  V(UNAVAILABLE_FOR_LEGAL_REASONS, 451)                                       \
  V(INTERNAL_SERVER_ERROR, 500)                                               \
  V(NOT_IMPLEMENTED, 501)                                                     \
  V(BAD_GATEWAY, 502)                                                         \
  V(SERVICE_UNAVAILABLE, 503)                                                 \
  V(GATEWAY_TIMEOUT, 504)                                                     \
  V(HTTP_VERSION_NOT_SUPPORTED, 505)                                          \
  V(VARIANT_ALSO_NEGOTIATES, 506)                                             \
  V(INSUFFICIENT_STORAGE, 507)                                                \
  V(LOOP_DETECTED, 508)                                                       \
  V(BANDWIDTH_LIMIT_EXCEEDED, 509)                                            \
  V(NOT_EXTENDED, 510)                                                        \
  V(NETWORK_AUTHENTICATION_REQUIRED, 511)

enum http_status_codes {
#define V(name, code) HTTP_STATUS_##name = code,
HTTP_STATUS_CODES(V)
#undef V
};

#define MIN(A, B) (A < B ? A : B)
#define MAX(A, B) (A > B ? A : B)

#define DATA_FLAGS(V)                                                         \
  V(ENDSTREAM)                                                                \
  V(ENDDATA)                                                                  \
  V(NOENDSTREAM)

#define V(name) FLAG_##name,
enum http2_data_flags {
  DATA_FLAGS(V)
} http2_data_flags;
#undef V

#define THROW_AND_RETURN_UNLESS_(template, name, env, obj)                    \
  do {                                                                        \
    if (!env->template##_constructor_template()->HasInstance(obj))            \
      return env->ThrowTypeError("argument must be an " #name " instance");   \
  } while (0)

#define THROW_AND_RETURN_UNLESS_HTTP2SETTINGS(env, obj)                       \
  THROW_AND_RETURN_UNLESS_(http2settings, "Http2Settings", env, obj);

#define THROW_AND_RETURN_UNLESS_HTTP2STREAM(env, obj)                         \
  THROW_AND_RETURN_UNLESS_(http2stream, "Http2Stream", env, obj);

static const int kSimultaneousBufferCount = 10;

#define NGHTTP2_ERROR_CODES(V)                                                 \
  V(NGHTTP2_ERR_INVALID_ARGUMENT)                                              \
  V(NGHTTP2_ERR_BUFFER_ERROR)                                                  \
  V(NGHTTP2_ERR_UNSUPPORTED_VERSION)                                           \
  V(NGHTTP2_ERR_WOULDBLOCK)                                                    \
  V(NGHTTP2_ERR_PROTO)                                                         \
  V(NGHTTP2_ERR_INVALID_FRAME)                                                 \
  V(NGHTTP2_ERR_EOF)                                                           \
  V(NGHTTP2_ERR_DEFERRED)                                                      \
  V(NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE)                                       \
  V(NGHTTP2_ERR_STREAM_CLOSED)                                                 \
  V(NGHTTP2_ERR_STREAM_CLOSING)                                                \
  V(NGHTTP2_ERR_STREAM_SHUT_WR)                                                \
  V(NGHTTP2_ERR_INVALID_STREAM_ID)                                             \
  V(NGHTTP2_ERR_INVALID_STREAM_STATE)                                          \
  V(NGHTTP2_ERR_DEFERRED_DATA_EXIST)                                           \
  V(NGHTTP2_ERR_START_STREAM_NOT_ALLOWED)                                      \
  V(NGHTTP2_ERR_GOAWAY_ALREADY_SENT)                                           \
  V(NGHTTP2_ERR_INVALID_HEADER_BLOCK)                                          \
  V(NGHTTP2_ERR_INVALID_STATE)                                                 \
  V(NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE)                                     \
  V(NGHTTP2_ERR_FRAME_SIZE_ERROR)                                              \
  V(NGHTTP2_ERR_HEADER_COMP)                                                   \
  V(NGHTTP2_ERR_FLOW_CONTROL)                                                  \
  V(NGHTTP2_ERR_INSUFF_BUFSIZE)                                                \
  V(NGHTTP2_ERR_PAUSE)                                                         \
  V(NGHTTP2_ERR_TOO_MANY_INFLIGHT_SETTINGS)                                    \
  V(NGHTTP2_ERR_PUSH_DISABLED)                                                 \
  V(NGHTTP2_ERR_DATA_EXIST)                                                    \
  V(NGHTTP2_ERR_SESSION_CLOSING)                                               \
  V(NGHTTP2_ERR_HTTP_HEADER)                                                   \
  V(NGHTTP2_ERR_HTTP_MESSAGING)                                                \
  V(NGHTTP2_ERR_REFUSED_STREAM)                                                \
  V(NGHTTP2_ERR_INTERNAL)                                                      \
  V(NGHTTP2_ERR_CANCEL)                                                        \
  V(NGHTTP2_ERR_FATAL)                                                         \
  V(NGHTTP2_ERR_NOMEM)                                                         \
  V(NGHTTP2_ERR_CALLBACK_FAILURE)                                              \
  V(NGHTTP2_ERR_BAD_CLIENT_MAGIC)                                              \
  V(NGHTTP2_ERR_FLOODED)

const char* nghttp2_errname(int rv) {
  switch (rv) {
#define V(code) case code: return #code;
  NGHTTP2_ERROR_CODES(V)
#undef V
    default:
      return "NGHTTP2_UNKNOWN_ERROR";
  }
}

#define OPTIONS(obj, V)                                                       \
  V(obj, "maxDeflateDynamicTableSize", SetMaxDeflateDynamicTableSize, Uint32) \
  V(obj, "maxReservedRemoteStreams", SetMaxReservedRemoteStreams, Uint32)     \
  V(obj, "maxSendHeaderBlockLength", SetMaxSendHeaderBlockLength, Uint32)     \
  V(obj, "peerMaxConcurrentStreams", SetPeerMaxConcurrentStreams, Uint32)     \
  V(obj, "noHttpMessaging", SetNoHttpMessaging, Boolean)                      \
  V(obj, "noRecvClientMagic", SetNoRecvClientMagic, Boolean)

#define SETTINGS(V)                                                     \
  V("headerTableSize", NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,              \
    Integer, NewFromUnsigned)                                           \
  V("maxConcurrentStreams", NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,    \
    Integer, NewFromUnsigned)                                           \
  V("initialWindowSize", NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,          \
    Integer, NewFromUnsigned)                                           \
  V("maxFrameSize", NGHTTP2_SETTINGS_MAX_FRAME_SIZE,                    \
    Integer, NewFromUnsigned)                                           \
  V("maxHeaderListSize", NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,         \
    Integer, NewFromUnsigned)                                           \
  V("enablePush", NGHTTP2_SETTINGS_ENABLE_PUSH,                         \
    Boolean, New)

#define DEFAULT_SETTINGS_HEADER_TABLE_SIZE 4096
#define DEFAULT_SETTINGS_ENABLE_PUSH 1
#define DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE 65535
#define DEFAULT_SETTINGS_MAX_FRAME_SIZE 16384
#define MAX_MAX_FRAME_SIZE 16777215
#define MIN_MAX_FRAME_SIZE DEFAULT_SETTINGS_MAX_FRAME_SIZE
#define MAX_INITIAL_WINDOW_SIZE 2147483647

class Http2Header;
class Http2Session;
class Http2Priority;

class Http2Options {
 public:
  Http2Options(Environment* env, Local<Value> options);

  ~Http2Options() {
    nghttp2_option_del(options_);
  }

  nghttp2_option* operator*() {
    return options_;
  }

  void SetMaxDeflateDynamicTableSize(size_t val) {
    nghttp2_option_set_max_deflate_dynamic_table_size(options_, val);
  }

  void SetMaxReservedRemoteStreams(uint32_t val) {
    nghttp2_option_set_max_reserved_remote_streams(options_, val);
  }

  void SetMaxSendHeaderBlockLength(size_t val) {
    nghttp2_option_set_max_send_header_block_length(options_, val);
  }

  void SetNoHttpMessaging(bool on = true) {
    nghttp2_option_set_no_http_messaging(options_, on ? 1 : 0);
  }

  void SetNoRecvClientMagic(bool on = true) {
    nghttp2_option_set_no_recv_client_magic(options_, on ? 1 : 0);
  }

  void SetPeerMaxConcurrentStreams(uint32_t val) {
    nghttp2_option_set_peer_max_concurrent_streams(options_, val);
  }

 private:
  nghttp2_option* options_;
};

class Http2Priority {
 public:
  Http2Priority(int32_t parent,
                int32_t weight,
                bool exclusive = false) {
    if (weight < 0) weight = NGHTTP2_DEFAULT_WEIGHT;
    weight = MAX(MIN(weight, NGHTTP2_MAX_WEIGHT), NGHTTP2_MIN_WEIGHT);
    nghttp2_priority_spec_init(&spec_, parent, weight, exclusive ? 1 : 0);
  }
  ~Http2Priority() {}

  nghttp2_priority_spec* operator*() {
    return &spec_;
  }
 private:
  nghttp2_priority_spec spec_;
};

class Http2Header : public nghttp2_nv {
 public:
  Http2Header(const char* name_,
              const char* value_,
              size_t namelen_,
              size_t valuelen_,
              bool noindex = false) {
    flags = NGHTTP2_NV_FLAG_NONE;
    // flags = NGHTTP2_NV_FLAG_NO_COPY_NAME |
    //         NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    if (noindex)
      flags |= NGHTTP2_NV_FLAG_NO_INDEX;
    name = Malloc<uint8_t>(namelen_);
    value = Malloc<uint8_t>(valuelen_);
    namelen = namelen_;
    valuelen = valuelen_;
    memcpy(this->name, name_, namelen);
    memcpy(this->value, value_, valuelen);
  }
  ~Http2Header() {
    free(name);
    free(value);
  }
};

static const size_t kAllocBufferSize = 64 * 1024;

////
typedef uint32_t(*get_setting)(nghttp2_session* session,
                               nghttp2_settings_id id);

class Http2Session : public AsyncWrap, public StreamBase {
 public:
  Http2Session(Environment* env,
               Local<Object> wrap,
               nghttp2_session_type type,
               Local<Value> options) :
               AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2SESSION),
               StreamBase(env) {
    Wrap(object(), this);
    node_nghttp2_session_callbacks cb;
    nghttp2_set_callback_send(&cb, OnSessionSend);
    nghttp2_set_callback_on_headers(&cb, OnHeaders);
    nghttp2_set_callback_on_stream_close(&cb, OnStreamClose);
    nghttp2_set_callback_on_data_chunks(&cb, OnDataChunks);
    nghttp2_set_callback_on_settings(&cb, OnSettings);
    nghttp2_set_callback_stream_init(&cb, OnStreamInit);
    nghttp2_set_callback_stream_free(&cb, OnStreamFree);
    nghttp2_set_callback_stream_get_trailers(&cb, OnTrailers);

    Http2Options opts(env, options);
    nghttp2_session_init(env->event_loop(), &handle_, &cb, type, *opts);
    stream_buf_.AllocateSufficientStorage(kAllocBufferSize);
  }

  ~Http2Session() override {}

  static void OnStreamAllocImpl(size_t suggested_size,
                                uv_buf_t* buf,
                                void* ctx);
  static void OnStreamReadImpl(ssize_t nread,
                               const uv_buf_t* bufs,
                               uv_handle_type pending,
                               void* ctx);
  static void OnHeaders(nghttp2_session_t* handle,
                        std::shared_ptr<nghttp2_stream_t> stream,
                        nghttp2_header_list* headers,
                        nghttp2_headers_category cat,
                        uint8_t flags);
  static void OnStreamClose(nghttp2_session_t* session,
                            int32_t id, uint32_t error_code);
  static void OnSessionSend(nghttp2_session_t* handle,
                            const uv_buf_t* bufs,
                            unsigned int nbufs,
                            size_t total);
  static void OnDataChunks(nghttp2_session_t* session,
                           std::shared_ptr<nghttp2_stream_t> stream,
                           std::shared_ptr<nghttp2_data_chunks_t> chunks);
  static void OnStreamInit(nghttp2_session_t* session,
                           std::shared_ptr<nghttp2_stream_t> stream);
  static void OnStreamFree(nghttp2_session_t* session,
                           nghttp2_stream_t* stream);
  static void OnSettings(nghttp2_session_t* session);
  static void OnTrailers(nghttp2_session_t* handle,
                         std::shared_ptr<nghttp2_stream_t> stream,
                         std::vector<nghttp2_nv>* trailers);

  int DoWrite(WriteWrap* w, uv_buf_t* bufs, size_t count,
              uv_stream_t* send_handle) override;

  AsyncWrap* GetAsyncWrap() override {
    return static_cast<AsyncWrap*>(this);
  }

  void* Cast() override {
    return reinterpret_cast<void*>(this);
  }
  bool IsAlive() override {
    return true;
  }
  bool IsClosing() override {
    return false;
  }
  // Non-op
  int ReadStart() override { return 0; }
  // Non-op
  int ReadStop() override { return 0; }
  // Non-op
  int DoShutdown(ShutdownWrap* req_wrap) override {
    return 0;
  }

  void Consume(Local<External> external);
  void Unconsume();

  static void New(const FunctionCallbackInfo<Value>& args);
  static void Consume(const FunctionCallbackInfo<Value>& args);
  static void Unconsume(const FunctionCallbackInfo<Value>& args);
  static void Destroy(const FunctionCallbackInfo<Value>& args);
  static void SubmitSettings(const FunctionCallbackInfo<Value>& args);
  static void SubmitRstStream(const FunctionCallbackInfo<Value>& args);
  static void SubmitResponse(const FunctionCallbackInfo<Value>& args);
  static void SubmitInfo(const FunctionCallbackInfo<Value>& args);
  static void ShutdownStream(const FunctionCallbackInfo<Value>& args);
  static void StreamWrite(const FunctionCallbackInfo<Value>& args);
  static void StreamReadStart(const FunctionCallbackInfo<Value>& args);
  static void StreamReadStop(const FunctionCallbackInfo<Value>& args);
  static void SetNextStreamID(const FunctionCallbackInfo<Value>& args);
  static void GetSessionState(const FunctionCallbackInfo<Value>& args);
  static void GetStreamState(const FunctionCallbackInfo<Value>& args);
  static void SubmitShutdown(const FunctionCallbackInfo<Value>& args);

  template <get_setting fn>
  static void GetSettings(const FunctionCallbackInfo<Value>& args);

  void Cleanup() {
    nghttp2_session_free(&handle_, true);
  }

  size_t self_size() const override {
    return sizeof(*this);
  }

  nghttp2_session_t* operator*() {
    return &handle_;
  }

  nghttp2_session_t handle_;

  char* stream_alloc() {
    return *stream_buf_;
  }

 private:
  StreamBase* stream_;
  StreamResource::Callback<StreamResource::AllocCb> prev_alloc_cb_;
  StreamResource::Callback<StreamResource::ReadCb> prev_read_cb_;
  MaybeStackBuffer<char, kAllocBufferSize> stream_buf_;
};

class SessionShutdownWrap : public ReqWrap<uv_idle_t> {
 public:
  typedef void (*DoneCb)(SessionShutdownWrap* req, int status);

  inline void Done(int status) {
    cb_(this, status);
  }

  SessionShutdownWrap(Environment* env,
                      v8::Local<v8::Object> req_wrap_obj,
                      nghttp2_session_t* handle,
                      uint32_t errorCode,
                      int32_t lastStreamID,
                      Local<Value> opaqueData,
                      bool immediate,
                      DoneCb cb)
      : ReqWrap(env, req_wrap_obj,
                AsyncWrap::PROVIDER_HTTP2SESSIONSHUTDOWNWRAP),
        handle_(handle),
        cb_(cb),
        errorCode_(errorCode),
        lastStreamID_(lastStreamID),
        immediate_(immediate) {
    Wrap(req_wrap_obj, this);
    // TODO: harvest the opaqueData
  }
  ~SessionShutdownWrap() {}

  static void New(const v8::FunctionCallbackInfo<v8::Value>& args) {
    CHECK(args.IsConstructCall());
  }
  static SessionShutdownWrap* from_req(uv_idle_t* req) {
    return ContainerOf(&SessionShutdownWrap::req_, req);
  }
  size_t self_size() const override { return sizeof(*this); }

  nghttp2_session_t* handle() {
    return handle_;
  }

  uint32_t errorCode() {
    return errorCode_;
  }

  int32_t lastStreamID() {
    return lastStreamID_ > 0 ? lastStreamID_ : 0;
  }

  uint8_t* opaqueData() {
    return *opaqueData_;
  }

  bool immediate() {
    return immediate_;
  }

  size_t opaqueDataLength() {
    return opaqueData_.length();
  }

 private:
  nghttp2_session_t* handle_;
  DoneCb cb_;
  uint32_t errorCode_;
  int32_t lastStreamID_;
  bool immediate_;
  MaybeStackBuffer<uint8_t> opaqueData_;
};

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_H_
