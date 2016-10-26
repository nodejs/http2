#ifndef SRC_NODE_HTTP2_H_
#define SRC_NODE_HTTP2_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "nghttp2/nghttp2.h"

#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include "vector"
#include "map"

namespace node {
namespace http2 {

using v8::FunctionCallbackInfo;
using v8::Local;
using v8::Name;
using v8::Object;
using v8::PropertyCallbackInfo;
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

#define MAKE_NV(NAME, VALUE)                                                  \
  {                                                                           \
    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(NAME)),             \
    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(VALUE)),            \
    sizeof(NAME) - 1, sizeof(VALUE) - 1,                                      \
    NGHTTP2_NV_FLAG_NONE                                                      \
  }

#define SET_SESSION_CALLBACK(callbacks, name)                                 \
  nghttp2_session_callbacks_set_##name##_callback(callbacks, name);

#define DATA_FLAGS(V)                                                         \
  V(ENDSTREAM)                                                                \
  V(ENDDATA)                                                                  \
  V(NOENDSTREAM)

#define V(name) FLAG_##name,
enum http2_data_flags {
  DATA_FLAGS(V)
} http2_data_flags;
#undef V

#define EMIT(env, obj, event, ...)                                            \
  do {                                                                        \
    Environment::AsyncCallbackScope callback_scope(env);                      \
    Local<Value> cb = obj->object()->Get(env->emit_string());                 \
    CHECK(cb->IsFunction());                                                  \
    Local<Value> argv[] {                                                     \
      FIXED_ONE_BYTE_STRING(env->isolate(), event),                           \
      __VA_ARGS__                                                             \
    };                                                                        \
    obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);              \
  } while (0)

#define EMIT0(env, obj, event)                                                \
  do {                                                                        \
    Environment::AsyncCallbackScope callback_scope(env);                      \
    Local<Value> cb = obj->object()->Get(env->emit_string());                 \
    CHECK(cb->IsFunction());                                                  \
    Local<Value> argv[] {                                                     \
      FIXED_ONE_BYTE_STRING(env->isolate(), event)                            \
    };                                                                        \
    obj->MakeCallback(cb.As<Function>(), arraysize(argv), argv);              \
  } while (0)

#define SESSION_OR_RETURN(session)                                            \
  {                                                                           \
    if (!**session) return;                                                   \
  }

enum http2_session_type {
  SESSION_TYPE_SERVER,
  SESSION_TYPE_CLIENT
} http2_session_type;

#define DEFAULT_SETTINGS_HEADER_TABLE_SIZE 4096
#define DEFAULT_SETTINGS_ENABLE_PUSH 1
#define DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE 65535
#define DEFAULT_SETTINGS_MAX_FRAME_SIZE 16384
#define MAX_MAX_FRAME_SIZE 16777215
#define MIN_MAX_FRAME_SIZE DEFAULT_SETTINGS_MAX_FRAME_SIZE
#define MAX_INITIAL_WINDOW_SIZE 2147483647

class Http2DataProvider;
class Http2Header;
class Http2Session;
class Http2Stream;
class Http2Priority;
class Http2Settings;

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

class Http2Settings : BaseObject {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);
  static void Defaults(const FunctionCallbackInfo<Value>& args);
  static void Reset(const FunctionCallbackInfo<Value>& args);
  static void Pack(const FunctionCallbackInfo<Value>& args);

  static void GetHeaderTableSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetHeaderTableSize(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  static void GetEnablePush(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetEnablePush(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  static void GetMaxConcurrentStreams(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetMaxConcurrentStreams(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  static void GetInitialWindowSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetInitialWindowSize(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  static void GetMaxFrameSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetMaxFrameSize(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  static void GetMaxHeaderListSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void SetMaxHeaderListSize(
      Local<String> property,
      Local<Value> value,
      const PropertyCallbackInfo<void>& info);

  void CollectSettings(std::vector<nghttp2_settings_entry>* entries) {
    for (auto it = settings_.begin();
         it != settings_.end(); it++) {
      entries->push_back({it->first, it->second});
    }
  }

  size_t size() {
    return settings_.size();
  }

 private:
  friend class Http2Session;
  Http2Settings(Environment* env,
                Local<Object> wrap,
                Http2Session* session = nullptr,
                bool localSettings = true);

  ~Http2Settings() {}

  void Set(int32_t id, uint32_t value) {
    settings_[id] = value;
  }

  void Find(int32_t id, const PropertyCallbackInfo<Value>& info) {
    auto p = settings_.find(id);
    if (p != settings_.end())
      info.GetReturnValue().Set(p->second);
  }

  void FindBoolean(int32_t id, const PropertyCallbackInfo<Value>& info) {
    auto p = settings_.find(id);
    if (p != settings_.end())
      info.GetReturnValue().Set(p->second != 0);
  }

  void Erase(int32_t id) {
    settings_.erase(id);
  }

  std::map<int32_t, uint32_t> settings_;
};

class Http2Priority {
 public:
  Http2Priority(int32_t parent,
                int32_t weight = NGHTTP2_DEFAULT_WEIGHT,
                bool exclusive = false);
  ~Http2Priority() {}

  nghttp2_priority_spec* operator*() {
    return &spec_;
  }
 private:
  nghttp2_priority_spec spec_;
};


class Http2Header : BaseObject {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);

  static void GetName(Local<String> property,
                      const PropertyCallbackInfo<Value>& info);
  static void GetValue(Local<String> property,
                       const PropertyCallbackInfo<Value>& info);
  static void GetFlags(Local<String> property,
                       const PropertyCallbackInfo<Value>& info);
  static void SetFlags(Local<String> property,
                       Local<Value> value,
                       const PropertyCallbackInfo<void>& info);

  nghttp2_nv operator*() {
    return nv_;
  }

 private:
  friend class Http2Session;

  Http2Header(Environment* env,
              Local<Object> wrap,
              char* name, size_t nlen,
              char* value, size_t vlen);

  ~Http2Header() {}

  MaybeStackBuffer<uint8_t> store_;
  nghttp2_nv nv_;
};


class Http2Stream : public AsyncWrap {
 public:
  static void GetUid(Local<String> property,
                     const PropertyCallbackInfo<Value>& args);
  static void GetID(Local<String> property,
                    const PropertyCallbackInfo<Value>& args);
  static void GetState(Local<String> property,
                       const PropertyCallbackInfo<Value>& args);
  static void GetWeight(Local<String> property,
                        const PropertyCallbackInfo<Value>& args);
  static void GetSumDependencyWeight(Local<String> property,
                                     const PropertyCallbackInfo<Value>& args);
  static void GetLocalWindowSize(Local<String> property,
                                 const PropertyCallbackInfo<Value>& args);
  static void GetStreamLocalClose(Local<String> property,
                                  const PropertyCallbackInfo<Value>& args);
  static void GetStreamRemoteClose(Local<String> property,
                                   const PropertyCallbackInfo<Value>& args);
  static void SetLocalWindowSize(Local<String> property,
                                 Local<Value> value,
                                 const PropertyCallbackInfo<void>& args);

  static void ConsumeStream(const FunctionCallbackInfo<Value>& args);
  static void ChangeStreamPriority(const FunctionCallbackInfo<Value>& args);
  static void Respond(const FunctionCallbackInfo<Value>& args);
  static void ResumeData(const FunctionCallbackInfo<Value>& args);
  static void SendContinue(const FunctionCallbackInfo<Value>& args);
  static void SendDataFrame(const FunctionCallbackInfo<Value>& args);
  static void SendPriority(const FunctionCallbackInfo<Value>& args);
  static void SendRstStream(const FunctionCallbackInfo<Value>& args);
  static void SendTrailers(const FunctionCallbackInfo<Value>& args);
  static void SendPushPromise(const FunctionCallbackInfo<Value>& args);

  nghttp2_stream* operator*() {
    return stream_;
  }

  bool IsLocalOpen() {
    nghttp2_stream_proto_state state =
      nghttp2_stream_get_state(stream_);
    return state != NGHTTP2_STREAM_STATE_CLOSED &&
           (state == NGHTTP2_STREAM_STATE_OPEN ||
            state == NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
  }

  int32_t id() {
    return stream_id_;
  }

  Http2Stream* previous() {
    return prev_;
  }

  Http2Stream* next() {
    return next_;
  }

  Http2Session* session() {
    return session_;
  }

  size_t self_size() const override {
    return sizeof(*this);
  }

  Http2Stream(Environment* env,
              Local<Object> wrap,
              Http2Session* session,
              int32_t stream_id);

  static void RemoveStream(Http2Stream* stream);
  static void AddStream(Http2Stream* stream, Http2Session* session);

  ~Http2Stream() override {}

 private:
  friend class Http2Session;

  Http2Session* session_;
  Http2Stream* prev_;
  Http2Stream* next_;
  int32_t stream_id_;
  nghttp2_stream* stream_;
};


class Http2Session : public AsyncWrap {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);

  static void GetUid(
    Local<String> property,
    const PropertyCallbackInfo<Value>& args);
  static void GetWantRead(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void GetWantWrite(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void GetType(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void GetNextStreamID(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void SetNextStreamID(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info);
  static void GetEffectiveLocalWindowSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetEffectiveRecvDataLength(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetLastProcStreamID(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetOutboundQueueSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetRemoteWindowSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetDeflateDynamicTableSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetInflateDynamicTableSize(
      Local<String> property,
      const PropertyCallbackInfo<Value>& info);
  static void GetLocalWindowSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void SetLocalWindowSize(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info);
  static void GetRootStream(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void GetRemoteSettings(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void GetLocalSettings(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info);
  static void SetLocalSettings(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info);

  static void GracefulTerminate(const FunctionCallbackInfo<Value>& args);
  static void Destroy(const FunctionCallbackInfo<Value>& args);
  static void Terminate(const FunctionCallbackInfo<Value>& args);
  static void Consume(const FunctionCallbackInfo<Value>& args);
  static void ConsumeSession(const FunctionCallbackInfo<Value>& args);
  static void CreateIdleStream(const FunctionCallbackInfo<Value>& args);
  static void ReceiveData(const FunctionCallbackInfo<Value>& args);
  static void SendData(const FunctionCallbackInfo<Value>& args);
  static void GetStream(const FunctionCallbackInfo<Value>& args);

  size_t self_size() const override {
    return sizeof(*this);
  }

  nghttp2_session* operator*() {
    return session_;
  }

 private:
  friend class Http2Stream;
  static Http2Stream* create_stream(Environment* env,
                                    Http2Session* session,
                                    uint32_t stream_id);

  Http2Session(Environment* env,
               Local<Object> wrap,
               enum http2_session_type type,
               Local<Value> options);

  ~Http2Session() override {
    nghttp2_session_del(session_);
  }

  static ssize_t send(nghttp2_session* session,
                      const uint8_t* data,
                      size_t length,
                      int flags,
                      void *user_data);

  static int on_rst_stream_frame(Http2Session* session,
                                 int32_t id,
                                 const nghttp2_frame_hd hd,
                                 const nghttp2_rst_stream rst);

  static int on_goaway_frame(Http2Session* session,
                             const nghttp2_frame_hd hd,
                             const nghttp2_goaway goaway);

  static int on_data_frame(Http2Session* session,
                           Http2Stream* stream,
                           const nghttp2_frame_hd hd,
                           const nghttp2_data data);

  static int on_headers_frame(Http2Session* session,
                              Http2Stream* stream,
                              const nghttp2_frame_hd hd,
                              const nghttp2_headers headers);

  static int on_frame_recv(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data);

  static int on_stream_close(nghttp2_session *session,
                             int32_t stream_id,
                             uint32_t error_code,
                             void *user_data);

  static int on_header(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name,
                       size_t namelen,
                       const uint8_t *value,
                       size_t valuelen,
                       uint8_t flags,
                       void *user_data);

  static int on_begin_headers(nghttp2_session* session,
                              const nghttp2_frame* frame,
                              void* user_data);

  static int on_data_chunk_recv(nghttp2_session* session,
                                uint8_t flags,
                                int32_t stream_id,
                                const uint8_t* data,
                                size_t len,
                                void* user_data);

  static int on_frame_send(nghttp2_session* session,
                           const nghttp2_frame* frame,
                           void* user_data);

  static ssize_t select_padding(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                size_t max_payloadlen,
                                void *user_data);

  void Init(enum http2_session_type type);

  bool WantReadOrWrite() {
    return nghttp2_session_want_read(session_) != 0 ||
           nghttp2_session_want_write(session_) != 0;
  }

  Http2Stream* root_;
  enum http2_session_type type_;
  nghttp2_session* session_;
};


class Http2DataProvider : BaseObject {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);

  nghttp2_data_provider* operator*() {
    return &provider_;
  }

  Http2Stream* stream() {
    return stream_;
  }

 private:
  static void FreeCallbackNonop(char* data, void* hint) {}
  static ssize_t on_read(nghttp2_session* session,
                         int32_t stream_id,
                         uint8_t* buf,
                         size_t length,
                         uint32_t* flags,
                         nghttp2_data_source* source,
                         void* user_data);

  Http2DataProvider(Environment* env,
                    Local<Object> wrap,
                    Http2Stream* stream);

  ~Http2DataProvider() {}

  Http2Stream* stream_;
  nghttp2_data_provider provider_;
  Local<Name> read_;
};

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_H_
