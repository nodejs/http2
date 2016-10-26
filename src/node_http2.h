#ifndef SRC_NODE_HTTP2_H_
#define SRC_NODE_HTTP2_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "nghttp2/nghttp2.h"
#include "uv.h"

#include "env.h"
#include "env-inl.h"
#include "node_crypto_bio.h"
#include "stream_base.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include "vector"
#include "map"

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

#define THROW_AND_RETURN_UNLESS_HTTP2HEADERS(env, obj)                        \
  THROW_AND_RETURN_UNLESS_(http2headers, "Http2Headers", env, obj);

#define THROW_AND_RETURN_UNLESS_HTTP2SETTINGS(env, obj)                       \
  THROW_AND_RETURN_UNLESS_(http2settings, "Http2Settings", env, obj);

#define THROW_AND_RETURN_UNLESS_HTTP2STREAM(env, obj)                         \
  THROW_AND_RETURN_UNLESS_(http2stream, "Http2Stream", env, obj);


enum http2_session_type {
  SESSION_TYPE_SERVER,
  SESSION_TYPE_CLIENT
} http2_session_type;

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

#define DEFAULT_SETTINGS_HEADER_TABLE_SIZE 4096
#define DEFAULT_SETTINGS_ENABLE_PUSH 1
#define DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE 65535
#define DEFAULT_SETTINGS_MAX_FRAME_SIZE 16384
#define MAX_MAX_FRAME_SIZE 16777215
#define MIN_MAX_FRAME_SIZE DEFAULT_SETTINGS_MAX_FRAME_SIZE
#define MAX_INITIAL_WINDOW_SIZE 2147483647

class Http2Header;
class Http2Session;
class Http2Stream;
class Http2Priority;
class Http2Settings;

void DoEmit(AsyncWrap* emitter,
            Local<String> name,
            Local<Value>* args,
            size_t count) {
  Environment* env = emitter->env();
  Environment::AsyncCallbackScope callback_scope(env);
  Local<Value> cb = emitter->object()->Get(name);
  CHECK(cb->IsFunction());
  v8::TryCatch try_catch(env->isolate());
  Local<Value> ret = emitter->MakeCallback(cb.As<Function>(), count, args);
  if (ret.IsEmpty()) {
    ClearFatalExceptionHandlers(env);
    FatalException(env->isolate(), try_catch);
  }
}

void DoEmitErrorIfFail(AsyncWrap* emitter, int rv) {
  if (rv < 0) {
    Environment* env = emitter->env();
    Isolate* isolate = env->isolate();
    HandleScope scope(isolate);
    Local<String> msg =
        String::NewFromUtf8(isolate,
                            nghttp2_strerror(rv),
                            v8::NewStringType::kNormal).ToLocalChecked();
    Local<Object> e = Exception::Error(msg)->ToObject(isolate);
    CHECK(!e.IsEmpty());
    e->Set(env->errno_string(), Integer::New(isolate, rv));
    e->Set(env->code_string(), OneByteString(isolate, nghttp2_errname(rv)));
    Local<Value> argv[] { env->error_string(), e };

    Environment::AsyncCallbackScope callback_scope(env);
    Local<Value> cb = emitter->object()->Get(env->onerror_string());
    CHECK(cb->IsFunction());
    v8::TryCatch try_catch(env->isolate());
    Local<Value> ret =
        emitter->MakeCallback(cb.As<Function>(), arraysize(argv), argv);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env);
      FatalException(env->isolate(), try_catch);
    }
  }
}

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

class Http2Settings : public BaseObject {
 public:
  Http2Settings(Environment* env,
                Local<Object> wrap,
                Http2Session* session = nullptr,
                bool localSettings = true);

  ~Http2Settings() {}

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

class Http2Headers : public BaseObject {
 public:
  Http2Headers(Environment* env,
               Local<Object> wrap,
               int reserve) :
               BaseObject(env, wrap) {
    MakeWeak(this);
    entries_.reserve(reserve);
  }

  ~Http2Headers() {}

  static void New(const FunctionCallbackInfo<Value>& args);
  static void Add(const FunctionCallbackInfo<Value>& args);
  static void Clear(const FunctionCallbackInfo<Value>& args);
  static void Reserve(const FunctionCallbackInfo<Value>& args);
  static void GetSize(Local<String> property,
                      const PropertyCallbackInfo<Value>& info);

  size_t Size() {
    return entries_.size();
  }

  nghttp2_nv* operator*() {
    return &entries_[0];
  }

 private:
  void Add(const char* name,
           const char* value,
           size_t nlen,
           size_t vlen,
           bool noindex = false) {
    uint8_t flags = NGHTTP2_NV_FLAG_NONE;
    if (noindex)
      flags |= NGHTTP2_NV_FLAG_NO_INDEX;
    const Http2Header* header =
      new Http2Header(name, value, nlen, vlen, noindex);
    entries_.push_back(*header);
  }

  void Reserve(int inc) {
    entries_.reserve(entries_.size() + inc);
  }

  void Clear() {
    entries_.clear();
  }

  std::vector<Http2Header> entries_;
};


class Http2Stream : public AsyncWrap, public StreamBase {
 public:
  // Get a stored Http2Stream instance from the nghttp2_session, if one exists
  static Http2Stream* GetFromSession(nghttp2_session* session, int32_t id) {
    return static_cast<Http2Stream*>(
      nghttp2_session_get_stream_user_data(session, id));
  }

  Http2Stream(Environment* env, Local<Object> wrap) :
              AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2STREAM),
              StreamBase(env) {
    Wrap(object(), this);
    str_in_ = NodeBIO::New();
    str_out_ = NodeBIO::New();
    NodeBIO::FromBIO(str_in_)->AssignEnvironment(env);
    NodeBIO::FromBIO(str_out_)->AssignEnvironment(env);
    provider_.read_callback = Http2Stream::on_read;
    provider_.source.ptr = this;
    set_alloc_cb({ OnAllocSelf, this });
    set_read_cb({ OnReadSelf, this });
    outgoing_headers_.reserve(100);
    outgoing_trailers_.reserve(100);
  }

  ~Http2Stream() override {
    Reset();
    ClearWrap(object());
    persistent().Reset();
    if (!headers_.IsEmpty())
      headers_.Reset();
    str_in_ = nullptr;
    str_out_ = nullptr;
  }

  void Reset();
  void Initialize(Http2Session* session,
                  int32_t id,
                  nghttp2_headers_category category);

  AsyncWrap* GetAsyncWrap() override {
    return static_cast<AsyncWrap*>(this);
  }

  void* Cast() override {
    return reinterpret_cast<void*>(this);
  }

  nghttp2_stream* operator*();

  // StreamBase::IsAlive
  bool IsAlive() override;

  // StreamBase::IsClosing
  bool IsClosing() override;

  // StreamBase::ReadStart
  int ReadStart() override;

  // StreamBase::ReadStop
  int ReadStop() override;

  // StreamBase::DoWrite - Write data to the outbound str_out_ NodeBIO
  int DoWrite(WriteWrap* w, uv_buf_t* bufs, size_t count,
              uv_stream_t* send_handle) override;

  void EmitPendingData();
  void ReceiveData(const uint8_t* data, size_t len);

  static void OnAllocSelf(size_t suggested_size, uv_buf_t* buf, void* ctx);
  static void OnReadSelf(ssize_t nread, const uv_buf_t* buf,
                         uv_handle_type pending, void* ctx);

  // JS Methods
  static void New(const FunctionCallbackInfo<Value>& args);
  static void Reinitialize(const FunctionCallbackInfo<Value>& args);
  static void Close(const FunctionCallbackInfo<Value>& args);
  static void Reset(const FunctionCallbackInfo<Value>& args);
  static void FinishedWriting(const FunctionCallbackInfo<Value>& args);

  static void ChangeStreamPriority(const FunctionCallbackInfo<Value>& args);
  static void Respond(const FunctionCallbackInfo<Value>& args);
  static void ResumeData(const FunctionCallbackInfo<Value>& args);
  static void SendContinue(const FunctionCallbackInfo<Value>& args);
  static void SendPriority(const FunctionCallbackInfo<Value>& args);
  static void SendRstStream(const FunctionCallbackInfo<Value>& args);
  static void SendPushPromise(const FunctionCallbackInfo<Value>& args);
  static void AddHeader(const FunctionCallbackInfo<Value>& args);
  static void AddTrailer(const FunctionCallbackInfo<Value>& args);
  static void GetId(const FunctionCallbackInfo<Value>& args);
  static void GetState(const FunctionCallbackInfo<Value>& args);
  static void SetLocalWindowSize(const FunctionCallbackInfo<Value>& args);

  int DoShutdown(ShutdownWrap* req_wrap) override {
    HandleScope scope(req_wrap->env()->isolate());
    Context::Scope context_scope(req_wrap->env()->context());
    req_wrap->Dispatched();
    req_wrap->Done(0);
    return 0;
  }

  // Tell nghttp2 to resume sending DATA frames. If
  // the Http2Stream instance is detached, this is
  // a non-op
  void Resume();

  // Returns the stream ID
  int32_t id() {
    return stream_id_;
  }

  // Returns the Http2Session pointer
  Http2Session* session() {
    return session_;
  }

  // AsyncWrap
  size_t self_size() const override {
    return sizeof(*this);
  }

  // As Headers are being received by the nghttp2_session, a set of
  // callbacks are invoked. Headers are processed sequentially.
  // The headers_ variable holds the Map instance that contains
  // the received headers. The headers_ variable will be cleared
  // whenever the header block is complete and passed off to the
  // JS callback.
  void SetHeaders(nghttp2_headers_category category) {
    // CHECK(headers_.IsEmpty());
    headers_category_ = category;
    Isolate* isolate = env()->isolate();
    headers_.Reset(isolate, Map::New(isolate));
  }

  // Set an individual header name+value pair in the headers_ Map
  void SetHeader(const uint8_t *name, size_t namelen,
                 const uint8_t *value, size_t valuelen) {
    Environment* env = this->env();
    Isolate* isolate = env->isolate();
    CHECK(!headers_.IsEmpty());
    Local<Map> headers = PersistentToLocal(isolate, headers_);
    Local<Context> context = env->context();
    Local<String> key = OneByteString(isolate, name, namelen);
    Local<String> val = OneByteString(isolate, value, valuelen);
    // If a header with the same name has already been set, then
    // change the value to an array if it hasn't been changed already.
    if (headers->Has(context, key).FromJust()) {
      Local<Value> existing = headers->Get(context, key).ToLocalChecked();
      if (existing->IsArray()) {
        Local<Function> fn = env->push_values_to_array_function();
        Local<Value> argv[] {val};
        fn->Call(context, existing, 1, argv).ToLocalChecked();
        return;
      }
    }
    headers->Set(context, key, val).IsEmpty();
  }

  // Get the type of headers
  nghttp2_headers_category GetHeadersCategory() {
    return headers_category_;
  }

  // Return the current set of headers_
  Local<Map> GetHeaders() {
    return PersistentToLocal(env()->isolate(), headers_);
  }

  // Clear the headers Local pointer. The pointer had to have
  // been previously handed off.
  void ClearHeaders() {
    headers_.Reset();
    headers_category_ = static_cast<nghttp2_headers_category>(NULL);
    CHECK(headers_.IsEmpty());
  }

  // nghttp2_data_source_read_callback. When the nghttp2_session instance
  // is given an nghttp2_data_provider for the purpose of providing DATA
  // frames outbound on a stream, this callback will be invoked. If there
  // is data available to be read, the buf should be filled up to length
  // and the total number of bytes read should be returned. If there is no
  // data available to be read but there *might* be data available later,
  // the function MUST return NGHTTP2_ERR_DEFERRED. If there is no more
  // data to read, the NGHTTP2_DATA_FLAG_EOF flag must be set on *flags.
  // If the there are also Trailing headers to be set, the
  // NGHTTP2_DATA_FLAG_NO_END_STREAM flag must also be set and the
  // nghttp2_submit_trailers function should be called. This function
  // will be called repeatedly until either there is no more data or until
  // NGHTTP2_ERR_DEFERRED is returned.
  static ssize_t on_read(nghttp2_session* session,
                         int32_t stream_id,
                         uint8_t* buf,
                         size_t length,
                         uint32_t* flags,
                         nghttp2_data_source* source,
                         void* user_data);

  nghttp2_data_provider* provider() {
    return &provider_;
  }

  // Adds an *Outgoing* Header.
  void AddHeader(const char* name, const char* value,
                 size_t nlen, size_t vlen, bool noindex = false) {
    const Http2Header* header =
      new Http2Header(name, value, nlen, vlen, noindex);
    if (strncmp(name, ":", 1) == 0) {
      outgoing_headers_.insert(outgoing_headers_.begin(), *header);
    } else {
      outgoing_headers_.push_back(*header);
    }
  }

  // Adds an *Outgoing* Trailer.
  void AddTrailer(const char* name, const char* value,
                 size_t nlen, size_t vlen, bool noindex = false) {
    const Http2Header* header =
      new Http2Header(name, value, nlen, vlen, noindex);
    outgoing_trailers_.push_back(*header);
  }

  // Returns the array of Outgoing Headers from the vector
  nghttp2_nv* OutgoingHeaders() {
    return &outgoing_headers_[0];
  }

  // Returns the total number of Outgoing Headers
  size_t OutgoingHeadersCount() {
    return outgoing_headers_.size();
  }

  // Returns the array of Outgoing Trailers from the vector
  nghttp2_nv* OutgoingTrailers() {
    return &outgoing_trailers_[0];
  }

  // Returns the total number of Outgoing Trailers
  size_t OutgoingTrailersCount() {
    return outgoing_trailers_.size();
  }

 private:
  bool writable_ = true;
  bool reading_ = false;
  nghttp2_data_provider provider_;
  BIO* str_in_;
  BIO* str_out_;
  Http2Session* session_;
  int32_t stream_id_;

  // The outgoing headers and trailers
  std::vector<Http2Header> outgoing_headers_;
  std::vector<Http2Header> outgoing_trailers_;

  // The temporary incoming headers
  Persistent<Map> headers_;
  nghttp2_headers_category headers_category_ =
      static_cast<nghttp2_headers_category>(NULL);
};


class Http2Session : public AsyncWrap {
 public:
  Http2Session(Environment* env, Local<Object> wrap) :
               AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2SESSION) {
    Wrap(object(), this);
    nghttp2_session_callbacks_new(&cb_);
#define SET_SESSION_CALLBACK(callbacks, name)                                 \
    nghttp2_session_callbacks_set_##name##_callback(callbacks, name);
    SET_SESSION_CALLBACK(cb_, send)
    SET_SESSION_CALLBACK(cb_, on_frame_recv)
    SET_SESSION_CALLBACK(cb_, on_stream_close)
    SET_SESSION_CALLBACK(cb_, on_header)
    SET_SESSION_CALLBACK(cb_, on_begin_headers)
    SET_SESSION_CALLBACK(cb_, on_data_chunk_recv)
    SET_SESSION_CALLBACK(cb_, select_padding);
#undef SET_SESSION_CALLBACK
  }

  ~Http2Session() override {
    nghttp2_session_callbacks_del(cb_);
    Reset();
  }

  void Initialize(Environment* env,
                  enum http2_session_type type,
                  Local<Value> options,
                  Local<External> external);
  void Unconsume();
  void Consume(Local<External> external);
  void Reset();

  // Native API
  int SendIfNecessary() {
    if (nghttp2_session_want_write(session_))
      return nghttp2_session_send(session_);
    return 0;
  }

  size_t self_size() const override {
    return sizeof(*this);
  }

  nghttp2_session* operator*() {
    return session_;
  }

  // JS Methods
  static void New(const FunctionCallbackInfo<Value>& args);
  static void Reinitialize(const FunctionCallbackInfo<Value>& args);
  static void Reset(const FunctionCallbackInfo<Value>& args);
  static void Close(const FunctionCallbackInfo<Value>& args);
  static void GracefulTerminate(const FunctionCallbackInfo<Value>& args);
  static void Terminate(const FunctionCallbackInfo<Value>& args);
  static void GetState(const FunctionCallbackInfo<Value>& args);
  static void SetNextStreamID(const FunctionCallbackInfo<Value>& args);
  static void SetLocalWindowSize(const FunctionCallbackInfo<Value>& args);
  static void GetRemoteSettings(const FunctionCallbackInfo<Value>& args);
  static void GetLocalSettings(const FunctionCallbackInfo<Value>& args);
  static void SetLocalSettings(const FunctionCallbackInfo<Value>& args);
  static void Request(const FunctionCallbackInfo<Value>& args);

 private:
  friend class Http2Stream;

  // The alloc implementation used by the consumed stream
  // (see the implementation of Consume)
  static void OnAllocImpl(size_t suggested_size, uv_buf_t* buf, void* ctx);

  // The read implementation used by the consumed stream
  // (see the implementation of Consume)
  static void OnReadImpl(ssize_t nread, const uv_buf_t* buf,
                         uv_handle_type pending, void* ctx);

  // Called by nghttp2 when there is data to be sent.
  static ssize_t send(nghttp2_session* session, const uint8_t* data,
                      size_t length, int flags, void *user_data);

  // Called by nghttp2 when an RST_STREAM frame has been received
  static int on_rst_stream_frame(Http2Session* session, int32_t id,
                                 const nghttp2_frame_hd hd,
                                 const nghttp2_rst_stream rst);

  // Called when a GOAWAY frame has been received
  static int on_goaway_frame(Http2Session* session,
                             const nghttp2_frame_hd hd,
                             const nghttp2_goaway goaway);

  // Called when a DATA frame has been fullly processed
  static int on_data_frame(Http2Session* session,
                           Http2Stream* stream,
                           const nghttp2_frame_hd hd,
                           const nghttp2_data data);

  // Called when a HEADERS frame has been fully processed
  static int on_headers_frame(Http2Session* session,
                              int32_t id,
                              const nghttp2_frame_hd hd,
                              const nghttp2_headers headers);

  // Called by nghttp2 when any frame has been received
  static int on_frame_recv(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data);

  // Called by nghttp2 when an nghttp2_stream has been closed
  static int on_stream_close(nghttp2_session *session,
                             int32_t stream_id,
                             uint32_t error_code,
                             void *user_data);

  // Called by nghttp2 when a header name+value pair is processed
  static int on_header(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name,
                       size_t namelen,
                       const uint8_t *value,
                       size_t valuelen,
                       uint8_t flags,
                       void *user_data);

  // Called by nghttp2 at the start of processing a HEADERS block.
  static int on_begin_headers(nghttp2_session* session,
                              const nghttp2_frame* frame,
                              void* user_data);

  // Called by nghttp2 multiple times while processing a DATA
  // frame to pass the data on
  static int on_data_chunk_recv(nghttp2_session* session, uint8_t flags,
                                int32_t stream_id, const uint8_t* data,
                                size_t len, void* user_data);

  // Called by nghttp2 whenever a frame has been sent.
  static int on_frame_send(nghttp2_session* session,
                           const nghttp2_frame* frame,
                           void* user_data);

  // Called by nghttp2 to select the padding len for any
  // given frame.
  static ssize_t select_padding(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                size_t max_payloadlen,
                                void *user_data);

  void Emit(Local<String> name, Local<Value>* args, size_t count) {
    DoEmit(this, name, args, count);
  }

  void EmitErrorIfFail(int rv) {
    DoEmitErrorIfFail(this, rv);
  }

  enum http2_session_type type_;
  nghttp2_session* session_;
  nghttp2_session_callbacks* cb_;
  StreamBase* stream_;
  StreamResource::Callback<StreamResource::AllocCb> prev_alloc_cb_;
  StreamResource::Callback<StreamResource::ReadCb> prev_read_cb_;
};

static const size_t kAllocBufferSize = 64 * 1024;

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_H_
