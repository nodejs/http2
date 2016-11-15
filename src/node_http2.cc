#include "node.h"
#include "node_buffer.h"
#include "nghttp2/nghttp2.h"
#include "node_http2.h"
#include "stream_base.h"
#include "stream_base-inl.h"

#include "async-wrap.h"
#include "async-wrap-inl.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8-profiler.h"
#include "v8.h"

#include <vector>

namespace node {

using v8::Context;
using v8::External;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Handle;
using v8::HandleScope;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Name;
using v8::Number;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;

namespace http2 {

// Http2Options statics

#define OPTIONS(obj, V)                                                       \
  V(obj, "maxDeflateDynamicTableSize", SetMaxDeflateDynamicTableSize, Uint32) \
  V(obj, "maxReservedRemoteStreams", SetMaxReservedRemoteStreams, Uint32)     \
  V(obj, "maxSendHeaderBlockLength", SetMaxSendHeaderBlockLength, Uint32)     \
  V(obj, "peerMaxConcurrentStreams", SetPeerMaxConcurrentStreams, Uint32)     \
  V(obj, "noHttpMessaging", SetNoHttpMessaging, Boolean)                      \
  V(obj, "noRecvClientMagic", SetNoRecvClientMagic, Boolean)

Http2Options::Http2Options(Environment* env, Local<Value> options) {
  nghttp2_option_new(&options_);
  if (options->IsObject()) {
    Local<Object> opts = options.As<Object>();

#define V(obj, name, fn, type)                                                \
  {                                                                           \
    Local<Value> val = obj->Get(FIXED_ONE_BYTE_STRING(env->isolate(), name)); \
    if (!val.IsEmpty() && !val->IsUndefined())                                \
      fn(val->type##Value());                                                 \
  }
    OPTIONS(opts, V)
#undef V
  }
}
#undef OPTIONS

// Http2Settings statics

// Utility typedef used to abstract getting remote or local
// settings from the nghttp2_session instance.
typedef uint32_t(*get_setting)(nghttp2_session* session,
                               nghttp2_settings_id id);
Http2Settings::Http2Settings(Environment* env,
                             Local<Object> wrap,
                             Http2Session* session,
                             bool localSettings) :
                             BaseObject(env, wrap) {
  MakeWeak<Http2Settings>(this);

  if (session != nullptr) {
    // When initialized using an existing Http2Session instance,
    // fetch the currently established settings and fill in the
    // internal map.
    get_setting fn =
        localSettings ?
            nghttp2_session_get_local_settings :
            nghttp2_session_get_remote_settings;
      Set(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
          fn(**session, NGHTTP2_SETTINGS_HEADER_TABLE_SIZE));
      Set(NGHTTP2_SETTINGS_ENABLE_PUSH,
          fn(**session, NGHTTP2_SETTINGS_ENABLE_PUSH));
      Set(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
          fn(**session, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS));
      Set(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
          fn(**session, NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE));
      Set(NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
          fn(**session, NGHTTP2_SETTINGS_MAX_FRAME_SIZE));
      Set(NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE,
          fn(**session, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE));
  }
}

void Http2Settings::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args.IsConstructCall())
    return env->ThrowTypeError("Class constructor Http2Settings cannot "
                               "be invoked without 'new'");
  new Http2Settings(env, args.This());
}

// Used to fill in the spec defined initial values for each setting.
void Http2Settings::Defaults(const FunctionCallbackInfo<Value>& args) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, args.Holder());
  settings->settings_.clear();
  settings->Set(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE,
                DEFAULT_SETTINGS_HEADER_TABLE_SIZE);
  settings->Set(NGHTTP2_SETTINGS_ENABLE_PUSH,
                DEFAULT_SETTINGS_ENABLE_PUSH);
  settings->Set(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
  settings->Set(NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
                DEFAULT_SETTINGS_MAX_FRAME_SIZE);
}

// Reset the settings object by clearing the internal map
void Http2Settings::Reset(const FunctionCallbackInfo<Value>& args) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, args.Holder());
  settings->settings_.clear();
}

// Serializes the settings object into a Buffer instance that
// would be suitable, for instance, for creating the Base64
// output for an HTTP2-Settings header field.
void Http2Settings::Pack(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  HandleScope scope(env->isolate());
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, args.Holder());
  std::vector<nghttp2_settings_entry> entries;
  settings->CollectSettings(&entries);
  size_t len = entries.size() * 6;
  MaybeStackBuffer<char> buf(len);
  ssize_t ret =
      nghttp2_pack_settings_payload(
        reinterpret_cast<uint8_t*>(*buf), len, &entries[0], entries.size());
  if (ret >= 0) {
    args.GetReturnValue().Set(
      Buffer::Copy(env, *buf, len).ToLocalChecked());
  }
}

void Http2Settings::GetHeaderTableSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->Find(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, info);
}

void Http2Settings::SetHeaderTableSize(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined())
    settings->Erase(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE);
  else
    settings->Set(NGHTTP2_SETTINGS_HEADER_TABLE_SIZE, value->Uint32Value());
}

void Http2Settings::GetEnablePush(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->FindBoolean(NGHTTP2_SETTINGS_ENABLE_PUSH, info);
}

void Http2Settings::SetEnablePush(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined())
    settings->Erase(NGHTTP2_SETTINGS_ENABLE_PUSH);
  else
    settings->Set(NGHTTP2_SETTINGS_ENABLE_PUSH, value->BooleanValue() ? 1 : 0);
}

void Http2Settings::GetMaxConcurrentStreams(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->Find(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, info);
}

void Http2Settings::SetMaxConcurrentStreams(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined()) {
    settings->Erase(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
  } else {
    settings->Set(NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
                  value->Uint32Value());
  }
}

void Http2Settings::GetInitialWindowSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->Find(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, info);
}

void Http2Settings::SetInitialWindowSize(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined())
    settings->Erase(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE);
  else
    settings->Set(NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                  MIN(MAX_INITIAL_WINDOW_SIZE, value->Uint32Value()));
}

void Http2Settings::GetMaxFrameSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->Find(NGHTTP2_SETTINGS_MAX_FRAME_SIZE, info);
}

void Http2Settings::SetMaxFrameSize(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined()) {
    settings->Erase(NGHTTP2_SETTINGS_MAX_FRAME_SIZE);
  } else {
    settings->Set(
        NGHTTP2_SETTINGS_MAX_FRAME_SIZE,
        MAX(MIN(value->Uint32Value(), MAX_MAX_FRAME_SIZE), MIN_MAX_FRAME_SIZE));
  }
}

void Http2Settings::GetMaxHeaderListSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  settings->Find(NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, info);
}
void Http2Settings::SetMaxHeaderListSize(
    Local<String> property,
    Local<Value> value,
    const PropertyCallbackInfo<void>& info) {
  Http2Settings* settings;
  ASSIGN_OR_RETURN_UNWRAP(&settings, info.Holder());
  if (value->IsUndefined())
    settings->Erase(NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE);
  else
    settings->Set(NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, value->Uint32Value());
}


// Http2Headers statics

// Create a new Http2Headers object. The first argument is the
// number of headers expected in order to reserve the space.
void Http2Headers::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  new Http2Headers(env, args.This(), args[0]->IntegerValue());
}

void Http2Headers::Add(const FunctionCallbackInfo<Value>& args) {
  Http2Headers* headers;
  ASSIGN_OR_RETURN_UNWRAP(&headers, args.Holder());
  Environment* env = headers->env();
  Utf8Value key(env->isolate(), args[0]);
  Utf8Value value(env->isolate(), args[1]);
  bool noindex = args[2]->BooleanValue();
  headers->Add(*key, *value, key.length(), value.length(), noindex);
}

void Http2Headers::Reserve(const FunctionCallbackInfo<Value>& args) {
  Http2Headers* headers;
  ASSIGN_OR_RETURN_UNWRAP(&headers, args.Holder());
  headers->Reserve(args[0]->IntegerValue());
}

void Http2Headers::Clear(const FunctionCallbackInfo<Value>& args) {
  Http2Headers* headers;
  ASSIGN_OR_RETURN_UNWRAP(&headers, args.Holder());
  headers->Clear();
}

void Http2Headers::GetSize(Local<String> property,
                           const PropertyCallbackInfo<Value>& info) {
  Http2Headers* headers;
  ASSIGN_OR_RETURN_UNWRAP(&headers, info.Holder());
  Environment* env = headers->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), headers->Size()));
}

// Http2Stream Statics

Http2Stream::Http2Stream(Environment* env,
                         Local<Object> wrap,
                         Http2Session* session,
                         int32_t stream_id) :
                         AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2STREAM),
                         StreamBase(env),
                         session_(session),
                         stream_id_(stream_id) {
  Wrap(object(), this);
  str_in_ = NodeBIO::New();
  str_out_ = NodeBIO::New();
  NodeBIO::FromBIO(str_in_)->AssignEnvironment(env);
  NodeBIO::FromBIO(str_out_)->AssignEnvironment(env);
  provider_.read_callback = Http2Stream::on_read;
  provider_.source.ptr = this;
  set_alloc_cb({ OnAllocSelf, this });
  set_read_cb({ OnReadSelf, this });
  nghttp2_session_set_stream_user_data(**session, stream_id, this);
}

nghttp2_stream* Http2Stream::operator*() {
  return nghttp2_session_find_stream(**session(), id());
}

void Http2Stream::Detach() {
  if (!detached_) {
    CHECK_NE(session_, nullptr);
    detached_ = true;
    nghttp2_session_set_stream_user_data(**session_, stream_id_, nullptr);
    provider_.read_callback = nullptr;
    provider_.source.ptr = nullptr;
    session_ = nullptr;
    // Emit Detached Event on the Http2Stream object to notify
    // the JS side that the underlying nghttp2_stream handle
    // is no longer valid.
    Local<Value> argv[] { env()->detached_string() };
    Emit(argv, arraysize(argv));
  }
}

void Http2Stream::Dispose(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  ClearWrap(stream->object());
  stream->persistent().Reset();
  delete stream;
}

// Called when chunks of data from a DATA frame are received for this stream.
// This will only be called if the Http2Stream is still attached to the session.
void Http2Stream::ReceiveData(const uint8_t* data, size_t len) {
  CHECK_NE(str_in_, nullptr);
  NodeBIO::FromBIO(str_in_)->Write(
      reinterpret_cast<const char*>(data),
      len);
  EmitPendingData();
}

void Http2Stream::OnAllocSelf(size_t suggested_size, uv_buf_t* buf, void* ctx) {
  buf->base = node::Malloc(suggested_size);
  buf->len = suggested_size;
}

void Http2Stream::OnReadSelf(ssize_t nread,
                             const uv_buf_t* buf,
                             uv_handle_type pending,
                             void* ctx) {
  Http2Stream* wrap = static_cast<Http2Stream*>(ctx);
  Local<Object> buf_obj;
  if (buf != nullptr)
    buf_obj = Buffer::New(wrap->env(), buf->base, buf->len).ToLocalChecked();
  wrap->EmitData(nread, buf_obj, Local<Object>());
}

void Http2Stream::EmitPendingData() {
  if (!reading_) return;
  // Rules, emit if there is any data pending in str_in_
  NodeBIO* in = NodeBIO::FromBIO(str_in_);
  while (in->Length() > 0) {
    size_t avail = 0;
    char* data = in->Peek(&avail);
    uv_buf_t buf;
    OnAlloc(avail, &buf);
    if (buf.len < avail)
      avail = buf.len;
    memcpy(buf.base, data, avail);
    OnRead(avail, &buf);
    in->Read(nullptr, avail);
  }

  // If str_in_ is empty and stream is remote closed, emit EOF
  if (nghttp2_session_get_stream_remote_close(**session(), id()) != 0) {
    OnRead(UV_EOF, nullptr);
  }
  // If str_in_ is empty and stream is not remote closed, do nothing
}

// Returns the AsyncWrap uid for the Http2Stream instance. This is
// provided primarily for debugging and logging purposes.
void Http2Stream::GetUid(Local<String> property,
                         const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  Environment* env = stream->env();
  args.GetReturnValue().Set(Number::New(env->isolate(), stream->get_uid()));
}

// Returns the Http2Session associated with this Http2Stream. Returns
// Undefined if the Http2Stream instance is detached.
void Http2Stream::GetSession(Local<String> property,
                             const PropertyCallbackInfo<Value>& info) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, info.Holder());
  if (stream->detached_) return;
  info.GetReturnValue().Set(stream->session()->object());
}

// Returns the HTTP/2 Stream ID as a signed 32-bit integer
void Http2Stream::GetID(Local<String> property,
                        const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(stream->id());
}

// Returns the current state of the HTTP/2 Stream as provided
// by nghttp2. If the Http2Stream is detached, the state is
// reported as NGHTTP2_STREAM_STATE_CLOSED
void Http2Stream::GetState(Local<String> property,
                           const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  nghttp2_stream_proto_state state =
      stream->detached_ ? NGHTTP2_STREAM_STATE_CLOSED :
                          nghttp2_stream_get_state(**stream);
  args.GetReturnValue().Set(state);
}

// Returns the nghttp2 managed summed dependency weight of this
// Http2Stream instance. If the Http2Stream instance is detached,
// then a value of 0 is returned.
void Http2Stream::GetSumDependencyWeight(
    Local<String> property,
    const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(
      stream->detached_ ? 0 :
          nghttp2_stream_get_sum_dependency_weight(**stream));
}

// Returns the nghttp2 managed priority weight of this Http2Stream
// instance. If the Http2Stream instance is detached, then a value
// of 0 is returned.
void Http2Stream::GetWeight(Local<String> property,
                            const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(
      stream->detached_ ? 0 : nghttp2_stream_get_weight(**stream));
}

// Return the Local Window Size for this Http2Stream instance.
// If the Http2Stream instance is detached, a value of 0 is returned
void Http2Stream::GetLocalWindowSize(Local<String> property,
                                     const PropertyCallbackInfo<Value>& info) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, info.Holder());
  if (stream->detached_) {
    info.GetReturnValue().Set(0);
  } else {
    Http2Session* session = stream->session();
    CHECK(**session);
    info.GetReturnValue().Set(
        nghttp2_session_get_stream_local_window_size(**session, stream->id()));
  }
}

// Modify the Local Window Size of this Http2Stream. This may
// result in a WINDOW_UPDATE frame being sent to the peer. If
// the Http2Stream instance is detached, this is a non-op
void Http2Stream::SetLocalWindowSize(Local<String> property,
                                     Local<Value> value,
                                     const PropertyCallbackInfo<void>& info) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, info.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  nghttp2_session_set_local_window_size(
      **session, NGHTTP2_FLAG_NONE, stream->id(), value->Int32Value());
}

// Returns 1 if the local peer half closed the stream, returns
// 0 if it did not, and -1 if the stream ID is unknown or if
// the Http2Stream instance is detached.
void Http2Stream::GetStreamLocalClose(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, info.Holder());
  if (stream->detached_) {
    info.GetReturnValue().Set(-1);
  } else {
    Http2Session* session = stream->session();
    CHECK(**session);
    info.GetReturnValue().Set(
        nghttp2_session_get_stream_local_close(**session, stream->id()));
  }
}

// Returns 1 if the remote peer half closed the stream, returns
// 0 if it did not, and -1 if the stream ID is unknown or if
// the Http2Stream instance is detached.
void Http2Stream::GetStreamRemoteClose(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, info.Holder());
  if (stream->detached_) {
    info.GetReturnValue().Set(-1);
  } else {
    Http2Session* session = stream->session();
    CHECK(**session);
    info.GetReturnValue().Set(
        nghttp2_session_get_stream_remote_close(**session, stream->id()));
  }
}

void Http2Stream::Resume() {
  if (detached_) return;
  nghttp2_session_resume_data(**session_, id());
  session_->SendIfNecessary();
}

// Tells nghttp2 to resume sending DATA frames for this stream. This
// is a non-op if the Http2Stream instance is detached.
void Http2Stream::ResumeData(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Resume();
}

// Send a 100-Continue response. In HTTP/2, a 100-continue is implemented
// by sending a HEADERS frame on the stream before the primary response
// HEADERS frame. These are distinguished on the client by the use of the
// 100 status code. If this Http2Stream instance is detached, then this
// is a non-op.
// TODO(jasnell): Currently, this does not permit any additional headers
// to be sent along with the 100 status.
void Http2Stream::SendContinue(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  nghttp2_nv headers[] {{
    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(HTTP2_HEADER_STATUS)),
    const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>("100")),
    strlen(HTTP2_HEADER_STATUS), 3, NGHTTP2_NV_FLAG_NONE
  }};
  int rv = nghttp2_submit_headers(**session, NGHTTP2_FLAG_NONE, stream->id(),
                                  nullptr, &headers[0], 1, nullptr);
  session->EmitErrorIfFail(rv);
}

// Initiate sending a response. Response Headers must have been set
// before calling. This will result in sending an initial HEADERS
// frame (or multiple), zero or more DATA frames, and zero or more
// trailing HEADERS frames. If this Http2Stream instance is detached
// then this is a non-op
void Http2Stream::Respond(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  bool nodata = args[0]->BooleanValue();
  nghttp2_data_provider* provider = nodata ? nullptr : stream->provider();
  int rv = nghttp2_submit_response(**session,
                                   stream->id(),
                                   stream->OutgoingHeaders(),
                                   stream->OutgoingHeadersCount(),
                                   provider);
  session->EmitErrorIfFail(rv);
}

// Send an RST-STREAM frame for this stream. The first argument is
// an unsigned int32 that identifies the RST-STREAM error code. If
// this Http2Stream instance is detached then this is a non-op
void Http2Stream::SendRstStream(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  int rv = nghttp2_submit_rst_stream(**session, NGHTTP2_FLAG_NONE,
                                     stream->id(), args[0]->Uint32Value());
  session->EmitErrorIfFail(rv);
}

// Send a PRIORITY frame for this stream. There are three arguments:
//   parent (int32) the ID of the parent stream
//   priority (int32) the priority value to assign
//   exclusive (bool) true to set the exclusive flag
// If this Http2Stream instance is detached, then this is a non-op
void Http2Stream::SendPriority(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  Http2Priority priority(args[0]->Int32Value(),
                         args[1]->Int32Value(),
                         args[2]->BooleanValue());
  int rv = nghttp2_submit_priority(**session, NGHTTP2_FLAG_NONE,
                                   stream->id(), *priority);
  session->EmitErrorIfFail(rv);
}

// Change the stream priority without sending a PRIORITY frame. There
// are three arguments:
//   parent (int32) the ID of the parent stream
//   priority (int32) the priority value to assign
//   exclusive (bool) true to set the exclusive flag
// If this Http2Stream instance is detached, then this is a non-op
void Http2Stream::ChangeStreamPriority(
    const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  Http2Priority priority(args[0]->Int32Value(),
                         args[1]->Int32Value(),
                         args[2]->BooleanValue());
  int rv = nghttp2_session_change_stream_priority(**session, stream->id(),
                                                  *priority);
  session->EmitErrorIfFail(rv);
}

// Send a PUSH_PROMISE frame, then create and return the Http2Stream
// instance that is associated. The first argument is an Http2Headers
// object instance used to pass along the PUSH_PROMISE headers. If
// this Http2Stream instance is detached, then this is a non-op
void Http2Stream::SendPushPromise(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  HandleScope scope(env->isolate());
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  if (stream->detached_) return;
  Http2Session* session = stream->session();
  CHECK(**session);
  if (!session->IsServer()) {
    return env->ThrowError("Client Http2Session instances cannot use push");
  }
  Http2Headers* headers;
  THROW_AND_RETURN_UNLESS_HTTP2HEADERS(env, args[0]);
  ASSIGN_OR_RETURN_UNWRAP(&headers, args[0].As<Object>());
  int32_t rv =
      nghttp2_submit_push_promise(**session,
                                  NGHTTP2_FLAG_NONE,
                                  stream->id(),
                                  **headers, headers->Size(),
                                  stream);
  session->EmitErrorIfFail(rv);
  args.GetReturnValue().Set(
      Http2Session::CreateStream(env, session, rv)->object());
}

// Called when end() has been called on the Writable side of the Http2Stream
// Duplex. Sets the internal writable state to false and resumes sending
// any additional data pending so long as the Http2Stream is not detached.
int Http2Stream::DoShutdown(ShutdownWrap* req_wrap) {
  writable_ = false;
  if (!detached_) Resume();
  req_wrap->Dispatched();
  req_wrap->Done(0);
  return 0;
}

// Called when data has been written on the Writable side of the Http2Stream
// Duplex. Causes the data to be buffered on the internal NodeBIO str_out_
// buffer. The data is only buffered if the Http2Stream instance is not
// detached.
int Http2Stream::DoWrite(WriteWrap* w,
                         uv_buf_t* bufs,
                         size_t count,
                         uv_stream_t* send_handle) {
  // Buffer the data for the Data Provider
  CHECK_EQ(send_handle, nullptr);

  // Simply write to the outgoing buffer. The buffer will be
  // written out when the data provider callback is invoked.
  // If the Http2Stream instance has been detached, then it
  // does not do any good to keep storing the data.
  // TODO(jasnell): Later could likely make this a CHECK
  if (!detached_) {
    for (size_t i = 0; i < count; i++) {
      // Only attempt to write if the buf is not empty
      if (bufs[i].len > 0)
        NodeBIO::FromBIO(str_out_)->Write(bufs[i].base, bufs[i].len);
    }
  }
  // Whether detached or not, call dispatch and done.
  w->Dispatched();
  w->Done(0);
  return 0;
}

bool Http2Stream::IsAlive() {
  return !detached_ &&
         nghttp2_stream_get_state(**this) != NGHTTP2_STREAM_STATE_CLOSED;
}

bool Http2Stream::IsClosing() {
  return detached_;
}

// Upon calling ReadStart, the Http2Stream instance will immediately
// emit all of the data currently stored in it's internal buffer and
// will set the reading_ flag to true. While the reading_ flag is set,
// all writes into the internal buffer will trigger the EmitPendingData
// function, allowing data events to be emitted.
int Http2Stream::ReadStart() {
  reading_ = true;
  EmitPendingData();
  return 0;
}

// ReadStop flips the reading_ bit back to false, stopping the EmitPendingData
// method from completing when called.
int Http2Stream::ReadStop() {
  reading_ = false;
  return 0;
}

// on_read is called by nghttp2 to poll for bytes for outbound
// DATA frames. Please see the code comments for on_read in
// node_http2.h for more detail
ssize_t Http2Stream::on_read(nghttp2_session* session,
                             int32_t stream_id,
                             uint8_t* buf,
                             size_t length,
                             uint32_t* flags,
                             nghttp2_data_source* source,
                             void* user_data) {
  Http2Stream* stream = static_cast<Http2Stream*>(source->ptr);
  CHECK(!stream->detached_);

  NodeBIO* bio = NodeBIO::FromBIO(stream->str_out_);

  ssize_t amount = bio->Read(reinterpret_cast<char*>(buf), length);

  if (amount == 0 && stream->writable_) {
    return NGHTTP2_ERR_DEFERRED;
  }
  if (!stream->writable_ && bio->Length() == 0) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;
    if (stream->OutgoingTrailersCount() > 0) {
      // If there are any trailing headers they have to be
      // queued up to send here.
      *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        nghttp2_submit_trailer(session,
                                stream->id(),
                                stream->OutgoingTrailers(),
                                stream->OutgoingTrailersCount());
    }
  }
  return amount;
}

// Adds an outgoing header. These must be set before the Http2Stream::Respond
// method is called. Any headers added after that call will not be sent.
void Http2Stream::AddHeader(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  Utf8Value key(env->isolate(), args[0]);
  Utf8Value value(env->isolate(), args[1]);
  bool noindex = args[2]->BooleanValue();
  stream->AddHeader(*key, *value, key.length(), value.length(), noindex);
}

// Adds an outgoing trailer. These must be set before the writable side
// of the Http2Stream Duplex is end()'ed. Any headers added after that
// call will not be sent. Specifically, the trailers vector is processed
// immediately after reading the final block of data has been submitted
// to nghttp2 for inclusion in the DATA frames. The specific timing is
// somewhat non-deterministic as it depends largely on when nghttp2
// is able to process the outgoing frame queue. The rule is: any trailers
// added after calling end *likely* will not be sent.
void Http2Stream::AddTrailer(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  Utf8Value key(env->isolate(), args[0]);
  Utf8Value value(env->isolate(), args[1]);
  bool noindex = args[2]->BooleanValue();
  stream->AddTrailer(*key, *value, key.length(), value.length(), noindex);
}

// Http2Session Statics

// The Http2Session class wraps an individual nghttp2_session struct.
Http2Session::Http2Session(Environment* env,
                           Local<Object> wrap,
                           enum http2_session_type type,
                           Local<Value> options,
                           Local<Value> external) :
                           AsyncWrap(env, wrap,
                                     AsyncWrap::PROVIDER_HTTP2SESSION),
                           type_(type) {
  MakeWeak<Http2Session>(this);
  nghttp2_session_callbacks* cb;
  nghttp2_session_callbacks_new(&cb);

#define SET_SESSION_CALLBACK(callbacks, name)                                 \
  nghttp2_session_callbacks_set_##name##_callback(callbacks, name);

  SET_SESSION_CALLBACK(cb, send)
  SET_SESSION_CALLBACK(cb, on_frame_recv)
  SET_SESSION_CALLBACK(cb, on_stream_close)
  SET_SESSION_CALLBACK(cb, on_header)
  SET_SESSION_CALLBACK(cb, on_begin_headers)
  SET_SESSION_CALLBACK(cb, on_data_chunk_recv)
  SET_SESSION_CALLBACK(cb, select_padding);

#undef SET_SESSION_CALLBACK

  Http2Options opts(env, options);
  if (type == SESSION_TYPE_CLIENT) {
    nghttp2_session_client_new2(&session_, cb, this, *opts);
  } else {
    nghttp2_session_server_new2(&session_, cb, this, *opts);
  }
  nghttp2_session_callbacks_del(cb);

  // When the Http2Session instance is created, it takes
  // over consumption of the underlying stream in order
  // to optimize reads and writes.
  if (!external.IsEmpty() && external->IsExternal()) {
    Consume(external);
  }
}

static const size_t kAllocBufferSize = 64 * 1024;

// Used to allocate buffer space when reading from the
// underlying stream.
void Http2Session::OnAllocImpl(size_t suggested_size,
                               uv_buf_t* buf,
                               void* ctx) {
  Http2Session* session = static_cast<Http2Session*>(ctx);
  Environment* env = session->env();

  if (env->http2_socket_buffer() == nullptr)
    env->set_http2_socket_buffer(new char[kAllocBufferSize]);

  buf->base = env->http2_socket_buffer();
  buf->len = kAllocBufferSize;
}

// Used when reading data from the underlying stream
void Http2Session::OnReadImpl(ssize_t nread,
                              const uv_buf_t* buf,
                              uv_handle_type pending,
                              void* ctx) {
  Http2Session* session = static_cast<Http2Session*>(ctx);

  if (nread < 0) {
    uv_buf_t tmp_buf;
    tmp_buf.base = nullptr;
    tmp_buf.len = 0;
    session->prev_read_cb_.fn(nread,
                              &tmp_buf,
                              pending,
                              session->prev_read_cb_.ctx);
    return;
  }

  // Pass the read data on to nghttp2 for processing
  nghttp2_session_mem_recv(**session,
                           reinterpret_cast<const uint8_t*>(buf->base),
                           nread);
  // Send any pending frame that exist in nghttp2 queue
  session->SendIfNecessary();
}

// Release the captured stream. Currently this is done
// only when the Http2Stream is deconstructed.
void Http2Session::Unconsume() {
  if (prev_alloc_cb_.is_empty())
    return;
  stream_->set_alloc_cb(prev_alloc_cb_);
  stream_->set_read_cb(prev_read_cb_);
  prev_alloc_cb_.clear();
  prev_read_cb_.clear();
  stream_ = nullptr;
}

// Capture the stream that will this session will use to send and
// receive data
void Http2Session::Consume(Local<Value> external) {
  Local<External> stream_obj = external.As<External>();
  StreamBase* stream = static_cast<StreamBase*>(stream_obj->Value());
  CHECK_NE(stream, nullptr);

  stream->Consume();

  stream_ = stream;
  prev_alloc_cb_ = stream->alloc_cb();
  prev_read_cb_ = stream->read_cb();

  stream->set_alloc_cb({ Http2Session::OnAllocImpl, this });
  stream->set_read_cb({ Http2Session::OnReadImpl, this });
}

// Gets the AsyncWrap uid of the Http2Session object. This is provided
// primarily for debugging purposes.
void Http2Session::GetUid(Local<String> property,
                          const PropertyCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  args.GetReturnValue().Set(Number::New(env->isolate(), session->get_uid()));
}

// Called by nghttp2 when there is data to send on this session.
// This is generally trigged by calling the Http2Session::SendIfNecessary
// method but there are other APIs that will trigger it also. The data
// buffer passed in contains the serialized frame data to be sent to
// the stream.
ssize_t Http2Session::send(nghttp2_session* session,
                           const uint8_t* data,
                           size_t length,
                           int flags,
                           void *user_data) {
  Http2Session* session_obj = static_cast<Http2Session*>(user_data);
  CHECK_NE(session_obj, nullptr);
  Environment* env = session_obj->env();

  Local<Object> req_wrap_obj =
      env->write_wrap_constructor_function()
          ->NewInstance(env->context()).ToLocalChecked();

  auto cb = [](WriteWrap* req, int status) {};
  WriteWrap* write_req = WriteWrap::New(env,
                                        req_wrap_obj,
                                        nullptr,
                                        cb);

  uv_buf_t buf[] {
    uv_buf_init(
        const_cast<char*>(reinterpret_cast<const char*>(data)),
        length)
  };
  int err = session_obj->stream_->DoWrite(write_req, buf, 1, nullptr);

  if (err) {
    // Ignore Errors
    write_req->Dispose();
  }
  return length;
}

// Called whenever an RST_STREAM frame has been received. Results
// in the emission of an rststream event. The event is emitted
// with two arguments: the numeric stream ID and the numeric
// error code. By the time this is emitted, the underlying
// stream object will have already been detached.
int Http2Session::on_rst_stream_frame(Http2Session* session,
                                      int32_t id,
                                      const nghttp2_frame_hd hd,
                                      const nghttp2_rst_stream rst) {
  Environment* env = session->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Value> argv[] {
    env->rststream_string(),
    Integer::New(env->isolate(), id),
    Integer::NewFromUnsigned(env->isolate(), rst.error_code)
  };
  session->Emit(argv, arraysize(argv));

  return 0;
}

// Called whenever a GOAWAY frame has been received. Results
// in the emission of a goaway event. The event is emitted
// with three arguments: the numeric error code, the ID of
// the last processed stream ID as reported by the peer, and
// a Buffer containing any additiona opaque data included in
// the goaway. If there is no opaque data, the third argument
// will be passed as Undefined.
int Http2Session::on_goaway_frame(Http2Session* session,
                                  const nghttp2_frame_hd hd,
                                  const nghttp2_goaway goaway) {
  Environment* env = session->env();
  Isolate* isolate = env->isolate();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Value> opaque_data;
  if (goaway.opaque_data_len > 0) {
    opaque_data =
        Buffer::Copy(env, reinterpret_cast<const char*>(goaway.opaque_data),
                     goaway.opaque_data_len).ToLocalChecked();
  } else {
    opaque_data = Undefined(isolate);
  }

  Local<Value> argv[] {
    env->goaway_string(),
    Integer::NewFromUnsigned(isolate, goaway.error_code),
    Integer::New(isolate, goaway.last_stream_id),
    opaque_data
  };
  session->Emit(argv, arraysize(argv));

  return 0;
}

// Called by nghttp2 while processing a chunk of data from a received
// DATA frame. The data is written to the Http2Stream's internal buffer
int Http2Session::on_data_chunk_recv(nghttp2_session* session,
                                     uint8_t flags,
                                     int32_t stream_id,
                                     const uint8_t* data,
                                     size_t len,
                                     void* user_data) {
  Http2Stream* stream = Http2Stream::GetFromSession(session, stream_id);
  CHECK_NE(stream, nullptr);
  stream->ReceiveData(data, len);
  return 0;
}

// Called whenever a HEADERS frame is received. Results in the
// emission of a headers event. The event is emitted with four
// arguments: the associated Http2Stream, the numeric flags
// bit field, the ES6 Map object containing the received headers,
// and a numeric headers type category as provided by nghttp2.
// The category argument indicates whether or not this HEADERS
// frame represents the start of a request, response, push_promise,
// or trailers block. nghttp2 makes the appropriate determination
// based on the current state of the underlying nghttp2_stream.
int Http2Session::on_headers_frame(Http2Session* session,
                                   Http2Stream* stream,
                                   const nghttp2_frame_hd hd,
                                   const nghttp2_headers headers) {
  Environment* env = session->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Value> argv[] {
    env->headers_string(),
    stream->object(),
    Integer::NewFromUnsigned(env->isolate(), hd.flags),
    stream->GetHeaders(),
    Integer::NewFromUnsigned(env->isolate(), stream->GetHeadersCategory())
  };
  session->Emit(argv, arraysize(argv));

  stream->ClearHeaders();
  return 0;
}

// Called when nghttp2 receives a frame from the connected peer.
// nghttp2 will automatically handle several connection specific
// frames such as PRIORITY, PING and WINDOW_UPDATE.
int Http2Session::on_frame_recv(nghttp2_session *session,
                                const nghttp2_frame *frame,
                                void *user_data) {
  Http2Session* session_obj = static_cast<Http2Session*>(user_data);
  CHECK_NE(session_obj, nullptr);
  Http2Stream* stream;
  switch (frame->hd.type) {
  case NGHTTP2_RST_STREAM:
    return on_rst_stream_frame(session_obj,
                               frame->hd.stream_id,
                               frame->hd,
                               frame->rst_stream);
  case NGHTTP2_GOAWAY:
    return on_goaway_frame(session_obj, frame->hd, frame->goaway);
  case NGHTTP2_HEADERS:
    stream = Http2Stream::GetFromSession(session, frame->hd.stream_id);
    CHECK_NE(stream, nullptr);
    return on_headers_frame(session_obj, stream, frame->hd, frame->headers);
  default:
    return 0;
  }
}

// Called by nghttp2 when an underlying nghttp2_stream handle has been
// closed and is no longer valid. We use this to clean up our Http2Stream
// object's associated state.
int Http2Session::on_stream_close(nghttp2_session *session,
                                  int32_t stream_id,
                                  uint32_t error_code,
                                  void *user_data) {
  Http2Session* session_obj = static_cast<Http2Session*>(user_data);
  CHECK_NE(session_obj, nullptr);
  Environment* env = session_obj->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Http2Stream* stream = Http2Stream::GetFromSession(session, stream_id);
  CHECK_NE(stream, nullptr);
  stream->Detach();

  // TODO(jasnell): Collapse this into the detach event. Perhaps use
  // "close" instead of "detach" as the event name
  Local<Value> argv[] {
    env->streamclose_string(),
    stream->object(),
    Integer::NewFromUnsigned(env->isolate(), error_code)
  };
  session_obj->Emit(argv, arraysize(argv));

  return 0;
}

// Called when an individual header name+value pair is processed by nghttp2.
// The name and value are simply collected by the Http2Stream instance.
int Http2Session::on_header(nghttp2_session *session,
                            const nghttp2_frame *frame,
                            const uint8_t *name,
                            size_t namelen,
                            const uint8_t *value,
                            size_t valuelen,
                            uint8_t flags,
                            void *user_data) {
  Http2Stream* stream =
      Http2Stream::GetFromSession(session, frame->hd.stream_id);
  CHECK_NE(stream, nullptr);
  stream->SetHeader(name, namelen, value, valuelen);
  return 0;
}

// Called by nghttp2 when beginning to process a block of headers.
// We use the callback here to initialize a new block of header storage
// in the Http2Stream. At any given time, the Http2Stream can process
// only one block of headers at a time.
int Http2Session::on_begin_headers(nghttp2_session* session,
                                   const nghttp2_frame* frame,
                                   void* user_data) {
  Http2Session* session_obj = static_cast<Http2Session*>(user_data);
  CHECK_NE(session_obj, nullptr);
  Environment* env = session_obj->env();
  Http2Stream* stream =
      Http2Stream::GetFromSession(session, frame->hd.stream_id);
  if (stream == nullptr)
    stream = CreateStream(env, session_obj, frame->hd.stream_id);
  CHECK_NE(stream, nullptr);
  stream->SetHeaders(frame->headers.cat);
  return 0;
}

// Called by nghttp2 to determine the amount of padding to use
// for a given frame.
ssize_t Http2Session::select_padding(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     size_t max_payloadlen,
                                     void *user_data) {
  // TODO(jasnell): Determine algorithm for seleting padding
  // Returning any value > frame->hd.length will intrduce
  // padding into the frame.
  return frame->hd.length;
}

// Creates and returns a new Http2Stream instance that wraps an
// nghttp2_stream.
Http2Stream* Http2Session::CreateStream(Environment* env,
                                        Http2Session* session,
                                        uint32_t stream_id) {
  HandleScope scope(env->isolate());
  CHECK_EQ(env->http2stream_constructor_template().IsEmpty(), false);
  Local<Function> constructor =
      env->http2stream_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Object> obj = constructor->NewInstance(env->context()).ToLocalChecked();
  return new Http2Stream(env, obj, session, stream_id);
}

// Create a new Http2Session instance. The first argument is the numeric
// indicator of the type of session to create (see enum http2_session_type).
// The second argument is the options object. The third argument is the
// stream to capture.
void Http2Session::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args.IsConstructCall())
    return env->ThrowTypeError("Class constructor Http2Session cannot "
                               "be invoked without 'new'");
  enum http2_session_type type =
      static_cast<enum http2_session_type>(args[0]->Int32Value());
  if (type != SESSION_TYPE_SERVER && type != SESSION_TYPE_CLIENT)
    return env->ThrowTypeError("Invalid HTTP/2 session type");

  new Http2Session(env, args.This(), type, args[1], args[2]);
}

// Returns true if this Http2Session is expecting to receive data
void Http2Session::GetWantRead(Local<String> property,
                               const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_want_read(**session) != 0);
}

// Returns true if this Http2Stream has data queued up to send
void Http2Session::GetWantWrite(Local<String> property,
                                const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_want_write(**session) != 0);
}

// Returns the Http2Session type identifier.
void Http2Session::GetType(Local<String> property,
                           const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(session->type_);
}


void Http2Session::GetEffectiveLocalWindowSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(
      nghttp2_session_get_effective_local_window_size(**session));
}


void Http2Session::GetEffectiveRecvDataLength(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(
      nghttp2_session_get_effective_recv_data_length(**session));
}


void Http2Session::GetNextStreamID(Local<String> property,
                                   const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_get_next_stream_id(**session));
}


void Http2Session::SetNextStreamID(Local<String> property,
                                   Local<Value> value,
                                   const PropertyCallbackInfo<void>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  int32_t id = value->Int32Value();
  nghttp2_session_set_next_stream_id(**session, id);
}


void Http2Session::GetLocalWindowSize(Local<String> property,
                                   const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_get_local_window_size(**session));
}

void Http2Session::SetLocalWindowSize(Local<String> property,
                                      Local<Value> value,
                                      const PropertyCallbackInfo<void>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  nghttp2_session_set_local_window_size(
      **session, NGHTTP2_FLAG_NONE, 0, value->Int32Value());
}

void Http2Session::GetLastProcStreamID(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_get_last_proc_stream_id(**session));
}


void Http2Session::GetRemoteWindowSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  info.GetReturnValue().Set(nghttp2_session_get_remote_window_size(**session));
}


void Http2Session::GetOutboundQueueSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  size_t size = nghttp2_session_get_outbound_queue_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}


void Http2Session::GetDeflateDynamicTableSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  size_t size = nghttp2_session_get_hd_deflate_dynamic_table_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}


void Http2Session::GetInflateDynamicTableSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  size_t size = nghttp2_session_get_hd_inflate_dynamic_table_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}

void Http2Session::GetLocalSettings(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  Environment* env = session->env();
  HandleScope scope(env->isolate());
  CHECK_EQ(env->http2settings_constructor_template().IsEmpty(), false);
  Local<Function> constructor =
      env->http2settings_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Object> obj = constructor->NewInstance(env->context()).ToLocalChecked();
  new Http2Settings(env, obj, session, true);
  info.GetReturnValue().Set(obj);
}

void Http2Session::SetLocalSettings(
  Local<String> property,
  Local<Value> value,
  const PropertyCallbackInfo<void>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  Environment* env = session->env();

  Http2Settings* settings;
  THROW_AND_RETURN_UNLESS_HTTP2SETTINGS(env, value);
  ASSIGN_OR_RETURN_UNWRAP(&settings, value.As<Object>());
  std::vector<nghttp2_settings_entry> entries;
  settings->CollectSettings(&entries);

  nghttp2_submit_settings(**session, NGHTTP2_FLAG_NONE,
                          &entries[0], entries.size());
  session->SendIfNecessary();
}

void Http2Session::GetRemoteSettings(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  Environment* env = session->env();

  HandleScope scope(env->isolate());
  CHECK_EQ(env->http2settings_constructor_template().IsEmpty(), false);
  Local<Function> constructor =
      env->http2settings_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Object> obj = constructor->NewInstance(env->context()).ToLocalChecked();
  new Http2Settings(env, obj, session, false);
  info.GetReturnValue().Set(obj);
}

// Releases state but does not completely tear everything down. Currently
// this is mainly used to release the consumption of the underlying stream
// once the socket has been destroyed. This will effectively make the
// session a non-op. Because the Ht2Session constructor calls MakeWeak,
// the ~Http2Session destructor wil called to clean up the rest when
// the object eventually gets garbage collected.
void Http2Session::Destroy(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Unconsume();
}

// Signals termination of the nghttp2_session by sending a GOAWAY
// frame. The only argument is the goaway error code.
void Http2Session::Terminate(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  uint32_t error_code = args[0]->Uint32Value();
  uint32_t last_proc = nghttp2_session_get_last_proc_stream_id(**session);

  int rv = last_proc > 0 ?
    nghttp2_session_terminate_session2(**session, last_proc, error_code) :
    nghttp2_session_terminate_session(**session, error_code);
  session->EmitErrorIfFail(rv);

  rv = session->SendIfNecessary();
  session->EmitErrorIfFail(rv);
}

// Signals initiation of a graceful termination process. Calling this
// method by itself is not sufficient as this only sends a frame that
// gives a pre-termination-warning to the peer. A subsequent call to
// Terminate must be called either in nextTick or setImmediate to
// complete the termination (ideally it would be in exactly one RTT)
void Http2Session::GracefulTerminate(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  int rv = nghttp2_submit_shutdown_notice(**session);
  session->EmitErrorIfFail(rv);

  rv = session->SendIfNecessary();
  session->EmitErrorIfFail(rv);
}

void HttpErrorString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(
      OneByteString(env->isolate(),
                    nghttp2_strerror(args[0]->Uint32Value())));
}


void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  // Method to fetch the nghttp2 string description of an nghttp2 error code
  env->SetMethod(target, "nghttp2ErrorString", HttpErrorString);

  Local<String> http2HeadersClassName =
    FIXED_ONE_BYTE_STRING(isolate, "Http2Headers");
  Local<String> http2SessionClassName =
    FIXED_ONE_BYTE_STRING(isolate, "Http2Session");
  Local<String> http2StreamClassName =
    FIXED_ONE_BYTE_STRING(isolate, "Http2Stream");
  Local<String> http2SettingsClassName =
    FIXED_ONE_BYTE_STRING(isolate, "Http2Settings");

  // Persistent FunctionTemplate for Http2Stream. Instances of this
  // class are only intended to be created by Http2Session::CreateStream
  // so the constructor is not exposed via the binding.
  Local<FunctionTemplate> stream_constructor_template =
     Local<FunctionTemplate>(FunctionTemplate::New(isolate));
  stream_constructor_template->SetClassName(http2StreamClassName);
  Local<ObjectTemplate> stream_template =
      stream_constructor_template->InstanceTemplate();
  stream_template->SetInternalFieldCount(1);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "uid"),
      Http2Stream::GetUid,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "session"),
      Http2Stream::GetSession,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "id"),
      Http2Stream::GetID,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "state"),
      Http2Stream::GetState,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "weight"),
      Http2Stream::GetWeight,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "sumDependencyWeight"),
      Http2Stream::GetSumDependencyWeight,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "localClose"),
      Http2Stream::GetStreamLocalClose,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "remoteClose"),
      Http2Stream::GetStreamRemoteClose,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  stream_template->SetAccessor(
    FIXED_ONE_BYTE_STRING(isolate, "localWindowSize"),
    Http2Stream::GetLocalWindowSize,
    Http2Stream::SetLocalWindowSize,
    Local<Value>(),
    v8::DEFAULT,
    v8::DontDelete);
  env->SetProtoMethod(stream_constructor_template,
                      "changeStreamPriority",
                      Http2Stream::ChangeStreamPriority);
  env->SetProtoMethod(stream_constructor_template,
                      "respond",
                      Http2Stream::Respond);
  env->SetProtoMethod(stream_constructor_template,
                      "resumeData",
                      Http2Stream::ResumeData);
  env->SetProtoMethod(stream_constructor_template,
                      "sendContinue",
                      Http2Stream::SendContinue);
  env->SetProtoMethod(stream_constructor_template,
                      "sendPriority",
                      Http2Stream::SendPriority);
  env->SetProtoMethod(stream_constructor_template,
                      "sendRstStream",
                      Http2Stream::SendRstStream);
  env->SetProtoMethod(stream_constructor_template,
                      "sendPushPromise",
                      Http2Stream::SendPushPromise);
  env->SetProtoMethod(stream_constructor_template,
                      "addHeader",
                      Http2Stream::AddHeader);
  env->SetProtoMethod(stream_constructor_template,
                      "addTrailer",
                      Http2Stream::AddTrailer);
  env->SetProtoMethod(stream_constructor_template,
                      "destroy",
                      Http2Stream::Dispose);
  StreamBase::AddMethods<Http2Stream>(env, stream_constructor_template,
                                      StreamBase::kFlagHasWritev);

  env->set_http2stream_constructor_template(stream_constructor_template);
  target->Set(http2StreamClassName, stream_constructor_template->GetFunction());

  // Http2Settings Template
  Local<FunctionTemplate> settings =
      env->NewFunctionTemplate(Http2Settings::New);
  settings->SetClassName(http2SettingsClassName);
  Local<ObjectTemplate> settings_object = settings->InstanceTemplate();
  settings_object->SetInternalFieldCount(1);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "headerTableSize"),
      Http2Settings::GetHeaderTableSize,
      Http2Settings::SetHeaderTableSize,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "enablePush"),
      Http2Settings::GetEnablePush,
      Http2Settings::SetEnablePush,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "maxConcurrentStreams"),
      Http2Settings::GetMaxConcurrentStreams,
      Http2Settings::SetMaxConcurrentStreams,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "initialWindowSize"),
      Http2Settings::GetInitialWindowSize,
      Http2Settings::SetInitialWindowSize,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "maxFrameSize"),
      Http2Settings::GetMaxFrameSize,
      Http2Settings::SetMaxFrameSize,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  settings_object->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "maxHeaderListSize"),
      Http2Settings::GetMaxHeaderListSize,
      Http2Settings::SetMaxHeaderListSize,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  env->SetProtoMethod(settings, "setDefaults", Http2Settings::Defaults);
  env->SetProtoMethod(settings, "reset", Http2Settings::Reset);
  env->SetProtoMethod(settings, "pack", Http2Settings::Pack);
  env->set_http2settings_constructor_template(settings);
  target->Set(context,
              http2SettingsClassName,
              settings->GetFunction()).FromJust();

  // Http2Headers Template
  Local<FunctionTemplate> headers =
      env->NewFunctionTemplate(Http2Headers::New);
  headers->InstanceTemplate()->SetInternalFieldCount(1);
  headers->SetClassName(http2HeadersClassName);
  headers->InstanceTemplate()->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "size"),
      Http2Headers::GetSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  env->SetProtoMethod(headers, "add", Http2Headers::Add);
  env->SetProtoMethod(headers, "clear", Http2Headers::Clear);
  env->SetProtoMethod(headers, "reserve", Http2Headers::Reserve);
  env->set_http2headers_constructor_template(headers);
  target->Set(context,
              http2HeadersClassName,
              headers->GetFunction()).FromJust();

  // Http2Session Template
  Local<FunctionTemplate> t =
      env->NewFunctionTemplate(Http2Session::New);
  t->SetClassName(http2SessionClassName);
  Local<ObjectTemplate> instance = t->InstanceTemplate();
  instance->SetInternalFieldCount(1);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "uid"),
      Http2Session::GetUid,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "wantWrite"),
      Http2Session::GetWantWrite,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "wantRead"),
      Http2Session::GetWantRead,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "type"),
      Http2Session::GetType,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "nextStreamID"),
      Http2Session::GetNextStreamID,
      Http2Session::SetNextStreamID,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "effectiveLocalWindowSize"),
      Http2Session::GetEffectiveLocalWindowSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "effectiveRecvDataLength"),
      Http2Session::GetEffectiveRecvDataLength,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "lastProcStreamID"),
      Http2Session::GetLastProcStreamID,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "outboundQueueSize"),
      Http2Session::GetOutboundQueueSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "remoteWindowSize"),
      Http2Session::GetRemoteWindowSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "deflateDynamicTableSize"),
      Http2Session::GetDeflateDynamicTableSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "inflateDynamicTableSize"),
      Http2Session::GetInflateDynamicTableSize,
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
      FIXED_ONE_BYTE_STRING(isolate, "localWindowSize"),
      Http2Session::GetLocalWindowSize,
      Http2Session::SetLocalWindowSize,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);
  instance->SetAccessor(
    FIXED_ONE_BYTE_STRING(isolate, "localSettings"),
    Http2Session::GetLocalSettings,
    Http2Session::SetLocalSettings,
    Local<Value>(),
    v8::DEFAULT,
    v8::DontDelete);
  instance->SetAccessor(
    FIXED_ONE_BYTE_STRING(isolate, "remoteSettings"),
    Http2Session::GetRemoteSettings,
    nullptr,
    Local<Value>(),
    v8::DEFAULT,
    v8::DontDelete);

  env->SetProtoMethod(t, "startGracefulTerminate",
                      Http2Session::GracefulTerminate);
  env->SetProtoMethod(t, "destroy", Http2Session::Destroy);
  env->SetProtoMethod(t, "terminate", Http2Session::Terminate);


  target->Set(context,
              http2SessionClassName,
              t->GetFunction()).FromJust();

  Local<Object> constants = Object::New(isolate);
  NODE_DEFINE_CONSTANT(constants, SESSION_TYPE_SERVER);
  NODE_DEFINE_CONSTANT(constants, SESSION_TYPE_CLIENT);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_IDLE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_OPEN);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_RESERVED_LOCAL);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_RESERVED_REMOTE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_CLOSED);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_HCAT_REQUEST);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_HCAT_RESPONSE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_HCAT_PUSH_RESPONSE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_HCAT_HEADERS);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_NO_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_PROTOCOL_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_INTERNAL_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLOW_CONTROL_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_TIMEOUT);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_CLOSED);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FRAME_SIZE_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_REFUSED_STREAM);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_CANCEL);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_COMPRESSION_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_CONNECT_ERROR);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_ENHANCE_YOUR_CALM);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_INADEQUATE_SECURITY);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_HTTP_1_1_REQUIRED);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_NV_FLAG_NONE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_NV_FLAG_NO_INDEX);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_NV_FLAG_NO_COPY_NAME);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_NV_FLAG_NO_COPY_VALUE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_ERR_DEFERRED);

  NODE_DEFINE_STRING_CONSTANT(constants,
                              "HTTP2_HEADER_STATUS",
                              HTTP2_HEADER_STATUS);
  NODE_DEFINE_STRING_CONSTANT(constants,
                              "HTTP2_HEADER_METHOD",
                              HTTP2_HEADER_METHOD);
  NODE_DEFINE_STRING_CONSTANT(constants,
                              "HTTP2_HEADER_AUTHORITY",
                              HTTP2_HEADER_AUTHORITY);
  NODE_DEFINE_STRING_CONSTANT(constants,
                              "HTTP2_HEADER_SCHEME",
                              HTTP2_HEADER_SCHEME);
  NODE_DEFINE_STRING_CONSTANT(constants,
                              "HTTP2_HEADER_PATH",
                              HTTP2_HEADER_PATH);

#define V(name, _) NODE_DEFINE_CONSTANT(constants, HTTP_STATUS_##name);
HTTP_STATUS_CODES(V)
#undef V

#define V(name) NODE_DEFINE_CONSTANT(constants, FLAG_##name);
DATA_FLAGS(V)
#undef V

  target->Set(context,
              FIXED_ONE_BYTE_STRING(isolate, "constants"),
              constants).FromJust();
}
}  // namespace http2
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(http2, node::http2::Initialize)
