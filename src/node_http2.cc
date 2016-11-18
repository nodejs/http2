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

void Http2Stream::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  new Http2Stream(env, args.This());
}

void Http2Stream::Initialize(Http2Session* session,
                             int32_t id,
                             nghttp2_headers_category category) {
  session_ = session;
  stream_id_ = id;
  SetHeaders(category);
  nghttp2_session_set_stream_user_data(**session, id, this);
}

// Detaches the Http2Stream instance from the underlying Http2Session
void Http2Stream::Reset() {
  if (session_ != nullptr) {
    if (**session_ != nullptr)
      nghttp2_session_set_stream_user_data(**session_, stream_id_, nullptr);
    session_ = nullptr;
    NodeBIO::FromBIO(str_in_)->Reset();
    NodeBIO::FromBIO(str_out_)->Reset();
    outgoing_headers_.clear();
    outgoing_trailers_.clear();
    writable_ = true;
    reading_ = false;
  }
}

void Http2Stream::Reinitialize(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  CHECK_EQ(env, stream->env());
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());
  nghttp2_headers_category category =
    static_cast<nghttp2_headers_category>(args[2]->Uint32Value());
  stream->Initialize(session, args[1]->Int32Value(), category);
}

void Http2Stream::Reset(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->Reset();
}

void Http2Stream::Close(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  delete stream;
}

nghttp2_stream* Http2Stream::operator*() {
  return nghttp2_session_find_stream(**session(), id());
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

// Passes incoming data received from the peer to the Readable side of
// the Http2Stream duplex.
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

void Http2Stream::GetId(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(stream->stream_id_);
}


// Returns the current state of the HTTP/2 Stream as provided
// by nghttp2. If the Http2Stream is detached, the state is
// reported as NGHTTP2_STREAM_STATE_CLOSED
void Http2Stream::GetState(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();
  Http2Session* session = stream->session();

  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();

  nghttp2_stream_proto_state state = nghttp2_stream_get_state(**stream);
  int32_t w = nghttp2_stream_get_weight(**stream);
  int32_t sdw = nghttp2_stream_get_sum_dependency_weight(**stream);
  int lclose = nghttp2_session_get_stream_local_close(**session, stream->id());
  int rclose = nghttp2_session_get_stream_remote_close(**session, stream->id());
  int32_t size =
      nghttp2_session_get_stream_local_window_size(**session, stream->id());

  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "state"),
           Integer::NewFromUnsigned(isolate, state)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "weight"),
           Integer::New(isolate, w)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "sumDependencyWeight"),
           Integer::New(isolate, sdw)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "streamLocalClose"),
           Integer::New(isolate, lclose)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "streamRemoteClose"),
           Integer::New(isolate, rclose)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "localWindowSize"),
           Integer::New(isolate, size)).FromJust();
}

// Modify the Local Window Size of this Http2Stream. This may
// result in a WINDOW_UPDATE frame being sent to the peer. If
// the Http2Stream instance is detached, this is a non-op
void Http2Stream::SetLocalWindowSize(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());;
  Http2Session* session = stream->session();
  CHECK(**session);
  nghttp2_session_set_local_window_size(
      **session, NGHTTP2_FLAG_NONE, stream->id(), args[0]->Int32Value());
}

void Http2Stream::Resume() {;
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
// trailing HEADERS frames.
void Http2Stream::Respond(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
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
  Http2Session* session = stream->session();
  CHECK(**session);
  if (session->type_ == SESSION_TYPE_CLIENT) {
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

  if (rv > 0) {
    Local<Object> obj = env->http2stream_object()->Clone();
    Http2Stream* ret = new Http2Stream(env, obj);
    ret->Initialize(session, rv, NGHTTP2_HCAT_REQUEST);
    args.GetReturnValue().Set(ret->object());
  }
}

// Called when end() has been called on the Writable side of the Http2Stream
// Duplex. Sets the internal writable state to false and resumes sending
// any additional data pending so long as the Http2Stream is not detached.
void Http2Stream::FinishedWriting(const FunctionCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  stream->writable_ = false;
  stream->Resume();
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

  for (size_t i = 0; i < count; i++) {
    // Only attempt to write if the buf is not empty
    if (bufs[i].len > 0)
      NodeBIO::FromBIO(str_out_)->Write(bufs[i].base, bufs[i].len);
  }

  // Whether detached or not, call dispatch and done.
  w->Dispatched();
  w->Done(0);
  return 0;
}

bool Http2Stream::IsAlive() {
  return nghttp2_stream_get_state(**this) != NGHTTP2_STREAM_STATE_CLOSED;
}

bool Http2Stream::IsClosing() {
  return false;
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

  NodeBIO* bio = NodeBIO::FromBIO(stream->str_out_);

  ssize_t amount = bio->Read(reinterpret_cast<char*>(buf), length);
  bool done = false;
  if (amount == 0) {
    if (stream->writable_)
      return NGHTTP2_ERR_DEFERRED;
    done = true;
  } else if (!stream->writable_ && bio->Length() == 0) {
    done = true;
  }
  if (done) {
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

// Create a new Http2Session instance. The first argument is the numeric
// indicator of the type of session to create (see enum http2_session_type).
// The second argument is the options object. The third argument is the
// stream to capture.
void Http2Session::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());
  new Http2Session(env, args.This());
}

// (Re)Initialize the Http2Session instance.
// The first argument is the numeric indicator of the type of session_ctx
// The second argument is the options object.
// The third argument is the stream to capture.
void Http2Session::Reinitialize(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  CHECK_EQ(env, session->env());

  enum http2_session_type type =
      static_cast<enum http2_session_type>(args[0]->Int32Value());
  CHECK(type == SESSION_TYPE_SERVER || type == SESSION_TYPE_CLIENT);
  CHECK(args[1]->IsObject());
  CHECK(args[2]->IsExternal());

  session->Initialize(env, type, args[1].As<Object>(), args[2].As<External>());
}

void Http2Session::Initialize(Environment* env,
                              enum http2_session_type type,
                              Local<Value> options,
                              Local<External> external) {
  type_ = type;
  Http2Options opts(env, options);
  if (type == SESSION_TYPE_CLIENT) {
    nghttp2_session_client_new2(&session_, cb_, this, *opts);
  } else {
    nghttp2_session_server_new2(&session_, cb_, this, *opts);
  }
  Consume(external);
}

// Capture the stream that will this session will use to send and receive data
void Http2Session::Consume(Local<External> external) {
  CHECK(prev_alloc_cb_.is_empty());
  StreamBase* stream = static_cast<StreamBase*>(external->Value());
  CHECK_NE(stream, nullptr);
  stream->Consume();
  stream_ = stream;
  prev_alloc_cb_ = stream->alloc_cb();
  prev_read_cb_ = stream->read_cb();
  stream->set_alloc_cb({ Http2Session::OnAllocImpl, this });
  stream->set_read_cb({ Http2Session::OnReadImpl, this });
}

// Release the captured stream (only if currently captured)
void Http2Session::Unconsume() {
  if (prev_alloc_cb_.is_empty())
    return;
  stream_->set_alloc_cb(prev_alloc_cb_);
  stream_->set_read_cb(prev_read_cb_);
  prev_alloc_cb_.clear();
  prev_read_cb_.clear();
  stream_ = nullptr;
}

void Http2Session::Reset() {
  if (session_ != nullptr) {
    Unconsume();
    nghttp2_session_del(session_);
    session_ = nullptr;
  }
}

void Http2Session::Reset(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Reset();
}

void Http2Session::Close(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Reset();
  ClearWrap(session->object());
  session->persistent().Reset();
  delete session;
}

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
  WriteWrap* write_req = WriteWrap::New(env, req_wrap_obj, nullptr, cb);

  uv_buf_t buf[] {
    uv_buf_init(const_cast<char*>(reinterpret_cast<const char*>(data)), length)
  };

  if (session_obj->stream_->DoWrite(write_req, buf, arraysize(buf), nullptr)) {
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
    Integer::New(env->isolate(), id),
    Integer::NewFromUnsigned(env->isolate(), rst.error_code)
  };
  session->Emit(env->rststream_string(), argv, arraysize(argv));

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
    Integer::NewFromUnsigned(isolate, goaway.error_code),
    Integer::New(isolate, goaway.last_stream_id),
    opaque_data
  };
  session->Emit(env->goaway_string(), argv, arraysize(argv));

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
                                   int32_t id,
                                   const nghttp2_frame_hd hd,
                                   const nghttp2_headers headers) {
  Environment* env = session->env();
  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());
  Http2Stream* stream =
      Http2Stream::GetFromSession(**session, id);
  CHECK_NE(stream, nullptr);
  Local<Value> argv[] {
    stream->object(),
    Integer::NewFromUnsigned(env->isolate(), hd.flags),
    stream->GetHeaders(),
    Integer::NewFromUnsigned(env->isolate(), stream->GetHeadersCategory())
  };
  session->Emit(env->headers_string(), argv, arraysize(argv));
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
  switch (frame->hd.type) {
  case NGHTTP2_RST_STREAM:
    return on_rst_stream_frame(session_obj,
                               frame->hd.stream_id,
                               frame->hd,
                               frame->rst_stream);
  case NGHTTP2_GOAWAY:
    return on_goaway_frame(session_obj,
                           frame->hd,
                           frame->goaway);
  case NGHTTP2_HEADERS:
    return on_headers_frame(session_obj,
                            frame->hd.stream_id,
                            frame->hd,
                            frame->headers);
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
  Isolate* isolate = env->isolate();
  HandleScope handle_scope(isolate);

  Local<Value> argv[] {
    Integer::New(isolate, stream_id),
    Integer::NewFromUnsigned(isolate, error_code)
  };
  session_obj->Emit(env->streamclose_string(), argv, arraysize(argv));

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
  Isolate* isolate = env->isolate();
  int32_t id = frame->hd.stream_id;
  Http2Stream* stream = Http2Stream::GetFromSession(session, id);
  if (stream == nullptr) {
    EscapableHandleScope scope(isolate);
    Local<Object> obj = env->http2stream_object()->Clone();
    Http2Stream* stream = new Http2Stream(env, scope.Escape(obj));
    stream->Initialize(session_obj, id, frame->headers.cat);
  } else {
    // Otherwise, begin working on the new headers block
    stream->SetHeaders(frame->headers.cat);
  }
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

void Http2Session::GetState(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Local<Context> context = env->context();

  int32_t elws = nghttp2_session_get_effective_local_window_size(**session);
  int32_t erdl = nghttp2_session_get_effective_recv_data_length(**session);
  uint32_t nextid = nghttp2_session_get_next_stream_id(**session);
  int32_t slws = nghttp2_session_get_local_window_size(**session);
  int32_t lpsid = nghttp2_session_get_last_proc_stream_id(**session);
  int32_t srws = nghttp2_session_get_remote_window_size(**session);
  size_t outbound_size = nghttp2_session_get_outbound_queue_size(**session);
  size_t ddts = nghttp2_session_get_hd_deflate_dynamic_table_size(**session);
  size_t idts = nghttp2_session_get_hd_inflate_dynamic_table_size(**session);

  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "effectiveLocalWindowSize"),
           Integer::New(isolate, elws)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "effectiveRecvDataLength"),
           Integer::New(isolate, erdl)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "nextStreamID"),
           Integer::NewFromUnsigned(isolate, nextid)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "localWindowSize"),
           Integer::New(isolate, slws)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "lastProcStreamID"),
           Integer::New(isolate, lpsid)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "remoteWindowSize"),
           Integer::New(isolate, srws)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "outboundQueueSize"),
           Integer::NewFromUnsigned(isolate, outbound_size)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "deflateDynamicTableSize"),
           Integer::NewFromUnsigned(isolate, ddts)).FromJust();
  obj->Set(context, FIXED_ONE_BYTE_STRING(isolate, "inflateDynamicTableSize"),
           Integer::NewFromUnsigned(isolate, idts)).FromJust();
}

void Http2Session::SetNextStreamID(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  nghttp2_session_set_next_stream_id(**session, args[0]->Int32Value());
}

void Http2Session::SetLocalWindowSize(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  nghttp2_session_set_local_window_size(
      **session, NGHTTP2_FLAG_NONE, 0, args[0]->Int32Value());
}

void Http2Session::GetLocalSettings(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  HandleScope scope(env->isolate());
  CHECK_EQ(env->http2settings_constructor_template().IsEmpty(), false);
  Local<Function> constructor =
      env->http2settings_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Object> obj = constructor->NewInstance(env->context()).ToLocalChecked();
  new Http2Settings(env, obj, session, true);
  args.GetReturnValue().Set(obj);
}

void Http2Session::SetLocalSettings(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();

  Http2Settings* settings;
  THROW_AND_RETURN_UNLESS_HTTP2SETTINGS(env, args[0]);
  ASSIGN_OR_RETURN_UNWRAP(&settings, args[0].As<Object>());
  std::vector<nghttp2_settings_entry> entries;
  settings->CollectSettings(&entries);

  nghttp2_submit_settings(**session, NGHTTP2_FLAG_NONE,
                          &entries[0], entries.size());
  session->SendIfNecessary();
}

void Http2Session::GetRemoteSettings(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();

  HandleScope scope(env->isolate());
  CHECK_EQ(env->http2settings_constructor_template().IsEmpty(), false);
  Local<Function> constructor =
      env->http2settings_constructor_template()->GetFunction();
  CHECK_EQ(constructor.IsEmpty(), false);
  Local<Object> obj = constructor->NewInstance(env->context()).ToLocalChecked();
  new Http2Settings(env, obj, session, false);
  args.GetReturnValue().Set(obj);
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

// Initiate sending a request. Request headers must be passed as an
// argument in the form of an Http2Headers object. This will result
// in sending an initial HEADERS frame (or multiple), zero or more
// DATA frames, and zero or more trailing HEADERS frames.
void Http2Session::Request(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();

  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(**session);

  EscapableHandleScope scope(isolate);
  Local<Object> obj = env->http2stream_object()->Clone();
  Http2Stream* stream = new Http2Stream(env, scope.Escape(obj));

  Http2Headers* headers;
  THROW_AND_RETURN_UNLESS_HTTP2HEADERS(env, args[0]);
  ASSIGN_OR_RETURN_UNWRAP(&headers, args[0].As<Object>());

  bool nodata = args[1]->BooleanValue();
  nghttp2_data_provider* provider = nodata ? nullptr : stream->provider();

  const nghttp2_priority_spec* pri = NULL;

  int32_t rv = nghttp2_submit_request(**session, pri,
                                      **headers, headers->Size(),
                                      provider, stream);

  session->EmitErrorIfFail(rv);

  if (rv > 0) {
    stream->Initialize(session, rv, NGHTTP2_HCAT_RESPONSE);
    args.GetReturnValue().Set(stream->object());
  }
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
    String::NewFromUtf8(isolate, "Http2Headers",
                        v8::NewStringType::kInternalized).ToLocalChecked();
  Local<String> http2SessionClassName =
    String::NewFromUtf8(isolate, "Http2Session",
                        v8::NewStringType::kInternalized).ToLocalChecked();
  Local<String> http2StreamClassName =
    String::NewFromUtf8(isolate, "Http2Stream",
                        v8::NewStringType::kInternalized).ToLocalChecked();
  Local<String> http2SettingsClassName =
    String::NewFromUtf8(isolate, "Http2Settings",
                        v8::NewStringType::kInternalized).ToLocalChecked();

  // Persistent FunctionTemplate for Http2Stream. Instances of this
  // class are only intended to be created by Http2Session::CreateStream
  // so the constructor is not exposed via the binding.
  Local<FunctionTemplate> stream = env->NewFunctionTemplate(Http2Stream::New);
  stream->SetClassName(http2StreamClassName);
  stream->InstanceTemplate()->SetInternalFieldCount(1);

  env->SetProtoMethod(stream, "close", Http2Stream::Close);
  env->SetProtoMethod(stream, "reset", Http2Stream::Reset);
  env->SetProtoMethod(stream, "reinitialize", Http2Stream::Reinitialize);
  env->SetProtoMethod(stream, "getId", Http2Stream::GetId);
  env->SetProtoMethod(stream, "getState", Http2Stream::GetState);
  env->SetProtoMethod(stream, "setLocalWindowSize",
                      Http2Stream::SetLocalWindowSize);

  env->SetProtoMethod(stream, "changeStreamPriority",
                      Http2Stream::ChangeStreamPriority);
  env->SetProtoMethod(stream, "respond", Http2Stream::Respond);
  env->SetProtoMethod(stream, "resume", Http2Stream::ResumeData);
  env->SetProtoMethod(stream, "sendContinue", Http2Stream::SendContinue);
  env->SetProtoMethod(stream, "sendPriority", Http2Stream::SendPriority);
  env->SetProtoMethod(stream, "sendRstStream", Http2Stream::SendRstStream);
  env->SetProtoMethod(stream, "sendPushPromise", Http2Stream::SendPushPromise);
  env->SetProtoMethod(stream, "addHeader", Http2Stream::AddHeader);
  env->SetProtoMethod(stream, "addTrailer", Http2Stream::AddTrailer);
  env->SetProtoMethod(stream, "finishedWriting", Http2Stream::FinishedWriting);
  StreamBase::AddMethods<Http2Stream>(env, stream, StreamBase::kFlagHasWritev |
                                                   StreamBase::kFlagNoShutdown);
  env->set_http2stream_object(
    stream->GetFunction()->NewInstance(env->context()).ToLocalChecked());
  target->Set(http2StreamClassName, stream->GetFunction());

  // Http2Settings Template
  Local<FunctionTemplate> settings =
      env->NewFunctionTemplate(Http2Settings::New);
  settings->SetClassName(http2SettingsClassName);
  settings->InstanceTemplate()->SetInternalFieldCount(1);

  env->SetAccessor(settings,
                   "headerTableSize",
                   Http2Settings::GetHeaderTableSize,
                   Http2Settings::SetHeaderTableSize);
  env->SetAccessor(settings,
                   "enablePush",
                   Http2Settings::GetEnablePush,
                   Http2Settings::SetEnablePush);
  env->SetAccessor(settings,
                   "maxConcurrentStreams",
                   Http2Settings::GetMaxConcurrentStreams,
                   Http2Settings::SetMaxConcurrentStreams);
  env->SetAccessor(settings,
                   "initialWindowSize",
                   Http2Settings::GetInitialWindowSize,
                   Http2Settings::SetInitialWindowSize);
  env->SetAccessor(settings,
                   "maxFrameSize",
                   Http2Settings::GetMaxFrameSize,
                   Http2Settings::SetMaxFrameSize);
  env->SetAccessor(settings,
                   "maxHeaderListSize",
                   Http2Settings::GetMaxHeaderListSize,
                   Http2Settings::SetMaxHeaderListSize);
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
  env->SetAccessor(headers, "size", Http2Headers::GetSize);
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
  t->InstanceTemplate()->SetInternalFieldCount(1);
  env->SetProtoMethod(t, "reinitialize", Http2Session::Reinitialize);
  env->SetProtoMethod(t, "close", Http2Session::Close);
  env->SetProtoMethod(t, "reset", Http2Session::Reset);
  env->SetProtoMethod(t, "terminate", Http2Session::Terminate);
  env->SetProtoMethod(t, "startGracefulTerminate",
                      Http2Session::GracefulTerminate);
  env->SetProtoMethod(t, "request", Http2Session::Request);

  env->SetProtoMethod(t, "getState", Http2Session::GetState);
  env->SetProtoMethod(t, "setNextStreamID", Http2Session::SetNextStreamID);
  env->SetProtoMethod(t, "setLocalWindowSize",
                      Http2Session::SetLocalWindowSize);
  env->SetProtoMethod(t, "getLocalSettings", Http2Session::GetLocalSettings);
  env->SetProtoMethod(t, "setLocalSettings", Http2Session::SetLocalSettings);
  env->SetProtoMethod(t, "getRemoteSettings", Http2Session::GetRemoteSettings);


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
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_ERR_DEFERRED);

#define STRING_CONSTANT(N) NODE_DEFINE_STRING_CONSTANT(constants, #N, N)
  STRING_CONSTANT(HTTP2_HEADER_STATUS);
  STRING_CONSTANT(HTTP2_HEADER_METHOD);
  STRING_CONSTANT(HTTP2_HEADER_AUTHORITY);
  STRING_CONSTANT(HTTP2_HEADER_SCHEME);
  STRING_CONSTANT(HTTP2_HEADER_PATH);
#undef STRING_CONSTANT

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
