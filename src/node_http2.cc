#include "node.h"
#include "node_buffer.h"
#include "node_http2.h"

namespace node {

using v8::ArrayBuffer;
using v8::Boolean;
using v8::Context;
using v8::Integer;

namespace http2 {

static const int kDefaultSettingsCount = 4;

enum Http2SettingsIndex {
  IDX_SETTINGS_HEADER_TABLE_SIZE,
  IDX_SETTINGS_ENABLE_PUSH,
  IDX_SETTINGS_INITIAL_WINDOW_SIZE,
  IDX_SETTINGS_MAX_FRAME_SIZE,
  IDX_SETTINGS_MAX_CONCURRENT_STREAMS,
  IDX_SETTINGS_MAX_HEADER_LIST_SIZE,
  IDX_SETTINGS_COUNT
};

enum Http2SessionStateIndex {
  IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE,
  IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH,
  IDX_SESSION_STATE_NEXT_STREAM_ID,
  IDX_SESSION_STATE_LOCAL_WINDOW_SIZE,
  IDX_SESSION_STATE_LAST_PROC_STREAM_ID,
  IDX_SESSION_STATE_REMOTE_WINDOW_SIZE,
  IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE,
  IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE,
  IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE,
  IDX_SESSION_STATE_COUNT
};

enum Http2StreamStateIndex {
  IDX_STREAM_STATE,
  IDX_STREAM_STATE_WEIGHT,
  IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT,
  IDX_STREAM_STATE_LOCAL_CLOSE,
  IDX_STREAM_STATE_REMOTE_CLOSE,
  IDX_STREAM_STATE_LOCAL_WINDOW_SIZE,
  IDX_STREAM_STATE_COUNT
};

Http2Options::Http2Options(Environment* env, Local<Value> options) {
  nghttp2_option_new(&options_);
  if (options->IsObject()) {
    Local<Object> opts = options.As<Object>();
  Local<Context> context = env->context();

#define V(obj, name, fn, type)                                                \
  do {                                                                        \
    if (obj->Has(context, env->name()).FromJust()) {                          \
      Local<Value> val = obj->Get(context, env->name()).ToLocalChecked();     \
      if (!val->IsUndefined() && !val->IsNull())                              \
        fn(val->type##Value());                                               \
    }                                                                         \
  } while (0);
    OPTIONS(opts, V)
#undef V
  }
}
#undef OPTIONS

inline void CopyHeaders(Isolate* isolate,
                        MaybeStackBuffer<nghttp2_nv>* list,
                        Local<Array> headers) {
  Local<Value> item;
  Local<Array> header;

  for (size_t n = 0; n < headers->Length(); n++) {
    item = headers->Get(n);
    header = item.As<Array>();
    Local<Value> key = header->Get(0);
    Local<Value> value = header->Get(1);
    CHECK(key->IsString());
    CHECK(value->IsString());
    size_t keylen = StringBytes::StorageSize(isolate, key, ASCII);
    size_t valuelen = StringBytes::StorageSize(isolate, value, ASCII);
    nghttp2_nv& nv = (*list)[n];
    nv.flags = NGHTTP2_NV_FLAG_NONE;
    if (header->Get(2)->BooleanValue())
      nv.flags |= NGHTTP2_NV_FLAG_NO_INDEX;
    nv.name = Malloc<uint8_t>(keylen);
    nv.value = Malloc<uint8_t>(valuelen);
    nv.namelen =
        StringBytes::Write(isolate,
                           reinterpret_cast<char*>(nv.name),
                           keylen, key, ASCII);
    nv.valuelen =
        StringBytes::Write(isolate,
                           reinterpret_cast<char*>(nv.value),
                           valuelen, value, ASCII);
  }
}

inline void FreeHeaders(MaybeStackBuffer<nghttp2_nv>* list) {
  for (size_t n = 0; n < list->length(); n++) {
    free((*list)[n].name);
    free((*list)[n].value);
  }
}

void Http2Session::OnFreeSession() {
  ::delete this;
}

ssize_t Http2Session::OnMaxFrameSizePadding(size_t frameLen,
                                            size_t maxPayloadLen) {
  DEBUG_HTTP2("Http2Session: using max frame size padding\n");
  return maxPayloadLen;
}

ssize_t Http2Session::OnCallbackPadding(size_t frameLen,
                                        size_t maxPayloadLen) {
  DEBUG_HTTP2("Http2Session: using callback padding\n");
  Isolate* isolate = env()->isolate();
  Local<Context> context = env()->context();

  HandleScope handle_scope(isolate);
  Context::Scope context_scope(context);

  if (object()->Has(context, env()->ongetpadding_string()).FromJust()) {
    uint32_t* buffer = env()->http2_padding_buffer();
    buffer[0] = frameLen;
    buffer[1] = maxPayloadLen;
    v8::TryCatch try_catch(isolate);
    Local<Value> ret = MakeCallback(env()->ongetpadding_string(), 0, nullptr);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    }
    uint32_t retval = buffer[2];
    retval = retval <= maxPayloadLen ? retval : maxPayloadLen;
    retval = retval >= frameLen ? retval : frameLen;
    CHECK_GE(retval, frameLen);
    CHECK_LE(retval, maxPayloadLen);
    return retval;
  }
  return frameLen;
}

void Http2Session::SetNextStreamID(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  nghttp2_session* s = session->session();
  int32_t id = args[0]->Int32Value();
  DEBUG_HTTP2("Http2Session: setting next stream id to %d\n", id);
  nghttp2_session_set_next_stream_id(s, id);
}

void HttpErrorString(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  args.GetReturnValue().Set(
      OneByteString(env->isolate(),
                    nghttp2_strerror(args[0]->Uint32Value())));
}

// Serializes the settings object into a Buffer instance that
// would be suitable, for instance, for creating the Base64
// output for an HTTP2-Settings header field.
void PackSettings(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  Local<Context> context = env->context();
  HandleScope scope(env->isolate());

  CHECK(args[0]->IsObject());
  Local<Object> obj = args[0].As<Object>();
  std::vector<nghttp2_settings_entry> entries;

#define V(name, id, type, c)                                                  \
  do {                                                                        \
     if (obj->Has(context, env->name()).FromJust()) {                         \
       Local<Value> val = obj->Get(context,                                   \
                                   env->name()).ToLocalChecked();             \
       if (!val->IsUndefined() && !val->IsNull())                             \
         entries.push_back({id, val->Uint32Value()});                         \
     }                                                                        \
  } while (0);
  SETTINGS(V)
#undef V

  const size_t len = entries.size() * 6;
  MaybeStackBuffer<char> buf(len);
  ssize_t ret =
      nghttp2_pack_settings_payload(
        reinterpret_cast<uint8_t*>(*buf), len, &entries[0], entries.size());
  if (ret >= 0) {
    args.GetReturnValue().Set(
      Buffer::Copy(env, *buf, len).ToLocalChecked());
  }
}

// Used to fill in the spec defined initial values for each setting.
void RefreshDefaultSettings(const FunctionCallbackInfo<Value>& args) {
  DEBUG_HTTP2("Http2Session: refreshing default settings\n");
  Environment* env = Environment::GetCurrent(args);
  int32_t* const buffer = env->http2_default_settings_buffer();
  buffer[IDX_SETTINGS_HEADER_TABLE_SIZE] =
      DEFAULT_SETTINGS_HEADER_TABLE_SIZE;
  buffer[IDX_SETTINGS_ENABLE_PUSH] =
      DEFAULT_SETTINGS_ENABLE_PUSH;
  buffer[IDX_SETTINGS_INITIAL_WINDOW_SIZE] =
      DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE;
  buffer[IDX_SETTINGS_MAX_FRAME_SIZE] =
      DEFAULT_SETTINGS_MAX_FRAME_SIZE;
}

template <get_setting fn>
void RefreshSettings(const FunctionCallbackInfo<Value>& args) {
  DEBUG_HTTP2("Http2Session: refreshing settings for session\n");
  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsObject());
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());
  Environment* env = session->env();
  nghttp2_session* s = session->session();

  int32_t* const buffer = env->http2_settings_buffer();
  buffer[IDX_SETTINGS_HEADER_TABLE_SIZE] =
      fn(s, NGHTTP2_SETTINGS_HEADER_TABLE_SIZE);
  buffer[IDX_SETTINGS_MAX_CONCURRENT_STREAMS] =
      fn(s, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
  buffer[IDX_SETTINGS_INITIAL_WINDOW_SIZE] =
      fn(s, NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE);
  buffer[IDX_SETTINGS_MAX_FRAME_SIZE] =
      fn(s, NGHTTP2_SETTINGS_MAX_FRAME_SIZE);
  buffer[IDX_SETTINGS_MAX_HEADER_LIST_SIZE] =
      fn(s, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE);
  buffer[IDX_SETTINGS_ENABLE_PUSH] =
      fn(s, NGHTTP2_SETTINGS_ENABLE_PUSH);
}

// Used to fill in the spec defined initial values for each setting.
void RefreshSessionState(const FunctionCallbackInfo<Value>& args) {
  DEBUG_HTTP2("Http2Session: refreshing session state\n");
  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsObject());
  Environment* env = Environment::GetCurrent(args);
  double* const buffer = env->http2_session_state_buffer();
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());
  nghttp2_session* s = session->session();

  buffer[IDX_SESSION_STATE_EFFECTIVE_LOCAL_WINDOW_SIZE] =
      nghttp2_session_get_effective_local_window_size(s);
  buffer[IDX_SESSION_STATE_EFFECTIVE_RECV_DATA_LENGTH] =
      nghttp2_session_get_effective_recv_data_length(s);
  buffer[IDX_SESSION_STATE_NEXT_STREAM_ID] =
      nghttp2_session_get_next_stream_id(s);
  buffer[IDX_SESSION_STATE_LOCAL_WINDOW_SIZE] =
      nghttp2_session_get_local_window_size(s);
  buffer[IDX_SESSION_STATE_LAST_PROC_STREAM_ID] =
      nghttp2_session_get_last_proc_stream_id(s);
  buffer[IDX_SESSION_STATE_REMOTE_WINDOW_SIZE] =
      nghttp2_session_get_remote_window_size(s);
  buffer[IDX_SESSION_STATE_OUTBOUND_QUEUE_SIZE] =
      nghttp2_session_get_outbound_queue_size(s);
  buffer[IDX_SESSION_STATE_HD_DEFLATE_DYNAMIC_TABLE_SIZE] =
      nghttp2_session_get_hd_deflate_dynamic_table_size(s);
  buffer[IDX_SESSION_STATE_HD_INFLATE_DYNAMIC_TABLE_SIZE] =
      nghttp2_session_get_hd_inflate_dynamic_table_size(s);
}

void RefreshStreamState(const FunctionCallbackInfo<Value>& args) {
  CHECK_EQ(args.Length(), 2);
  CHECK(args[0]->IsObject());
  CHECK(args[1]->IsNumber());
  int32_t id = args[1]->Int32Value();
  DEBUG_HTTP2("Http2Session: refreshing stream %d state\n", id);
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args[0].As<Object>());
  nghttp2_session* s = session->session();
  Nghttp2Stream* stream;

  Environment* env = Environment::GetCurrent(args);
  double* const buffer = env->http2_stream_state_buffer();

  if ((stream = session->FindStream(id)) == nullptr) {
    buffer[IDX_STREAM_STATE] = NGHTTP2_STREAM_STATE_IDLE;
    buffer[IDX_STREAM_STATE_WEIGHT] =
        buffer[IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT] =
        buffer[IDX_STREAM_STATE_LOCAL_CLOSE] =
        buffer[IDX_STREAM_STATE_REMOTE_CLOSE] =
        buffer[IDX_STREAM_STATE_LOCAL_WINDOW_SIZE] = 0;
    return;
  }
  nghttp2_stream* str =
      nghttp2_session_find_stream(s, stream->id());

  if (str == nullptr) {
    buffer[IDX_STREAM_STATE] = NGHTTP2_STREAM_STATE_IDLE;
    buffer[IDX_STREAM_STATE_WEIGHT] =
        buffer[IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT] =
        buffer[IDX_STREAM_STATE_LOCAL_CLOSE] =
        buffer[IDX_STREAM_STATE_REMOTE_CLOSE] =
        buffer[IDX_STREAM_STATE_LOCAL_WINDOW_SIZE] = 0;
  } else {
    buffer[IDX_STREAM_STATE] =
        nghttp2_stream_get_state(str);
    buffer[IDX_STREAM_STATE_WEIGHT] =
        nghttp2_stream_get_weight(str);
    buffer[IDX_STREAM_STATE_SUM_DEPENDENCY_WEIGHT] =
        nghttp2_stream_get_sum_dependency_weight(str);
    buffer[IDX_STREAM_STATE_LOCAL_CLOSE] =
        nghttp2_session_get_stream_local_close(s, id);
    buffer[IDX_STREAM_STATE_REMOTE_CLOSE] =
        nghttp2_session_get_stream_remote_close(s, id);
    buffer[IDX_STREAM_STATE_LOCAL_WINDOW_SIZE] =
        nghttp2_session_get_stream_local_window_size(s, id);
  }
}

void Http2Session::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  CHECK(args.IsConstructCall());

  nghttp2_session_type type =
    static_cast<nghttp2_session_type>(args[0]->IntegerValue());
  DEBUG_HTTP2("Http2Session: creating a session of type: %d\n", type);
  new Http2Session(env, args.This(), type, args[1]);
}


// Capture the stream that this session will use to send and receive data
void Http2Session::Consume(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  CHECK(args[0]->IsExternal());
  session->Consume(args[0].As<External>());
}

void Http2Session::Destroy(const FunctionCallbackInfo<Value>& args) {
  DEBUG_HTTP2("Http2Session: destroying session\n");
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  session->Unconsume();
  session->Free();
}

void Http2Session::SubmitPriority(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  nghttp2_priority_spec spec;
  int32_t id = args[0]->Int32Value();
  int32_t parent = args[1]->Int32Value();
  int32_t weight = args[2]->Int32Value();
  bool exclusive = args[3]->BooleanValue();
  bool silent = args[4]->BooleanValue();
  DEBUG_HTTP2("Http2Session: submitting priority for stream %d: "
              "parent: %d, weight: %d, exclusive: %d, silent: %d\n",
              id, parent, weight, exclusive, silent);
  CHECK_GT(id, 0);
  CHECK_GE(parent, 0);
  CHECK_GE(weight, 0);

  Nghttp2Stream* stream;
  if (!(stream = session->FindStream(id))) {
    // invalid stream
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  nghttp2_priority_spec_init(&spec, parent, weight, exclusive ? 1 : 0);

  args.GetReturnValue().Set(stream->SubmitPriority(&spec, silent));
}

void Http2Session::SubmitSettings(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsObject());

  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  Environment* env = session->env();
  Local<Context> context = env->context();

  // Collect the settings
  Local<Object> obj = args[0].As<Object>();
  std::vector<nghttp2_settings_entry> entries;
  entries.reserve(6);   // There are currently six known settings
#define V(name, id, type, c)                                                \
  do {                                                                      \
     if (obj->Has(context, env->name()).FromJust()) {                       \
       Local<Value> val = obj->Get(context,                                 \
                                   env->name()).ToLocalChecked();           \
       if (!val->IsUndefined() && !val->IsNull())                           \
         entries.push_back({id, val->Uint32Value()});                       \
     }                                                                      \
  } while (0);
  SETTINGS(V)
#undef V

  args.GetReturnValue().Set(
      session->Nghttp2Session::SubmitSettings(&entries[0], entries.size()));
}


void Http2Session::SubmitRstStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  CHECK(args[1]->IsNumber());

  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  int32_t id = args[0]->Int32Value();
  uint32_t code = args[1]->Uint32Value();

  Nghttp2Stream* stream;
  if (!(stream = session->FindStream(id))) {
    // invalid stream
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  DEBUG_HTTP2("Http2Session: sending rst_stream for stream %d, code: %d\n",
              id, code);
  args.GetReturnValue().Set(stream->SubmitRstStream(code));
}

void Http2Session::SubmitRequest(const FunctionCallbackInfo<Value>& args) {
  // args[0] Array of headers
  // args[1] endStream boolean
  // args[2] parentStream ID (for priority spec)
  // args[3] weight (for priority spec)
  // args[4] exclusive boolean (for priority spec)
  CHECK(args[0]->IsArray());

  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  Isolate* isolate = env->isolate();

  Local<Array> headers = args[0].As<Array>();
  bool endStream = args[1]->BooleanValue();
  int32_t parent = args[2]->Int32Value();
  int32_t weight = args[3]->Int32Value();
  bool exclusive = args[4]->BooleanValue();

  DEBUG_HTTP2("Http2Session: submitting request: headers: %d, end-stream: %d, "
              "parent: %d, weight: %d, exclusive: %d", headers->Length(),
              endStream, parent, weight, exclusive);

  nghttp2_priority_spec prispec;
  nghttp2_priority_spec_init(&prispec, parent, weight, exclusive ? 1 : 0);

  Headers list(isolate, headers);

  int32_t ret = session->Nghttp2Session::SubmitRequest(&prispec,
                                                       *list, list.length(),
                                                       nullptr, endStream);
  DEBUG_HTTP2("Http2Session: request submitted, response: %d\n", ret);
  args.GetReturnValue().Set(ret);
}

void Http2Session::SubmitResponse(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  CHECK(args[1]->IsArray());

  Http2Session* session;
  Nghttp2Stream* stream;

  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  Isolate* isolate = env->isolate();

  int32_t id = args[0]->Int32Value();
  Local<Array> headers = args[1].As<Array>();
  bool endStream = args[2]->BooleanValue();

  DEBUG_HTTP2("Http2Session: submitting response for stream %d: headers: %d, "
              "end-stream: %d\n", id, headers->Length(), endStream);

  if (!(stream = session->FindStream(id))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }

  Headers list(isolate, headers);

  args.GetReturnValue().Set(
      stream->SubmitResponse(*list, list.length(), endStream));
}

void Http2Session::SendHeaders(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  CHECK(args[1]->IsArray());

  Http2Session* session;
  Nghttp2Stream* stream;

  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = session->env();
  Isolate* isolate = env->isolate();

  int32_t id = args[0]->Int32Value();
  Local<Array> headers = args[1].As<Array>();

  DEBUG_HTTP2("Http2Session: sending informational headers for stream %d, "
              "count: %d\n", id, headers->Length());

  if (!(stream = session->FindStream(id))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }

  Headers list(isolate, headers);

  args.GetReturnValue().Set(stream->SubmitInfo(*list, list.length()));
}

void Http2Session::ShutdownStream(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Nghttp2Stream* stream;
  int32_t id = args[0]->Int32Value();
  DEBUG_HTTP2("Http2Session: shutting down stream %d\n", id);
  if (!(stream = session->FindStream(id))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  stream->Shutdown();
}


void Http2Session::StreamReadStart(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Nghttp2Stream* stream;
  if (!(stream = session->FindStream(args[0]->Int32Value()))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  stream->ReadStart();
}


void Http2Session::StreamReadStop(const FunctionCallbackInfo<Value>& args) {
  CHECK(args[0]->IsNumber());
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Nghttp2Stream* stream;
  if (!(stream = session->FindStream(args[0]->Int32Value()))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  stream->ReadStop();
}


static void DoSessionShutdown(SessionShutdownWrap* req) {
  int status;
  if (req->graceful()) {
    DEBUG_HTTP2("Http2Session: initiating graceful session shutdown. "
                "last-stream-id: %d, code: %d\n",
                req->lastStreamID(), req->errorCode());
    status = nghttp2_session_terminate_session2(req->handle()->session(),
                                                req->lastStreamID(),
                                                req->errorCode());
  } else {
    DEBUG_HTTP2("Http2Session: initiating immediate shutdown. "
                "last-stream-id: %d, code: %d, opaque-data: %d\n",
                req->lastStreamID(), req->errorCode(), req->opaqueDataLength());
    status = nghttp2_submit_goaway(req->handle()->session(),
                                   NGHTTP2_FLAG_NONE,
                                   req->lastStreamID(),
                                   req->errorCode(),
                                   req->opaqueData(),
                                   req->opaqueDataLength());
  }
  req->Done(status);
}

static void AfterSessionShutdown(SessionShutdownWrap* req, int status) {
  Environment* env = req->env();
  CHECK_EQ(req->persistent().IsEmpty(), false);

  HandleScope handle_scope(env->isolate());
  Context::Scope context_scope(env->context());

  Local<Object> req_wrap_obj = req->object();
  Local<Value> argv[2] = {
    Integer::New(env->isolate(), status),
    req_wrap_obj
  };

  if (req_wrap_obj->Has(env->context(), env->oncomplete_string()).FromJust())
    req->MakeCallback(env->oncomplete_string(), arraysize(argv), argv);

  delete req;
}

void Http2Session::SubmitShutdown(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  Environment* env = Environment::GetCurrent(args);
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  CHECK(args[0]->IsObject());
  Local<Object> req_wrap_obj = args[0].As<Object>();
  bool graceful = args[1]->BooleanValue();
  uint32_t errorCode = args[2]->Uint32Value();
  int32_t lastStreamID = args[3]->Int32Value();
  Local<Value> opaqueData = args[4];

  if (opaqueData->BooleanValue())
    THROW_AND_RETURN_UNLESS_BUFFER(env, opaqueData);

  SessionShutdownWrap* req_wrap =
      new SessionShutdownWrap(env, req_wrap_obj, session, errorCode,
                              lastStreamID, opaqueData, graceful,
                              AfterSessionShutdown);

  req_wrap->Dispatched();
  if (graceful) {
    session->SubmitShutdownNotice();
    auto AfterShutdownIdle = [](uv_idle_t* idle) {
      uv_idle_stop(idle);
      SessionShutdownWrap* wrap =
        SessionShutdownWrap::from_req(idle);
      DoSessionShutdown(wrap);
    };
    uv_idle_init(env->event_loop(), req_wrap->req());
    uv_idle_start(req_wrap->req(), AfterShutdownIdle);
  } else {
    DoSessionShutdown(req_wrap);
  }
}

void Http2Session::DestroyStream(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  CHECK_EQ(args.Length(), 1);
  CHECK(args[0]->IsNumber());
  int32_t id = args[0]->Int32Value();
  DEBUG_HTTP2("Http2Session: destroy stream %d\n", id);
  Nghttp2Stream* stream;
  if (!(stream = session->FindStream(id))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }
  stream->Destroy();
}

void Http2Session::SubmitPushPromise(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());

  CHECK(args[0]->IsNumber());  // parent stream ID
  CHECK(args[1]->IsArray());  // headers array

  Nghttp2Stream* parent;
  int32_t id = args[0]->Int32Value();
  Local<Array> headers = args[1].As<Array>();
  bool endStream = args[2]->BooleanValue();

  DEBUG_HTTP2("Http2Session: submitting push promise for stream %d: "
              "end-stream: %d, headers: %d\n", id, endStream,
              headers->Length());

  if (!(parent = session->FindStream(id))) {
    return args.GetReturnValue().Set(NGHTTP2_ERR_INVALID_STREAM_ID);
  }

  Headers list(isolate, headers);

  int32_t ret = parent->SubmitPushPromise(*list, list.length(),
                                          nullptr, endStream);
  DEBUG_HTTP2("Http2Session: push promise submitted, ret: %d\n", ret);
  args.GetReturnValue().Set(ret);
}

int Http2Session::DoWrite(WriteWrap* req_wrap,
                          uv_buf_t* bufs,
                          size_t count,
                          uv_stream_t* send_handle) {
  Environment* env = req_wrap->env();
  Local<Object> req_wrap_obj = req_wrap->object();
  Local<Context> context = env->context();

  Nghttp2Stream* stream;
  {
    Local<Value> val =
        req_wrap_obj->Get(context, env->stream_string()).ToLocalChecked();
    if (!val->IsNumber() || !(stream = FindStream(val->Int32Value()))) {
      // invalid stream
      req_wrap->Dispatched();
      req_wrap->Done(0);
      return NGHTTP2_ERR_INVALID_STREAM_ID;
    }
  }

  nghttp2_stream_write_t* req = new nghttp2_stream_write_t;
  req->data = req_wrap;

  auto AfterWrite = [](nghttp2_stream_write_t* req, int status) {
    WriteWrap* wrap = static_cast<WriteWrap*>(req->data);
    wrap->Done(status);
    delete req;
  };
  req_wrap->Dispatched();
  stream->Write(req, bufs, count, AfterWrite);
  return 0;
}

uv_buf_t* Http2Session::AllocateSend(size_t recommended) {
  HandleScope scope(env()->isolate());
  Local<Object> req_wrap_obj =
    env()->write_wrap_constructor_function()
      ->NewInstance(env()->context()).ToLocalChecked();
  SessionSendBuffer* buf =
      ::new SessionSendBuffer(env(),
                              req_wrap_obj,
                              recommended);
  return &buf->buffer_;
}

void Http2Session::Send(uv_buf_t* buf, size_t length) {
  // Do not attempt to write data if the stream is not alive or is closing
  if (stream_ == nullptr || !stream_->IsAlive() || stream_->IsClosing()) {
    return;
  }
  HandleScope scope(env()->isolate());
  SessionSendBuffer* req = ContainerOf(&SessionSendBuffer::buffer_, buf);
  uv_buf_t actual = uv_buf_init(buf->base, length);
  if (stream_->DoWrite(req, &actual, 1, nullptr)) {
    req->Dispose();
  }
}

void Http2Session::OnTrailers(Nghttp2Stream* stream,
                              MaybeStackBuffer<nghttp2_nv>* trailers) {
  DEBUG_HTTP2("Http2Session: prompting for trailers on stream %d\n",
              stream->id());
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);
  Isolate* isolate = env()->isolate();

  HandleScope scope(isolate);
  if (object()->Has(context, env()->ontrailers_string()).FromJust()) {
    Local<Value> argv[1] = {
      Integer::New(isolate, stream->id())
    };

    v8::TryCatch try_catch(isolate);
    Local<Value> ret = MakeCallback(env()->ontrailers_string(),
                                    arraysize(argv), argv);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    } else {
      if (ret->IsArray()) {
        Local<Array> headers = ret.As<Array>();
        if (headers->Length() > 0) {
          trailers->AllocateSufficientStorage(headers->Length());
          CopyHeaders(isolate, trailers, headers);
        }
      }
    }
  }
}

static inline bool CheckHeaderAllowsMultiple(nghttp2_vec* name) {
  switch (name->len) {
    case 3:
      if (memcmp(name->base, "age", 3) == 0)
        return false;
      break;
    case 4:
      switch (name->base[3]) {
        case 'e':
          if (memcmp(name->base, "dat", 3) == 0)
            return false;
          break;
        case 'g':
          if (memcmp(name->base, "eta", 3) == 0)
            return false;
          break;
        case 'm':
          if (memcmp(name->base, "fro", 3) == 0)
            return false;
          break;
        case 't':
          if (memcmp(name->base, "hos", 3) == 0)
            return false;
          break;
      }
    case 5:
      if (memcmp(name->base, "range", 5) == 0)
        return false;
      break;
    case 6:
      if (memcmp(name->base, "server", 6) == 0)
        return false;
      break;
    case 7:
      switch (name->base[6]) {
        case 's':
          if (memcmp(name->base, "expire", 6) == 0)
            return false;
          break;
        case 'r':
          if (memcmp(name->base, "refere", 6) == 0)
            return false;
          break;
      }
      break;
    case 8:
      switch (name->base[7]) {
        case 'e':
          if (memcmp(name->base, "if-rang", 7) == 0)
            return false;
          break;
        case 'h':
          if (memcmp(name->base, "if-matc", 7) == 0)
            return false;
          break;
        case 'n':
          if (memcmp(name->base, "locatio", 7) == 0)
            return false;
          break;
      }
      break;
    case 10:
      if (memcmp(name->base, "user-agent", 10) == 0)
        return false;
      break;
    case 11:
      switch (name->base[10]) {
        case '5':
          if (memcmp(name->base, "content-md", 10) == 0)
            return false;
          break;
        case 'r':
          if (memcmp(name->base, "retry-afte", 10) == 0)
            return false;
          break;
      }
      break;
    case 12:
      switch (name->base[11]) {
        case 'e':
          if (memcmp(name->base, "content-typ", 11) == 0)
            return false;
          break;
        case 's':
          if (memcmp(name->base, "max-forward", 11) == 0)
            return false;
          break;
      }
      break;
    case 13:
      switch (name->base[12]) {
        case 'd':
          if (memcmp(name->base, "last-modifie", 12) == 0)
            return false;
          break;
        case 'h':
          if (memcmp(name->base, "if-none-matc", 12) == 0)
            return false;
          break;
        case 'n':
          if (memcmp(name->base, "authorizatio", 12) == 0)
            return false;
          break;
      }
      break;
    case 14:
      if (memcmp(name->base, "content-length", 14) == 0)
        return false;
      break;
    case 16:
      switch (name->base[15]) {
        case 'e':
          if (memcmp(name->base, "content-languag", 15) == 0)
            return false;
          break;
        case 'g':
          if (memcmp(name->base, "content-encodin", 15) == 0)
            return false;
          break;
        case 'n':
          if (memcmp(name->base, "content-locatio", 15) == 0)
            return false;
          break;
      }
      break;
    case 17:
      if (memcmp(name->base, "if-modified-since", 17) == 0)
        return false;
      break;
    case 19:
      switch (name->base[18]) {
        case 'e':
          if (memcmp(name->base, "if-unmodified-sinc", 18) == 0)
            return false;
          break;
        case 'n':
          if (memcmp(name->base, "proxy-authorizatio", 18) == 0)
            return false;
          break;
      }
  }
  return true;
}

void Http2Session::OnHeaders(Nghttp2Stream* stream,
                             nghttp2_header_list* headers,
                             nghttp2_headers_category cat,
                             uint8_t flags) {
  Local<Context> context = env()->context();
  Context::Scope context_scope(context);

  Isolate* isolate = env()->isolate();
  HandleScope scope(isolate);
  Local<Object> holder = Object::New(isolate);
  holder->SetPrototype(context, v8::Null(isolate)).ToChecked();
  Local<String> name_str;
  Local<String> value_str;
  Local<Array> array;
  while (headers != nullptr) {
    nghttp2_header_list* item = headers;
    name_str = ExternalHeaderNameResource::New(isolate, item->name);
    nghttp2_vec name = nghttp2_rcbuf_get_buf(item->name);
    nghttp2_vec value = nghttp2_rcbuf_get_buf(item->value);
    value_str = String::NewFromUtf8(isolate,
                                    reinterpret_cast<char*>(value.base),
                                    v8::NewStringType::kNormal,
                                    value.len).ToLocalChecked();
    if (holder->Has(context, name_str).FromJust()) {
      if (CheckHeaderAllowsMultiple(&name)) {
        Local<Value> existing = holder->Get(context, name_str).ToLocalChecked();
        if (existing->IsArray()) {
          array = existing.As<Array>();
          array->Set(context, array->Length(), value_str).FromJust();
        } else {
          array = Array::New(isolate, 2);
          array->Set(context, 0, existing).FromJust();
          array->Set(context, 1, value_str).FromJust();
          holder->Set(context, name_str, array).FromJust();
        }
      }  // Ignore singleton headers that appear more than once
    } else {
      holder->Set(context, name_str, value_str).FromJust();
    }
    headers = item->next;
  }

  if (object()->Has(context, env()->onheaders_string()).FromJust()) {
    Local<Value> argv[4] = {
      Integer::New(isolate, stream->id()),
      Integer::New(isolate, cat),
      Integer::New(isolate, flags),
      holder
    };
    v8::TryCatch try_catch(isolate);
    Local<Value> ret = MakeCallback(env()->onheaders_string(),
                                    arraysize(argv), argv);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    }
  }
}


void Http2Session::OnStreamClose(int32_t id, uint32_t code) {
  Isolate* isolate = env()->isolate();
  Local<Context> context = env()->context();
  HandleScope scope(isolate);
  if (object()->Has(context, env()->onstreamclose_string()).FromJust()) {
    Local<Value> argv[2] = {
      Integer::New(isolate, id),
      Integer::NewFromUnsigned(isolate, code)
    };
    v8::TryCatch try_catch(isolate);
    Local<Value> ret = MakeCallback(env()->onstreamclose_string(),
                                    arraysize(argv), argv);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    }
  }
}

void Http2Session::OnDataChunk(
    Nghttp2Stream* stream,
    nghttp2_data_chunk_t* chunk) {
  Isolate* isolate = env()->isolate();
  Local<Context> context = env()->context();
  HandleScope scope(isolate);
  Local<Object> obj = Object::New(isolate);
  obj->Set(context,
           env()->id_string(),
           Integer::New(isolate, stream->id())).FromJust();
  Local<Object> buf = Buffer::Copy(isolate,
                                   chunk->buf.base,
                                   chunk->buf.len).ToLocalChecked();
  EmitData(chunk->buf.len, buf, obj);
}

void Http2Session::OnSettings() {
  Local<Context> context = env()->context();
  Isolate* isolate = env()->isolate();
  HandleScope scope(isolate);
  if (object()->Has(context, env()->onsettings_string()).FromJust()) {
    v8::TryCatch try_catch(isolate);
    Local<Value> ret = MakeCallback(env()->onsettings_string(), 0, nullptr);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    }
  }
}

void Http2Session::OnPriority(int32_t stream,
                              int32_t parent,
                              int32_t weight,
                              int8_t exclusive) {
  Local<Context> context = env()->context();
  Isolate* isolate = env()->isolate();
  HandleScope scope(isolate);
  if (object()->Has(context, env()->onpriority_string()).FromJust()) {
    v8::TryCatch try_catch(isolate);
    Local<Value> argv[4] = {
      Integer::New(isolate, stream),
      Integer::New(isolate, parent),
      Integer::New(isolate, weight),
      Boolean::New(isolate, exclusive)
    };
    Local<Value> ret = MakeCallback(env()->onpriority_string(),
                                    arraysize(argv), argv);
    if (ret.IsEmpty()) {
      ClearFatalExceptionHandlers(env());
      FatalException(isolate, try_catch);
    }
  }
}

void Http2Session::OnStreamAllocImpl(size_t suggested_size,
                                      uv_buf_t* buf,
                                      void* ctx) {
  Http2Session* session = static_cast<Http2Session*>(ctx);
  buf->base = session->stream_alloc();
  buf->len = kAllocBufferSize;
}


void Http2Session::OnStreamReadImpl(ssize_t nread,
                                     const uv_buf_t* bufs,
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
  uv_buf_t buf[] { uv_buf_init((*bufs).base, nread) };
  session->Write(buf, 1);
}


void Http2Session::Consume(Local<External> external) {
  DEBUG_HTTP2("Http2Session: consuming socket\n");
  CHECK(prev_alloc_cb_.is_empty());
  StreamBase* stream = static_cast<StreamBase*>(external->Value());
  CHECK_NE(stream, nullptr);
  stream->Consume();
  stream_ = stream;
  prev_alloc_cb_ = stream->alloc_cb();
  prev_read_cb_ = stream->read_cb();
  stream->set_alloc_cb({ Http2Session::OnStreamAllocImpl, this });
  stream->set_read_cb({ Http2Session::OnStreamReadImpl, this });
}


void Http2Session::Unconsume() {
  DEBUG_HTTP2("Http2Session: unconsuming socket\n");
  if (prev_alloc_cb_.is_empty())
    return;
  stream_->set_alloc_cb(prev_alloc_cb_);
  stream_->set_read_cb(prev_read_cb_);
  prev_alloc_cb_.clear();
  prev_read_cb_.clear();
  stream_ = nullptr;
}


void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();
  HandleScope scope(isolate);

  // Initialize the buffer used for padding callbacks
  env->set_http2_padding_buffer(new uint32_t[3]);
  const size_t http2_padding_buffer_byte_length =
      sizeof(*env->http2_padding_buffer()) * 3;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "paddingArrayBuffer"),
              ArrayBuffer::New(env->isolate(),
                               env->http2_padding_buffer(),
                               http2_padding_buffer_byte_length));

  // Initialize the buffer used to store the session state
  env->set_http2_session_state_buffer(
      new double[IDX_SESSION_STATE_COUNT]);

  const size_t http2_session_state_buffer_byte_length =
      sizeof(*env->http2_session_state_buffer()) *
      IDX_SESSION_STATE_COUNT;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "sessionStateArrayBuffer"),
              ArrayBuffer::New(env->isolate(),
                               env->http2_session_state_buffer(),
                               http2_session_state_buffer_byte_length));

  // Initialize the buffer used to store the stream state
  env->set_http2_stream_state_buffer(
      new double[IDX_STREAM_STATE_COUNT]);

  const size_t http2_stream_state_buffer_byte_length =
      sizeof(*env->http2_stream_state_buffer()) *
      IDX_STREAM_STATE_COUNT;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "streamStateArrayBuffer"),
              ArrayBuffer::New(env->isolate(),
                               env->http2_stream_state_buffer(),
                               http2_stream_state_buffer_byte_length));

  // Initialize the buffer used to store the default settings
  env->set_http2_default_settings_buffer(
      new int32_t[kDefaultSettingsCount]);

  const size_t http2_default_settings_buffer_byte_length =
      sizeof(*env->http2_default_settings_buffer()) *
      kDefaultSettingsCount;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "defaultSettingsArrayBuffer"),
              ArrayBuffer::New(env->isolate(),
                               env->http2_default_settings_buffer(),
                               http2_default_settings_buffer_byte_length));

  // Initialize the buffer used to store the default settings
  env->set_http2_settings_buffer(
      new int32_t[IDX_SETTINGS_COUNT]);

  const size_t http2_settings_buffer_byte_length =
      sizeof(*env->http2_settings_buffer()) *
      IDX_SETTINGS_COUNT;

  target->Set(FIXED_ONE_BYTE_STRING(env->isolate(),
                                    "settingsArrayBuffer"),
              ArrayBuffer::New(env->isolate(),
                               env->http2_settings_buffer(),
                               http2_settings_buffer_byte_length));

  // Method to fetch the nghttp2 string description of an nghttp2 error code
  env->SetMethod(target, "nghttp2ErrorString", HttpErrorString);

  Local<String> http2SessionClassName =
    String::NewFromUtf8(isolate, "Http2Session",
                        v8::NewStringType::kInternalized).ToLocalChecked();

  Local<String> http2SessionShutdownWrapClassName =
      FIXED_ONE_BYTE_STRING(env->isolate(), "SessionShutdownWrap");
  Local<FunctionTemplate> sw =
      FunctionTemplate::New(env->isolate(), SessionShutdownWrap::New);
  sw->InstanceTemplate()->SetInternalFieldCount(1);
  sw->SetClassName(http2SessionShutdownWrapClassName);
  target->Set(http2SessionShutdownWrapClassName, sw->GetFunction());

  Local<FunctionTemplate> session =
      env->NewFunctionTemplate(Http2Session::New);
  session->SetClassName(http2SessionClassName);
  session->InstanceTemplate()->SetInternalFieldCount(1);
  env->SetProtoMethod(session, "consume",
                      Http2Session::Consume);
  env->SetProtoMethod(session, "destroy",
                      Http2Session::Destroy);
  env->SetProtoMethod(session, "sendHeaders",
                      Http2Session::SendHeaders);
  env->SetProtoMethod(session, "submitShutdown",
                      Http2Session::SubmitShutdown);
  env->SetProtoMethod(session, "submitSettings",
                      Http2Session::SubmitSettings);
  env->SetProtoMethod(session, "submitPushPromise",
                      Http2Session::SubmitPushPromise);
  env->SetProtoMethod(session, "submitRstStream",
                      Http2Session::SubmitRstStream);
  env->SetProtoMethod(session, "submitResponse",
                      Http2Session::SubmitResponse);
  env->SetProtoMethod(session, "submitRequest",
                      Http2Session::SubmitRequest);
  env->SetProtoMethod(session, "submitPriority",
                      Http2Session::SubmitPriority);
  env->SetProtoMethod(session, "shutdownStream",
                      Http2Session::ShutdownStream);
  env->SetProtoMethod(session, "streamReadStart",
                      Http2Session::StreamReadStart);
  env->SetProtoMethod(session, "streamReadStop",
                      Http2Session::StreamReadStop);
  env->SetProtoMethod(session, "setNextStreamID",
                      Http2Session::SetNextStreamID);
  env->SetProtoMethod(session, "destroyStream",
                      Http2Session::DestroyStream);
  StreamBase::AddMethods<Http2Session>(env, session,
                                        StreamBase::kFlagHasWritev |
                                        StreamBase::kFlagNoShutdown);
  target->Set(context,
              http2SessionClassName,
              session->GetFunction()).FromJust();

  Local<Object> constants = Object::New(isolate);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SESSION_SERVER);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SESSION_CLIENT);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_IDLE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_OPEN);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_RESERVED_LOCAL);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_RESERVED_REMOTE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_HALF_CLOSED_LOCAL);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_HALF_CLOSED_REMOTE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_STREAM_STATE_CLOSED);
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

  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_HCAT_REQUEST);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_HCAT_RESPONSE);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_HCAT_PUSH_RESPONSE);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_HCAT_HEADERS);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_NV_FLAG_NONE);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_NV_FLAG_NO_INDEX);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_ERR_DEFERRED);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_ERR_NOMEM);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_ERR_STREAM_ID_NOT_AVAILABLE);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_ERR_INVALID_ARGUMENT);
  NODE_DEFINE_HIDDEN_CONSTANT(constants, NGHTTP2_ERR_STREAM_CLOSED);

  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_NONE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_END_STREAM);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_END_HEADERS);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_ACK);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_PADDED);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_FLAG_PRIORITY);

  NODE_DEFINE_CONSTANT(constants, DEFAULT_SETTINGS_HEADER_TABLE_SIZE);
  NODE_DEFINE_CONSTANT(constants, DEFAULT_SETTINGS_ENABLE_PUSH);
  NODE_DEFINE_CONSTANT(constants, DEFAULT_SETTINGS_INITIAL_WINDOW_SIZE);
  NODE_DEFINE_CONSTANT(constants, DEFAULT_SETTINGS_MAX_FRAME_SIZE);
  NODE_DEFINE_CONSTANT(constants, MAX_MAX_FRAME_SIZE);
  NODE_DEFINE_CONSTANT(constants, MIN_MAX_FRAME_SIZE);
  NODE_DEFINE_CONSTANT(constants, MAX_INITIAL_WINDOW_SIZE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_DEFAULT_WEIGHT);

  NODE_DEFINE_CONSTANT(constants, PADDING_STRATEGY_NONE);
  NODE_DEFINE_CONSTANT(constants, PADDING_STRATEGY_MAX);
  NODE_DEFINE_CONSTANT(constants, PADDING_STRATEGY_CALLBACK);

#define STRING_CONSTANT(NAME, VALUE)                                          \
  NODE_DEFINE_STRING_CONSTANT(constants, "HTTP2_HEADER_" # NAME, VALUE);
HTTP_KNOWN_HEADERS(STRING_CONSTANT)
#undef STRING_CONSTANT

#define V(name, _) NODE_DEFINE_CONSTANT(constants, HTTP_STATUS_##name);
HTTP_STATUS_CODES(V)
#undef V

  env->SetMethod(target, "refreshLocalSettings",
                 RefreshSettings<nghttp2_session_get_local_settings>);
  env->SetMethod(target, "refreshRemoteSettings",
                 RefreshSettings<nghttp2_session_get_remote_settings>);
  env->SetMethod(target, "refreshDefaultSettings", RefreshDefaultSettings);
  env->SetMethod(target, "refreshSessionState", RefreshSessionState);
  env->SetMethod(target, "refreshStreamState", RefreshStreamState);
  env->SetMethod(target, "packSettings", PackSettings);

  target->Set(context,
              FIXED_ONE_BYTE_STRING(isolate, "constants"),
              constants).FromJust();
}
}  // namespace http2
}  // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(http2, node::http2::Initialize)
