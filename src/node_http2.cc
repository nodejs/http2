#include "node.h"
#include "nghttp2/nghttp2.h"

#include "async-wrap.h"
#include "async-wrap-inl.h"
#include "env.h"
#include "env-inl.h"
#include "util.h"
#include "util-inl.h"
#include "v8.h"

#include <vector>

namespace node {

using v8::Array;
using v8::Context;
using v8::Exception;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Integer;
using v8::Isolate;
using v8::Local;
using v8::Name;
using v8::Object;
using v8::ObjectTemplate;
using v8::PropertyCallbackInfo;
using v8::String;
using v8::Value;

namespace http2 {

#define ERROR_STR(code)                                                       \
  OneByteString(env->isolate(), nghttp2_http2_strerror(code))

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                  \
  {                                                                           \
    (uint8_t *) NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,  \
        NGHTTP2_NV_FLAG_NONE                                                  \
  }

#define MAKE_NV2(NAME, NAMELEN, VALUE, VALLEN)                                \
  {                                                                           \
    (uint8_t *) NAME, (uint8_t *)VALUE, NAMELEN, VALLEN, NGHTTP2_NV_FLAG_NONE \
  }

#define SET_SESSION_CALLBACK(callbacks, name)                                 \
  nghttp2_session_callbacks_set_##name##_callback(callbacks, name);

#define SESSION_CALLBACKS(V)                                                  \
  V(ONSEND)                                                                   \
  V(ONSTREAMCLOSE)                                                            \
  V(ONBEGINHEADERS)                                                           \
  V(ONHEADERS)                                                                \
  V(ONHEADER)                                                                 \
  V(ONDATA)                                                                   \
  V(ONGOAWAY)                                                                 \
  V(ONSETTINGS)                                                               \
  V(ONRSTSTREAM)                                                              \
  V(ONPRIORITY)                                                               \
  V(ONPING)                                                                   \
  V(ONDATACHUNK)                                                              \
  V(ONFRAMESEND)

#define DATA_FLAGS(V)                                                         \
  V(ENDSTREAM)                                                                \
  V(ENDDATA)                                                                  \
  V(NOENDSTREAM)

#define V(name) CALLBACK_##name,
enum http2_session_callbacks {
SESSION_CALLBACKS(V)
} http2_session_callbacks;
#undef V

#define V(name) FLAG_##name,
enum http2_data_flags {
DATA_FLAGS(V)
} http2_data_flags;
#undef V

enum http2_session_type {
  SESSION_TYPE_SERVER = 0,
  SESSION_TYPE_CLIENT = 1
} http2_session_type;

class Http2Session;
class Http2Stream;
class Http2Header;
class Http2DataProvider;

class Http2Header : BaseObject {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);

  nghttp2_nv operator*() {
    return nv_;
  }

 private:
  friend class Http2Session;

  Http2Header(Environment* env,
              Local<Object> wrap,
              char* name, size_t nlen,
              char* value, size_t vlen) :
              BaseObject(env, wrap) {
     Wrap(object(), this);
     nv_.name = static_cast<uint8_t*>(malloc(nlen));
     nv_.value = static_cast<uint8_t*>(malloc(vlen));
     nv_.namelen = nlen;
     nv_.valuelen = vlen;
     nv_.flags = NGHTTP2_NV_FLAG_NONE;
     memcpy(nv_.name, name, nlen);
     memcpy(nv_.value, value, vlen);
  }

  ~Http2Header() {
    free(nv_.name);
    free(nv_.value);
  }

  nghttp2_nv nv_;
};

class Http2Stream : public AsyncWrap {
 public:
   static void GetID(Local<String> property,
                     const PropertyCallbackInfo<Value>& args);

   size_t self_size() const override {
     return sizeof(*this);
   }

 private:
   friend class Http2Session;

   Http2Stream(Environment* env,
               Local<Object> wrap,
               Http2Session* session,
               int32_t stream_id)
       : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2STREAM),
         session_(session),
         stream_id_(stream_id) {
     Wrap(object(), this);
     prev_ = nullptr;
     next_ = nullptr;
   }

   ~Http2Stream() override {}

   static void RemoveStream(Http2Stream* stream);
   static void AddStream(Http2Stream* stream, Http2Session* session);

   Http2Session* session_;
   Http2Stream* prev_;
   Http2Stream* next_;
   int32_t stream_id_;
};

class Http2Session : public AsyncWrap {
 public:
  static void New(const FunctionCallbackInfo<Value>& args);

  static void GetType(
    Local<String> property,
    const PropertyCallbackInfo<Value>& args);
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

  static void SetLocalWindowSize(const FunctionCallbackInfo<Value>& args);
  static void GetLocalSetting(const FunctionCallbackInfo<Value>& args);
  static void GetRemoteSetting(const FunctionCallbackInfo<Value>& args);
  static void Destroy(const FunctionCallbackInfo<Value>& args);
  static void Terminate(const FunctionCallbackInfo<Value>& args);
  static void ChangeStreamPriority(const FunctionCallbackInfo<Value>& args);
  static void Consume(const FunctionCallbackInfo<Value>& args);
  static void ConsumeSession(const FunctionCallbackInfo<Value>& args);
  static void ConsumeStream(const FunctionCallbackInfo<Value>& args);
  static void CreateIdleStream(const FunctionCallbackInfo<Value>& args);
  static void GetStreamLocalClose(const FunctionCallbackInfo<Value>& args);
  static void GetStreamRemoteClose(const FunctionCallbackInfo<Value>& args);
  static void GetStreamState(const FunctionCallbackInfo<Value>& args);
  static void GetStreamWeight(const FunctionCallbackInfo<Value>& args);
  static void SendServerConnectionHeader(
      const FunctionCallbackInfo<Value>& args);
  static void ReceiveData(const FunctionCallbackInfo<Value>& args);
  static void SendData(const FunctionCallbackInfo<Value>& args);
  static void RstStream(const FunctionCallbackInfo<Value>& args);
  static void Respond(const FunctionCallbackInfo<Value>& args);
  static void SendContinue(const FunctionCallbackInfo<Value>& args);
  static void ResumeData(const FunctionCallbackInfo<Value>& args);
  static void SendTrailers(const FunctionCallbackInfo<Value>& args);

  size_t self_size() const override {
    return sizeof(*this);
  }

  nghttp2_session* operator*() {
    return session_;
  }

 private:
  Http2Session(Environment* env,
               Local<Object> wrap,
               enum http2_session_type type)
      : AsyncWrap(env, wrap, AsyncWrap::PROVIDER_HTTP2SESSION),
        type_(type) {
    Wrap(object(), this);
    Init(type);
    //root_ = create_stream(env, this, 0);
  }

  ~Http2Session() override {
    nghttp2_session_del(session_);
  }

  static ssize_t send(nghttp2_session* session,
                      const uint8_t *data,
                      size_t length,
                      int flags,
                      void *user_data) {
    return 0;
  }

  static int on_frame_recv(nghttp2_session *session,
                           const nghttp2_frame *frame,
                           void *user_data) {
    return 0;
  }

  static int on_stream_close(nghttp2_session *session,
                             int32_t stream_id,
                             uint32_t error_code,
                             void *user_data) {
  }

  static int on_header(nghttp2_session *session,
                       const nghttp2_frame *frame,
                       const uint8_t *name,
                       size_t namelen,
                       const uint8_t *value,
                       size_t valuelen,
                       uint8_t flags,
                       void *user_data) {
  }

  static int on_begin_headers(nghttp2_session* session,
                              const nghttp2_frame* frame,
                              void* user_data) {
  }

  static int on_data_chunk_recv(nghttp2_session* session,
                                uint8_t flags,
                                int32_t stream_id,
                                const uint8_t* data,
                                size_t len,
                                void* user_data) {
  }

  static int on_frame_send(nghttp2_session* session,
                           const nghttp2_frame* frame,
                           void* user_data) {
  }

  void Init(enum http2_session_type type) {
    nghttp2_session_callbacks *cb;
    nghttp2_session_callbacks_new(&cb);
    SET_SESSION_CALLBACK(cb, send)
    SET_SESSION_CALLBACK(cb, on_frame_recv)
    SET_SESSION_CALLBACK(cb, on_stream_close)
    SET_SESSION_CALLBACK(cb, on_header)
    SET_SESSION_CALLBACK(cb, on_begin_headers)
    SET_SESSION_CALLBACK(cb, on_data_chunk_recv)
    SET_SESSION_CALLBACK(cb, on_frame_send)
    nghttp2_session_server_new(&session_, cb, this);
    nghttp2_session_callbacks_del(cb);
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

 private:

  static ssize_t on_read(nghttp2_session* session,
                           int32_t stream_id,
                           uint8_t* buf,
                           size_t length,
                           uint32_t* flags,
                           nghttp2_data_source* source,
                           void* user_data) {
  }

  Http2DataProvider(Environment* env,
                    Local<Object> wrap,
                    Http2Stream* stream) :
                    BaseObject(env, wrap),
                    stream_(stream) {
     Wrap(object(), this);
     provider_.read_callback = on_read;
     provider_.source.ptr = this;
  }

  ~Http2DataProvider() {}

  Http2Stream* stream_;
  nghttp2_data_provider provider_;
};

void Http2DataProvider::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args.IsConstructCall())
    return env->ThrowTypeError("Class constructor Http2DataProvider cannot "
                               "be invoked without 'new'");
  if (args.Length() < 1)
    return env->ThrowTypeError("'stream' argument is required");
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
  new Http2DataProvider(env, args.This(), stream);
}

void Http2Header::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args.IsConstructCall())
    return env->ThrowTypeError("Class constructor Http2Header cannot "
                               "be invoked without 'new'");
  Utf8Value key(env->isolate(), args[0].As<String>());
  Utf8Value value(env->isolate(), args[1].As<String>());
  new Http2Header(env, args.This(),
                 *key, key.length(),
                 *value, value.length());
}

void Http2Session::New(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);
  if (!args.IsConstructCall())
    return env->ThrowTypeError("Class constructor Http2Session cannot "
                               "be invoked without 'new'");
  enum http2_session_type type =
      static_cast<enum http2_session_type>(args[0]->Int32Value());
  if (type != SESSION_TYPE_SERVER && type != SESSION_TYPE_CLIENT)
    return env->ThrowTypeError("Invalid HTTP/2 session type");
  new Http2Session(env, args.This(), type);
}

void Http2Stream::GetID(Local<String> property,
                        const PropertyCallbackInfo<Value>& args) {
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args.Holder());
  args.GetReturnValue().Set(stream->stream_id_);
}

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
  if (!**session)
    return;
  info.GetReturnValue().Set(
      nghttp2_session_get_effective_local_window_size(**session));
}

void Http2Session::GetEffectiveRecvDataLength(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  info.GetReturnValue().Set(
      nghttp2_session_get_effective_recv_data_length(**session));
}

void Http2Session::GetNextStreamID(Local<String> property,
                                   const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  info.GetReturnValue().Set(nghttp2_session_get_next_stream_id(**session));
}

void Http2Session::SetNextStreamID(Local<String> property,
                                   Local<Value> value,
                                   const PropertyCallbackInfo<void>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  Environment* env = session->env();
  int32_t id = value->Int32Value();
  nghttp2_session_set_next_stream_id(**session, id);
}

void Http2Session::GetLocalWindowSize(Local<String> property,
                                   const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  info.GetReturnValue().Set(nghttp2_session_get_local_window_size(**session));
}

void Http2Session::GetLastProcStreamID(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  info.GetReturnValue().Set(nghttp2_session_get_last_proc_stream_id(**session));
}

void Http2Session::GetRemoteWindowSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  info.GetReturnValue().Set(nghttp2_session_get_remote_window_size(**session));
}

void Http2Session::GetOutboundQueueSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  size_t size = nghttp2_session_get_outbound_queue_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}

void Http2Session::GetDeflateDynamicTableSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  size_t size = nghttp2_session_get_hd_deflate_dynamic_table_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}

void Http2Session::GetInflateDynamicTableSize(
    Local<String> property,
    const PropertyCallbackInfo<Value>& info) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, info.Holder());
  if (!**session)
    return;
  size_t size = nghttp2_session_get_hd_inflate_dynamic_table_size(**session);
  Environment* env = session->env();
  info.GetReturnValue().Set(Integer::New(env->isolate(), size));
}

void Http2Session::SetLocalWindowSize(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  Environment* env = Environment::GetCurrent(args);
  if (!**session)
    return;
  int32_t stream = args[0]->Int32Value();
  int32_t size = args[1]->Int32Value();
  int rv = nghttp2_session_set_local_window_size(session->session_,
                                                 NGHTTP2_FLAG_NONE,
                                                 stream, size);
  if (rv != 0) {
   // TODO: Better error message.
   // if rv == -501 == Invalid Arguments... what to do?
   Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
   Local<Object> obj = e->ToObject(env->isolate());
   obj->Set(env->code_string(), ERROR_STR(rv));
   args.GetReturnValue().Set(e);
  }
}

void Http2Session::GetLocalSetting(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  nghttp2_settings_id id =
      static_cast<nghttp2_settings_id>(args[0]->Uint32Value());
  if (id < NGHTTP2_SETTINGS_HEADER_TABLE_SIZE ||
      id > NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)
    return;
  args.GetReturnValue().Set(nghttp2_session_get_local_settings(**session, id));
}

void Http2Session::GetRemoteSetting(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  nghttp2_settings_id id =
      static_cast<nghttp2_settings_id>(args[0]->Uint32Value());
  if (id < NGHTTP2_SETTINGS_HEADER_TABLE_SIZE ||
      id > NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE)
    return;
  args.GetReturnValue().Set(nghttp2_session_get_remote_settings(**session, id));
}

/**
 * Destroys the underlying nghttp2_session so that it can no longer
 * be used and all associated memory is freed. After calling this,
 * The Http2Session object will no longer be usable and calls to any
 * of the methods except GetType() will abort. GetType() will return -1
 * Any passed arguments will be ignored.
 * Returns undefined.
 * Has no effect if the session has already been destroyed.
 **/
void Http2Session::Destroy(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  nghttp2_session_del(session->session_);
  session->session_ = nullptr;
}

/**
 * Causes the session to be terminated but not destroyed. Termination here
 * means sending the GOAWAY frame to the connected peer. This will not
 * interrupt existing streams, which will be allowed to complete, but will
 * half-close the connection so that any new frames/streams cannot be
 * created. Destroy() must be called to actually tear down the session and
 * free resources.
 * Arguments:
 *   code {Integer} The goaway code, if any 
 * Returns undefined if successfull, Error if not
 * Aborts if the session has been destroyed.
 **/
void Http2Session::Terminate(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  uint32_t error_code = args[0]->Uint32Value();
  uint32_t last_proc = args[1]->Uint32Value();

  int rv = last_proc > 0 ?
    nghttp2_session_terminate_session2(**session, last_proc, error_code) :
    nghttp2_session_terminate_session(**session, error_code);
  if (rv != 0) {
    // TODO: Better error message
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

/**
 * Change the priority of the given stream
 * Arguments:
 *   stream {Integer} The Stream ID
 *   parent {Integer} The parent Stream ID
 *   weight {Integer} The weight
 *   exclusive {Boolean} true or false
 * Returns undefined if successful, Error if not
 * Aborts if the session has been destroyed or streamID is not given
 **/
void Http2Session::ChangeStreamPriority(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;

  Environment* env = Environment::GetCurrent(args);
  int32_t stream = args[0]->Int32Value();
  int32_t parent = 0;      // Root Stream
  int32_t weight = 16;     // Default Weight
  bool exclusive = false;  // Non-Exclusive

  int argslen = args.Length();
  if (argslen > 1)
    parent = args[1]->Int32Value();
  if (argslen > 2)
    weight = args[2]->Int32Value();
  if (argslen > 3)
    exclusive = args[3]->BooleanValue();

  nghttp2_priority_spec pri_spec;
  nghttp2_priority_spec_init(&pri_spec, parent, weight, exclusive);
  int rv = nghttp2_session_change_stream_priority(**session, stream, &pri_spec);
  if (rv != 0) {
    // TODO: Better error message.
    // if rv == -501 == Invalid Arguments... what to do?
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

/**
 * Arguments
 *  stream {integer}
 *  size (integer)
 * Returns undefined if successful, Error if not
 * Aborts if session is null or not enough arguments are passed
 */
void Http2Session::Consume(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  int32_t stream = args[0]->Int32Value();
  size_t size = args[1]->Uint32Value();

  int rv = nghttp2_session_consume(**session, stream, size);
  if (rv != 0) {
    // TODO: Better error message.
    // if rv == -501 == Invalid Arguments... what to do?
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

/**
 * Arguments
 *  size (integer)
 * Returns undefined if successful, Error if not
 * Aborts if session is null or not enough arguments are passed
 */
void Http2Session::ConsumeSession(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  size_t size = args[0]->Uint32Value();

  int rv = nghttp2_session_consume_connection(**session, size);
  if (rv != 0) {
    // TODO: Better error message.
    // if rv == -501 == Invalid Arguments... what to do?
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

/**
 * Arguments
 *  stream {integer}
 *  size (integer)
 * Returns undefined if successful, Error if not
 * Aborts if session is null or not enough arguments are passed
 */
void Http2Session::ConsumeStream(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  int32_t stream = args[0]->Int32Value();
  size_t size = args[1]->Uint32Value();

  int rv = nghttp2_session_consume_stream(**session, stream, size);
  if (rv != 0) {
    // TODO: Better error message.
    // if rv == -501 == Invalid Arguments... what to do?
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

/**
 * Arguments
 *  stream {integer}
 *  parent (integer)
 *  weight {integer}
 *  exclusive {boolean}
 **/
void Http2Session::CreateIdleStream(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  const int argslen = args.Length();

  int32_t stream = args[0]->Int32Value();
  int32_t parent = -1;
  int32_t weight = 16;
  bool exclusive = false;

  if (argslen > 1)
    parent = args[1]->Int32Value();
  if (argslen > 2)
    weight = args[2]->Int32Value();
  if (argslen > 3)
    exclusive = args[3]->BooleanValue();

  if (parent == -1) parent = stream;

  nghttp2_priority_spec pri_spec;
  nghttp2_priority_spec_init(&pri_spec, parent, weight, exclusive);
  int rv;
  rv = nghttp2_session_create_idle_stream(**session, stream, &pri_spec);
  if (rv != 0) {
   // TODO: Better error message.
   // if rv == -501 == Invalid Arguments... what to do?
   Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
   Local<Object> obj = e->ToObject(env->isolate());
   obj->Set(env->code_string(), ERROR_STR(rv));
   args.GetReturnValue().Set(e);
  }
}

void Http2Session::GetStreamLocalClose(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  int32_t stream = 0;
  if (args.Length() > 0)
    stream = args[0]->Int32Value();
  Environment* env = Environment::GetCurrent(args);
  int ret = nghttp2_session_get_stream_local_close(**session, stream);
  args.GetReturnValue().Set(Integer::New(env->isolate(), ret));
}

void Http2Session::GetStreamRemoteClose(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  int32_t stream = 0;
  if (args.Length() > 0)
    stream = args[0]->Int32Value();
  Environment* env = Environment::GetCurrent(args);
  int ret = nghttp2_session_get_stream_remote_close(**session, stream);
  args.GetReturnValue().Set(Integer::New(env->isolate(), ret));
}

void Http2Session::GetStreamState(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  int32_t stream = args[0]->Int32Value();
  nghttp2_stream* stream_ = nghttp2_session_find_stream(**session, stream);
  if (stream_ != nullptr)
    args.GetReturnValue().Set(nghttp2_stream_get_state(stream_));
}

void Http2Session::GetStreamWeight(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;

  Environment* env = Environment::GetCurrent(args);
  int32_t stream = args[0]->Int32Value();
  bool dependencies = false;
  if (args.Length() > 1)
    dependencies = args[1]->BooleanValue();
  int32_t weight = 0;
  nghttp2_stream* stream_ = nghttp2_session_find_stream(**session, stream);
  if (stream_ != nullptr) {
    weight = dependencies ?
      nghttp2_stream_get_sum_dependency_weight(stream_) :
      nghttp2_stream_get_weight(stream_);
  }
  args.GetReturnValue().Set(Integer::New(env->isolate(), weight));
}

void Http2Session::SendServerConnectionHeader(
    const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  // TODO: Get the settings somehow
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  rv = nghttp2_submit_settings(**session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
  if (rv != 0) {
    // TODO: Better error message.
    // if rv == -501 == Invalid Arguments... what to do?
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Http2Session::ReceiveData(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  
  Environment* env = Environment::GetCurrent(args);
  // THROW_AND_RETURN_UNLESS_BUFFER(env, args[0]);
  // SPREAD_ARG(args[0], ts_obj);
  // 
  // uint8_t* data = reinterpret_cast<uint8_t*>(ts_obj_data);
  // 
  // ssize_t readlen;
  // 
  // readlen = nghttp2_session_mem_recv(**session, data, ts_obj_length);
  // 
  // if (readlen < 0) {
  //   // what is a good error to return?
  //   Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
  //   Local<Object> obj = e->ToObject(env->isolate());
  //   obj->Set(env->code_string(), ERROR_STR(readlen));
  //   args.GetReturnValue().Set(e);
  // }
}

void Http2Session::SendData(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  int rv = nghttp2_session_send(**session);
  if (rv != 0) {
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Http2Session::RstStream(const FunctionCallbackInfo<Value>& args) {
}

void Http2Session::Respond(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);

  Http2Stream* stream;
  nghttp2_data_provider* provider;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
  std::vector<nghttp2_nv> headers;

  if (args.Length() > 1) {
    // args[1], if given, must be an array of Http2Header objects
    if(!args[1]->IsArray())
      return env->ThrowTypeError(
          "Second argument must be an array of Http2Header objects");
    Local<Array> headers_array = args[1].As<Array>();
    int length = headers_array->Length();
    for (int i = 0; i < length; i++) {
      Local<Value> val = headers_array->Get(i);
      if(!val->IsObject())
        return env->ThrowTypeError("Value must be an Http2Header object");
      Http2Header* header;
      ASSIGN_OR_RETURN_UNWRAP(&header, val.As<Object>());
      headers.push_back(**header);
    }
  }
  if (args.Length() > 2) {
    // args[2], if given, must be a Http2DataProvider object
    if(!args[2]->IsObject())
      return env->ThrowTypeError(
        "Third argument must be an Http2DataProvider object");
    Http2DataProvider* dataProvider;
    ASSIGN_OR_RETURN_UNWRAP(&dataProvider, args[2].As<Object>());
    provider = **dataProvider;
  }

  int rv = nghttp2_submit_response(**session,
                                   stream->stream_id_,
                                   &headers[0],
                                   headers.size(), 
                                   provider);
  
  if (rv != 0) {
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Http2Session::SendContinue(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
  nghttp2_nv headers[] { MAKE_NV(":status", "100") };
  int rv = nghttp2_submit_headers(**session,
                                  NGHTTP2_FLAG_NONE,
                                  stream->stream_id_,
                                  nullptr,
                                  &headers[0], 1, nullptr);
  if (rv != 0) {
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Http2Session::ResumeData(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();
  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());
  nghttp2_nv headers[] { MAKE_NV(":status", "100") };
  int rv = nghttp2_session_resume_data(**session, stream->stream_id_);
  if (rv != 0) {
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Http2Session::SendTrailers(const FunctionCallbackInfo<Value>& args) {
  Http2Session* session;
  ASSIGN_OR_RETURN_UNWRAP(&session, args.Holder());
  if (!**session)
    return;
  Environment* env = Environment::GetCurrent(args);
  Isolate* isolate = env->isolate();

  Http2Stream* stream;
  ASSIGN_OR_RETURN_UNWRAP(&stream, args[0].As<Object>());

  std::vector<nghttp2_nv> headers;

  if (args.Length() > 1) {
    // args[1], if given, must be an array of Http2Header objects
    if(!args[1]->IsArray())
      return env->ThrowTypeError(
          "Argument must be an array of Http2Header objects");
    Local<Array> headers_array = args[1].As<Array>();
    int length = headers_array->Length();
    for (int i = 0; i < length; i++) {
      Local<Value> val = headers_array->Get(i);
      if(!val->IsObject())
        return env->ThrowTypeError("value must be an Http2Header object");
      Http2Header* header;
      ASSIGN_OR_RETURN_UNWRAP(&header, val.As<Object>());
      headers.push_back(**header);
    }
  }

  int rv = nghttp2_submit_headers(**session,
                                  NGHTTP2_FLAG_END_STREAM,
                                  stream->stream_id_,
                                  nullptr,
                                  &headers[0], 1, nullptr);
  if (rv != 0) {
    Local<Value> e = Exception::Error(OneByteString(env->isolate(), "Error"));
    Local<Object> obj = e->ToObject(env->isolate());
    obj->Set(env->code_string(), ERROR_STR(rv));
    args.GetReturnValue().Set(e);
  }
}

void Initialize(Local<Object> target,
                Local<Value> unused,
                Local<Context> context,
                void* priv) {
  Environment* env = Environment::GetCurrent(context);
  Isolate* isolate = env->isolate();

  Local<FunctionTemplate> provider =
      env->NewFunctionTemplate(Http2DataProvider::New);
  provider->InstanceTemplate()->SetInternalFieldCount(1);
  provider->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2DataProvider"));
  target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2DataProvider"),
              provider->GetFunction());

  Local<FunctionTemplate> header =
      env->NewFunctionTemplate(Http2Header::New);
  header->InstanceTemplate()->SetInternalFieldCount(1);
  header->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2Header"));
  target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2Header"),
              header->GetFunction());

  Local<FunctionTemplate> t =
      env->NewFunctionTemplate(Http2Session::New);
  t->SetClassName(FIXED_ONE_BYTE_STRING(isolate, "Http2Session"));
  Local<ObjectTemplate> instance = t->InstanceTemplate();
  instance->SetInternalFieldCount(1);
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
      nullptr,
      Local<Value>(),
      v8::DEFAULT,
      v8::DontDelete);

  env->SetProtoMethod(t, "setLocalWindowSize",
                      Http2Session::SetLocalWindowSize);
  env->SetProtoMethod(t, "getLocalSetting",
                      Http2Session::GetLocalSetting);
  env->SetProtoMethod(t, "getRemoteSetting",
                      Http2Session::GetRemoteSetting);
  env->SetProtoMethod(t, "destroy",
                      Http2Session::Destroy);
  env->SetProtoMethod(t, "terminate",
                      Http2Session::Terminate);
  env->SetProtoMethod(t, "changeStreamPriority",
                      Http2Session::ChangeStreamPriority);
  env->SetProtoMethod(t, "consume",
                      Http2Session::Consume);
  env->SetProtoMethod(t, "consumeSession",
                      Http2Session::ConsumeSession);
  env->SetProtoMethod(t, "consumeStream",
                      Http2Session::ConsumeStream);
  env->SetProtoMethod(t, "createIdleStream",
                      Http2Session::CreateIdleStream);
  env->SetProtoMethod(t, "getStreamLocalClose",
                      Http2Session::GetStreamLocalClose);
  env->SetProtoMethod(t, "getStreamRemoteClose",
                      Http2Session::GetStreamRemoteClose);
  env->SetProtoMethod(t, "getStreamState",
                      Http2Session::GetStreamState);
  env->SetProtoMethod(t, "getStreamWeight",
                      Http2Session::GetStreamWeight);
  env->SetProtoMethod(t, "sendServerConnectionHeader",
                      Http2Session::SendServerConnectionHeader);
  env->SetProtoMethod(t, "receiveData",
                      Http2Session::ReceiveData);
  env->SetProtoMethod(t, "sendData",
                      Http2Session::SendData);
  env->SetProtoMethod(t, "rstStream",
                      Http2Session::RstStream);
  env->SetProtoMethod(t, "respond",
                      Http2Session::Respond);
  env->SetProtoMethod(t, "sendContinue", Http2Session::SendContinue);
  env->SetProtoMethod(t, "resumeData", Http2Session::ResumeData);
  env->SetProtoMethod(t, "sendTrailers", Http2Session::SendTrailers);

  target->Set(FIXED_ONE_BYTE_STRING(isolate, "Http2Session"),
              t->GetFunction());

  Local<Object> constants = Object::New(isolate);
  NODE_DEFINE_CONSTANT(constants, SESSION_TYPE_SERVER);
  NODE_DEFINE_CONSTANT(constants, SESSION_TYPE_CLIENT);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_HEADER_TABLE_SIZE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_ENABLE_PUSH);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_MAX_FRAME_SIZE);
  NODE_DEFINE_CONSTANT(constants, NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE);

#define V(name) NODE_DEFINE_CONSTANT(constants, CALLBACK_##name);
SESSION_CALLBACKS(V)
#undef V
#define V(name) NODE_DEFINE_CONSTANT(constants, FLAG_##name);
DATA_FLAGS(V)
#undef V

  target->Set(FIXED_ONE_BYTE_STRING(isolate, "constants"), constants);
}
} // namespace http2
} // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(http2, node::http2::Initialize)
