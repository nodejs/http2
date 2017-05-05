#ifndef SRC_NODE_HTTP2_CORE_H_
#define SRC_NODE_HTTP2_CORE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "util.h"
#include "util-inl.h"
#include "uv.h"
#include "nghttp2/nghttp2.h"

#include <unordered_map>
#include <memory>
#include <string>

namespace node {
namespace http2 {

class Nghttp2Session;
class Nghttp2Stream;

struct nghttp2_stream_write_t;
struct nghttp2_data_chunk_t;
struct nghttp2_data_chunks_t;

#define MAX_BUFFER_COUNT 10
#define SEND_BUFFER_RECOMMENDED_SIZE 4096

enum nghttp2_session_type {
  NGHTTP2_SESSION_SERVER,
  NGHTTP2_SESSION_CLIENT
};

enum nghttp2_shutdown_flags {
  NGHTTP2_SHUTDOWN_FLAG_GRACEFUL,
  NGHTTP2_SHUTDOWN_FLAG_IMMEDIATE
};

enum nghttp2_stream_flags {
  NGHTTP2_STREAM_FLAG_NONE = 0x0,
  // Writable side has ended
  NGHTTP2_STREAM_FLAG_SHUT = 0x1,
  // Readable side has ended
  NGHTTP2_STREAM_FLAG_ENDED = 0x2
};


// Callbacks
typedef void (*nghttp2_stream_write_cb)(
    nghttp2_stream_write_t* req,
    int status);


struct nghttp2_stream_write_queue {
  unsigned int nbufs = 0;
  nghttp2_stream_write_t* req = nullptr;
  nghttp2_stream_write_cb cb = nullptr;
  nghttp2_stream_write_queue* next = nullptr;
  MaybeStackBuffer<uv_buf_t, MAX_BUFFER_COUNT> bufs;
};

struct nghttp2_header_list {
  nghttp2_rcbuf* name = nullptr;
  nghttp2_rcbuf* value = nullptr;
  nghttp2_header_list* next = nullptr;
};

typedef enum {
  NGHTTP2_CB_NONE,
  NGHTTP2_CB_SESSION_SEND,
  NGHTTP2_CB_HEADERS,
  NGHTTP2_CB_STREAM_CLOSE,
  NGHTTP2_CB_DATA_CHUNKS,
  NGHTTP2_CB_SETTINGS,
} nghttp2_pending_cb_type;

struct nghttp2_pending_settings_cb {};

struct nghttp2_pending_data_chunks_cb {
  std::shared_ptr<Nghttp2Stream> handle;
  nghttp2_data_chunk_t* head = nullptr;
  nghttp2_data_chunk_t* tail = nullptr;
  unsigned int nbufs = 0;
  uint8_t flags = NGHTTP2_FLAG_NONE;
};

struct nghttp2_pending_session_send_cb {
  size_t length = 0;
  uv_buf_t* buf = nullptr;
};

struct nghttp2_pending_headers_cb {
  std::shared_ptr<Nghttp2Stream> handle;
  nghttp2_headers_category category = NGHTTP2_HCAT_HEADERS;
  nghttp2_header_list* headers = nullptr;
  uint8_t flags = NGHTTP2_FLAG_NONE;
};

struct nghttp2_pending_stream_close_cb {
  std::shared_ptr<Nghttp2Stream> handle;
  uint32_t error_code = NGHTTP2_NO_ERROR;
};

struct nghttp2_pending_cb_list {
  nghttp2_pending_cb_type type = NGHTTP2_CB_NONE;
  void* cb = nullptr;
  nghttp2_pending_cb_list* next = nullptr;
};

// Handle Types
class Nghttp2Session {
 public:
  inline bool HasStream(int32_t id);
  inline std::shared_ptr<Nghttp2Stream> FindStream(int32_t id);

  inline int32_t SubmitRequest(
      nghttp2_priority_spec* prispec,
      nghttp2_nv* nva,
      size_t len,
      std::shared_ptr<Nghttp2Stream>* assigned = nullptr,
      bool emptyPayload = true);

  inline void SubmitShutdownNotice();

  inline int Init(
      uv_loop_t*,
      const nghttp2_session_type type = NGHTTP2_SESSION_SERVER,
      nghttp2_option* options = nullptr,
      nghttp2_mem* mem = nullptr);
  inline int Free();

  inline bool IsAliveSession();
  inline ssize_t Write(const uv_buf_t* bufs, unsigned int nbufs);

  inline int SubmitSettings(const nghttp2_settings_entry iv[], size_t niv);
  inline std::shared_ptr<Nghttp2Stream> StreamInit(
        int32_t id,
        nghttp2_headers_category category = NGHTTP2_HCAT_HEADERS);

  inline nghttp2_session* session() { return session_; }

 protected:
  virtual void OnStreamInit(std::shared_ptr<Nghttp2Stream> stream) {}
  virtual void OnStreamFree(Nghttp2Stream* stream) {}
  virtual void Send(uv_buf_t* buf,
                    size_t length) {}
  virtual void OnHeaders(std::shared_ptr<Nghttp2Stream> stream,
                         nghttp2_header_list* headers,
                         nghttp2_headers_category cat,
                         uint8_t flags) {}
  virtual void OnStreamClose(int32_t id,
                             uint32_t error_code) {}
  virtual void OnDataChunks(std::shared_ptr<Nghttp2Stream> stream,
                            std::shared_ptr<nghttp2_data_chunks_t> chunks) {}
  virtual void OnSettings() {}
  virtual ssize_t GetPadding(size_t frameLength,
                             size_t maxFrameLength) { return 0; }
  virtual void OnTrailers(std::shared_ptr<Nghttp2Stream> stream,
                          MaybeStackBuffer<nghttp2_nv>* nva) {}
  virtual void OnFreeSession() {}
  virtual uv_buf_t* AllocateSend(size_t suggested_size) = 0;

  virtual bool HasGetPaddingCallback() { return false; }

 private:
  inline void SendAndMakeReady();
  inline void DrainSend();
  inline void QueuePendingCallback(nghttp2_pending_cb_list* item);
  inline void DrainHeaders(nghttp2_pending_headers_cb*);
  inline void DrainStreamClose(nghttp2_pending_stream_close_cb*);
  inline void DrainSend(nghttp2_pending_session_send_cb*);
  inline void DrainDataChunks(nghttp2_pending_data_chunks_cb*);
  inline void DrainSettings(nghttp2_pending_settings_cb*);
  inline void DrainCallbacks();

  static void StreamDeleter(Nghttp2Stream* handle);

  /* callbacks for nghttp2 */
  static int OnBeginHeadersCallback(nghttp2_session* session,
                                    const nghttp2_frame* frame,
                                    void* user_data);
  static int OnHeaderCallback(nghttp2_session* session,
                              const nghttp2_frame* frame,
                              nghttp2_rcbuf* name,
                              nghttp2_rcbuf* value,
                              uint8_t flags,
                              void* user_data);
  static int OnFrameReceive(nghttp2_session* session,
                            const nghttp2_frame* frame,
                            void* user_data);
  static int OnStreamClose(nghttp2_session* session,
                           int32_t stream_id,
                           uint32_t error_code,
                           void* user_data);
  static int OnBeginFrameReceived(nghttp2_session* session,
                                  const nghttp2_frame_hd* hd,
                                  void* user_data);
  static int OnDataChunkReceived(nghttp2_session* session,
                                 uint8_t flags,
                                 int32_t stream_id,
                                 const uint8_t *data,
                                 size_t len,
                                 void* user_data);

  inline void QueuePendingDataChunks(Nghttp2Stream* stream,
                                     uint8_t flags = NGHTTP2_FLAG_NONE);

  static ssize_t OnStreamRead(nghttp2_session* session,
                              int32_t stream_id,
                              uint8_t* buf,
                              size_t length,
                              uint32_t* flags,
                              nghttp2_data_source* source,
                              void* user_data);
  static ssize_t OnSelectPadding(nghttp2_session* session,
                                 const nghttp2_frame* frame,
                                 size_t maxPayloadLen,
                                 void* user_data);

  struct Callbacks {
    inline explicit Callbacks(bool kHasGetPaddingCallback);
    inline ~Callbacks();

    nghttp2_session_callbacks* callbacks;
  };

  /* Use callback_struct_saved[kHasGetPaddingCallback ? 1 : 0] */
  static Callbacks callback_struct_saved[2];

  nghttp2_session* session_;
  uv_loop_t* loop_;
  uv_prepare_t prep_;
  nghttp2_session_type session_type_;
  nghttp2_pending_cb_list* pending_callbacks_head_ = nullptr;
  nghttp2_pending_cb_list* pending_callbacks_tail_ = nullptr;
  nghttp2_pending_cb_list* ready_callbacks_head_ = nullptr;
  nghttp2_pending_cb_list* ready_callbacks_tail_ = nullptr;
  std::unordered_map<int32_t, std::shared_ptr<Nghttp2Stream>> streams_;

  friend class Nghttp2Stream;
};

class Nghttp2Stream : public std::enable_shared_from_this<Nghttp2Stream> { 
 public:
  inline ~Nghttp2Stream();

  inline int Write(
      nghttp2_stream_write_t* req,
      const uv_buf_t bufs[],
      unsigned int nbufs,
      nghttp2_stream_write_cb cb);

  inline int SubmitResponse(nghttp2_nv* nva,
                            size_t len,
                            bool emptyPayload = false);

  inline int SubmitInfo(nghttp2_nv* nva, size_t len);
  inline int SubmitPriority(nghttp2_priority_spec* prispec,
                            bool silent = false);
  inline int SubmitRstStream(const uint32_t code);
  inline int SubmitPushPromise(
      nghttp2_nv* nva,
      size_t len,
      std::shared_ptr<Nghttp2Stream>* assigned = nullptr,
      bool writable = true);

  inline int Shutdown();
  inline void ReadStart();
  inline void ReadStop();

  inline bool IsWritable() const;
  inline bool IsReadable() const;
  inline bool IsReading() const;

  inline int32_t id() const;

 private:
  Nghttp2Session* session_ = nullptr;
  int32_t id_ = 0;
  int flags_ = 0;
  nghttp2_stream_write_queue* queue_head_ = nullptr;
  nghttp2_stream_write_queue* queue_tail_ = nullptr;
  unsigned int queue_head_index_ = 0;
  size_t queue_head_offset_ = 0;
  nghttp2_header_list* current_headers_head_ = nullptr;
  nghttp2_header_list* current_headers_tail_ = nullptr;
  nghttp2_headers_category current_headers_category_ = NGHTTP2_HCAT_HEADERS;
  nghttp2_pending_data_chunks_cb* current_data_chunks_cb_ = nullptr;
  int reading_ = -1;
  int32_t prev_local_window_size_ = 65535;

  friend class Nghttp2Session;
};

struct nghttp2_stream_write_t {
  void* data;
  int status;
  std::shared_ptr<Nghttp2Stream> handle;
  nghttp2_stream_write_queue* item;
};

struct nghttp2_data_chunk_t {
  uv_buf_t buf;
  nghttp2_data_chunk_t* next = nullptr;
};

struct nghttp2_data_chunks_t {
  unsigned int nbufs = 0;
  uv_buf_t buf[MAX_BUFFER_COUNT];

  inline ~nghttp2_data_chunks_t();
};

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_CORE_H_
