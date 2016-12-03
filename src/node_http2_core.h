#ifndef SRC_NODE_HTTP2_CORE_H_
#define SRC_NODE_HTTP2_CORE_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "util.h"
#include "util-inl.h"
#include "uv.h"
#include "nghttp2/nghttp2.h"

#include <map>
#include <memory>
#include <string>

typedef struct nghttp2_session_s nghttp2_session_t;
typedef struct nghttp2_stream_s nghttp2_stream_t;
typedef struct nghttp2_stream_write_s nghttp2_stream_write_t;
typedef struct nghttp2_data_chunk_s nghttp2_data_chunk_t;
typedef struct nghttp2_data_chunks_s nghttp2_data_chunks_t;
typedef struct node_nghttp2_session_callbacks_s node_nghttp2_session_callbacks;

static const int kSimultaneousBufferCount = 10;

typedef enum {
  NGHTTP2_SESSION_SERVER,
  NGHTTP2_SESSION_CLIENT
} nghttp2_session_type;

typedef enum {
  NGHTTP2_SESSION,
  NGHTTP2_STREAM
} nghttp2_handle_type;

typedef enum {
  NGHTTP2_SHUTDOWN_FLAG_GRACEFUL,
  NGHTTP2_SHUTDOWN_FLAG_IMMEDIATE
} nghttp2_shutdown_flags;

#define NGHTTP2_HANDLE_FIELDS                                                 \
  /* public */                                                                \
  void* data;                                                                 \
  /* read-only */                                                             \
  uv_loop_t* loop;                                                            \
  nghttp2_handle_type type;                                                   \
  /* private */                                                               \
  uv_close_cb close_cb;                                                       \
  void* handle_queue[2];                                                      \
  union {                                                                     \
    int fd;                                                                   \
    void* reserved[4];                                                        \
  } u;                                                                        \
  int flags = 0;

#define NGHTTP2_SESSION_FIELDS                                                \
  nghttp2_session* session;                                                   \
  nghttp2_session_type session_type;                                          \
  node_nghttp2_session_callbacks callbacks;                                   \
  uv_idle_t idler;                                                            \
  nghttp2_pending_cb_list* pending_callbacks_head = nullptr;                  \
  nghttp2_pending_cb_list* pending_callbacks_tail = nullptr;                  \
  nghttp2_pending_cb_list* ready_callbacks_head = nullptr;                    \
  nghttp2_pending_cb_list* ready_callbacks_tail = nullptr;                    \
  std::map<int32_t, std::shared_ptr<nghttp2_stream_t>> streams;

#define NGHTTP2_STREAM_FIELDS                                                 \
  nghttp2_session_t* session = nullptr;                                       \
  int32_t id = 0;                                                             \
  nghttp2_stream_write_queue* queue_head = nullptr;                           \
  nghttp2_stream_write_queue* queue_tail = nullptr;                           \
  unsigned int queue_head_index = 0;                                          \
  nghttp2_header_list* current_headers_head = nullptr;                        \
  nghttp2_header_list* current_headers_tail = nullptr;                        \
  nghttp2_headers_category current_headers_category = NGHTTP2_HCAT_HEADERS;   \
  nghttp2_pending_data_chunks_cb* current_data_chunks_cb = nullptr;           \
  int reading = -1;                                                           \
  int32_t prev_local_window_size = 65535;                                     \

#define NGHTTP2_REQ_FIELDS                                                    \
  /* public */                                                                \
  void* data;                                                                 \
  /* read-only */                                                             \
  uv_req_type type;                                                           \
  /* private */                                                               \
  void* active_queue[2];                                                      \
  void* reserved[4];                                                          \
  uv_work_t work_req;                                                         \
  int status;

// Callbacks
typedef void (*nghttp2_stream_alloc_cb)(
    std::shared_ptr<nghttp2_stream_t> handle,
    size_t suggested_size,
    const uv_buf_t* buf);
typedef void (*nghttp2_stream_read_cb)(
    std::shared_ptr<nghttp2_stream_t> stream,
    ssize_t nread,
    const uv_buf_t* buf);
typedef void (*nghttp2_stream_write_cb)(
    nghttp2_stream_write_t* req,
    int status);


struct nghttp2_stream_write_queue {
  node::MaybeStackBuffer<uv_buf_t, kSimultaneousBufferCount> bufs;
  unsigned int nbufs = 0;
  nghttp2_stream_write_t* req = nullptr;
  nghttp2_stream_write_cb cb = nullptr;
  nghttp2_stream_write_queue* next = nullptr;
};

struct nghttp2_header_list {
  nghttp2_rcbuf* name;
  nghttp2_rcbuf* value;
  nghttp2_header_list* next = nullptr;
};

typedef enum {
  NGHTTP2_CB_SESSION_SEND,
  NGHTTP2_CB_HEADERS,
  NGHTTP2_CB_STREAM_CLOSE,
  NGHTTP2_CB_DATA_CHUNKS,
  NGHTTP2_CB_SETTINGS,
} nghttp2_pending_cb_type;

struct nghttp2_pending_settings_cb {};

struct nghttp2_pending_data_chunks_cb {
  std::shared_ptr<nghttp2_stream_t> handle;
  nghttp2_data_chunk_t* head = nullptr;
  nghttp2_data_chunk_t* tail = nullptr;
  unsigned int nbufs = 0;
  uint8_t flags = NGHTTP2_FLAG_NONE;
};

struct nghttp2_pending_session_send_cb {
  node::MaybeStackBuffer<uv_buf_t, kSimultaneousBufferCount> bufs;
  unsigned int nbufs = 0;
  size_t total = 0;
};

struct nghttp2_pending_headers_cb {
  std::shared_ptr<nghttp2_stream_t> handle;
  nghttp2_headers_category category;
  nghttp2_header_list* headers = nullptr;
  uint8_t flags = NGHTTP2_FLAG_NONE;
};

struct nghttp2_pending_stream_close_cb {
  std::shared_ptr<nghttp2_stream_t> handle;
  uint32_t error_code;
};

struct nghttp2_pending_cb_list {
  nghttp2_pending_cb_type type;
  void* cb;
  nghttp2_pending_cb_list* next = nullptr;
};

typedef void (*nghttp2_on_stream_init_cb)(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> stream);
typedef void (*nghttp2_on_stream_free_cb)(
    nghttp2_session_t* session,
    nghttp2_stream_t* stream);
typedef void (*nghttp2_session_send_cb)(
    nghttp2_session_t* session,
    const uv_buf_t* bufs,
    unsigned int nbufs,
    size_t total);
typedef void (*nghttp2_session_on_headers_cb)(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> stream,
    nghttp2_header_list* headers,
    nghttp2_headers_category cat,
    uint8_t flags);
typedef void (*nghttp2_session_on_stream_close_cb)(
    nghttp2_session_t* session,
    int32_t id,
    uint32_t error_code);
typedef void (*nghttp2_session_on_data_chunks_cb)(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> stream,
    std::shared_ptr<nghttp2_data_chunks_t> chunks);
typedef void (*nghttp2_session_on_settings_cb)(
    nghttp2_session_t* session);
typedef void (*nghttp2_stream_get_trailers_cb)(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> stream,
    std::vector<nghttp2_nv>* nva);

struct node_nghttp2_session_callbacks_s {
  nghttp2_on_stream_init_cb stream_init = nullptr;
  nghttp2_on_stream_free_cb stream_free = nullptr;
  nghttp2_session_send_cb send = nullptr;
  nghttp2_session_on_headers_cb on_headers = nullptr;
  nghttp2_session_on_stream_close_cb on_stream_close = nullptr;
  nghttp2_session_on_data_chunks_cb on_data_chunks = nullptr;
  nghttp2_session_on_settings_cb on_settings = nullptr;
  nghttp2_stream_get_trailers_cb on_get_trailers = nullptr;
};

// Handle Types
struct nghttp2_session_s {
  NGHTTP2_HANDLE_FIELDS
  NGHTTP2_SESSION_FIELDS
};

struct nghttp2_stream_s {
  NGHTTP2_HANDLE_FIELDS
  NGHTTP2_STREAM_FIELDS
};

struct nghttp2_stream_write_s {
  NGHTTP2_REQ_FIELDS
  std::shared_ptr<nghttp2_stream_t> handle;
  nghttp2_stream_write_queue* item;
};

struct nghttp2_data_chunk_s {
  uv_buf_t buf;
  nghttp2_data_chunk_t* next = nullptr;
};

struct nghttp2_data_chunks_s {
  node::MaybeStackBuffer<uv_buf_t, kSimultaneousBufferCount> buf;
  unsigned int nbufs;
};

UV_EXTERN bool nghttp2_session_has_stream(
    nghttp2_session_t* handle,
    int32_t id);

UV_EXTERN bool nghttp2_session_find_stream(
    nghttp2_session_t* handle,
    int32_t id,
    std::shared_ptr<nghttp2_stream_t>* stream_handle);

UV_EXTERN void nghttp2_set_callback_stream_get_trailers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_stream_get_trailers_cb cb);

UV_EXTERN void nghttp2_set_callback_on_settings(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_settings_cb cb);

UV_EXTERN void nghttp2_set_callback_stream_init(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_init_cb cb);

UV_EXTERN void nghttp2_set_callback_stream_free(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_free_cb cb);

UV_EXTERN void nghttp2_set_callback_send(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_send_cb cb);

UV_EXTERN void nghttp2_set_callback_on_headers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_headers_cb cb);

UV_EXTERN void nghttp2_set_callback_on_stream_close(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_stream_close_cb cb);

UV_EXTERN void nghttp2_set_callback_on_data_chunks(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_data_chunks_cb cb);

UV_EXTERN int nghttp2_session_init(
    uv_loop_t*,
    nghttp2_session_t* handle,
    const node_nghttp2_session_callbacks* cb,
    const nghttp2_session_type type = NGHTTP2_SESSION_SERVER,
    nghttp2_option* options = nullptr,
    nghttp2_mem* mem = nullptr);

UV_EXTERN std::shared_ptr<nghttp2_stream_t> nghttp2_stream_init(
    nghttp2_session_t* handle,
    int32_t id,
    nghttp2_headers_category category);

UV_EXTERN int nghttp2_session_free(
    nghttp2_session_t* handle,
    bool forced = false);

UV_EXTERN int nghttp2_session_is_alive(
    nghttp2_session_t* handle);

UV_EXTERN ssize_t nghttp2_session_write(
    nghttp2_session_t* handle,
    const uv_buf_t* bufs,
    unsigned int nbufs);

UV_EXTERN int nghttp2_submit_settings(
    nghttp2_session_t* handle,
    const nghttp2_settings_entry iv[],
    size_t niv);

UV_EXTERN int nghttp2_stream_read_start(
    std::shared_ptr<nghttp2_stream_t> handle,
    nghttp2_stream_alloc_cb alloc_cb,
    nghttp2_stream_read_cb read_cb);

UV_EXTERN int nghttp2_stream_read_stop(
    nghttp2_session_t* handle);

UV_EXTERN int nghttp2_stream_write(
    nghttp2_stream_write_t* req,
    std::shared_ptr<nghttp2_stream_t> handle,
    const uv_buf_t bufs[],
    unsigned int nbufs,
    nghttp2_stream_write_cb cb);

UV_EXTERN int nghttp2_submit_response(
    std::shared_ptr<nghttp2_stream_t> handle,
    const nghttp2_nv* nva,
    size_t nvlen,
    bool emptyPayload = false);

UV_EXTERN int32_t nghttp2_submit_request(
    nghttp2_session_t* handle,
    nghttp2_priority_spec* prispec,
    const nghttp2_nv* nva,
    size_t nvlen,
    std::shared_ptr<nghttp2_stream_t>* assigned,
    bool writable = true);

UV_EXTERN int nghttp2_submit_info(
    std::shared_ptr<nghttp2_stream_t> handle,
    const nghttp2_nv* nva,
    size_t nvlen);

UV_EXTERN int nghttp2_submit_priority(
    std::shared_ptr<nghttp2_stream_t> handle,
    nghttp2_priority_spec* prispec);

UV_EXTERN int nghttp2_submit_rst_stream(
    std::shared_ptr<nghttp2_stream_t> handle,
    const uint32_t code);

UV_EXTERN int nghttp2_submit_push_promise(
    std::shared_ptr<nghttp2_stream_t> handle,
    const nghttp2_nv* nv,
    size_t nvlen,
    std::shared_ptr<nghttp2_stream_t>* assigned,
    bool writable = true);

UV_EXTERN int nghttp2_stream_shutdown(
    std::shared_ptr<nghttp2_stream_t> handle);

UV_EXTERN int nghttp2_stream_writable(
    std::shared_ptr<nghttp2_stream_t> handle);

UV_EXTERN void nghttp2_stream_read_start(
    std::shared_ptr<nghttp2_stream_t> handle);

UV_EXTERN void nghttp2_stream_read_stop(
    std::shared_ptr<nghttp2_stream_t> handle);

UV_EXTERN bool nghttp2_stream_is_reading(
    std::shared_ptr<nghttp2_stream_t> handle);

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_CORE_H_
