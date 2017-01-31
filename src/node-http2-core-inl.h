#ifndef SRC_NODE_HTTP2_CORE_INL_H_
#define SRC_NODE_HTTP2_CORE_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node-http2-core.h"
#include "util.h"
#include "util-inl.h"
#include "freelist.h"

#include "uv.h"
#include "nghttp2/nghttp2.h"
#include <string>

namespace node {
namespace http2 {

#define LINKED_LIST_ADD(list, item)                                           \
  do {                                                                        \
    if (list ## _tail == nullptr) {                                           \
      list ## _head = item;                                                   \
      list ## _tail = item;                                                   \
    } else {                                                                  \
      list ## _tail->next = item;                                             \
      list ## _tail = item;                                                   \
    }                                                                         \
  } while (0);

struct PendingDataChunksFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* cb) {
    cb->handle.reset();
    cb->head = nullptr;
    cb->tail = nullptr;
    cb->nbufs = 0;
    cb->flags = NGHTTP2_FLAG_NONE;
  }
};

struct DataChunkFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* chunk) {
    chunk->next = nullptr;
  }
};

#define FREELIST_MAX 1024

static Freelist<nghttp2_pending_data_chunks_cb, FREELIST_MAX,
                PendingDataChunksFreelistTraits> pending_data_chunks_free_list;

static Freelist<nghttp2_data_chunk_t, FREELIST_MAX,
                DataChunkFreelistTraits> data_chunk_free_list;

struct StreamHandleFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* handle) {
    if (handle->current_data_chunks_cb != nullptr) {
      nghttp2_pending_data_chunks_cb* chunks =
        handle->current_data_chunks_cb;
      while (chunks->head != nullptr) {
        nghttp2_data_chunk_t* chunk = chunks->head;
        chunks->head = chunk->next;
        delete[] chunk->buf.base;
        data_chunk_free_list.push(chunk);
      }
      pending_data_chunks_free_list.push(chunks);
    }
    handle->session = nullptr;
    handle->id = 0;
    handle->flags = NGHTTP2_STREAM_FLAG_NONE;
    handle->queue_head = nullptr;
    handle->queue_tail = nullptr;
    handle->queue_head_index = 0;
    handle->queue_head_offset = 0;
    handle->current_headers_head = nullptr;
    handle->current_headers_tail = nullptr;
    handle->current_headers_category = NGHTTP2_HCAT_HEADERS;
    handle->current_data_chunks_cb = nullptr;
    handle->reading = -1;
    handle->prev_local_window_size = 65535;
  }
};

struct CbListFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* item) {
    item->type = NGHTTP2_CB_NONE;
    item->cb = nullptr;
    item->next = nullptr;
  }
};

struct HeaderListFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* item) {
    item->name = nullptr;
    item->value = nullptr;
    item->next = nullptr;
  }
};

struct PendingStreamCloseFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* cb) {
    cb->handle.reset();
    cb->error_code = NGHTTP2_NO_ERROR;
  }
};

struct PendingHeadersFreelistTraits : public DefaultFreelistTraits {
  template<typename T>
  static void Reset(T* cb) {
    cb->handle.reset();
    cb->category = NGHTTP2_HCAT_REQUEST;
    cb->headers = nullptr;
    cb->flags = NGHTTP2_FLAG_NONE;
  }
};

struct DataChunksFreelistTraits : public DefaultFreelistTraits {
  template <typename T>
  static T* Alloc() {
    nghttp2_data_chunks_t* chunks = Calloc<nghttp2_data_chunks_t>(1);
    chunks->buf.AllocateSufficientStorage(MAX_BUFFER_COUNT);
    return chunks;
  }

  template<typename T>
  static void Reset(T* chunks) {
    chunks->nbufs = 0;
  }
};

struct PendingSessionFreelistTraits : public DefaultFreelistTraits {
  template <typename T>
  static T* Alloc() {
    auto cb = Calloc<nghttp2_pending_session_send_cb>(1);
    return cb;
  }

  template<typename T>
  static void Reset(T* cb) {
    cb->length = 0;
    cb->buf = nullptr;
  }
};

static node::Freelist<nghttp2_stream_t, FREELIST_MAX,
                      StreamHandleFreelistTraits> stream_free_list;

static node::Freelist<nghttp2_pending_cb_list, FREELIST_MAX,
                      CbListFreelistTraits> cb_free_list;

static node::Freelist<nghttp2_header_list, FREELIST_MAX,
                      HeaderListFreelistTraits> header_free_list;

static node::Freelist<nghttp2_pending_settings_cb, FREELIST_MAX,
                      DefaultFreelistTraits>
                        pending_settings_free_list;

static node::Freelist<nghttp2_pending_stream_close_cb, FREELIST_MAX,
                      PendingStreamCloseFreelistTraits>
                        pending_stream_close_free_list;

static node::Freelist<nghttp2_pending_headers_cb, FREELIST_MAX,
                      PendingHeadersFreelistTraits>
                        pending_headers_free_list;

static node::Freelist<nghttp2_data_chunks_t, FREELIST_MAX,
                      DataChunksFreelistTraits> data_chunks_free_list;

static node::Freelist<nghttp2_pending_session_send_cb, FREELIST_MAX,
                      PendingSessionFreelistTraits>
                        pending_session_send_free_list;

inline bool nghttp2_session_has_stream(nghttp2_session_t* handle, int32_t id) {
  assert(handle != nullptr);
  auto s = handle->streams.find(id);
  return s != handle->streams.end();
}

inline bool nghttp2_session_find_stream(
    nghttp2_session_t* handle,
    int32_t id,
    std::shared_ptr<nghttp2_stream_t>* stream_handle) {
  assert(handle != nullptr);
  auto s = handle->streams.find(id);
  if (s != handle->streams.end()) {
    *stream_handle = s->second;
    return true;
  } else {
    return false;
  }
}

inline void nghttp2_set_callbacks_allocate_send_buf(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_allocate_send_buf_cb cb) {
  assert(callbacks != nullptr);
  callbacks->allocate_send_buf = cb;
}

inline void nghttp2_set_callbacks_free_session(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_free_session_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_free_session = cb;
}

inline void nghttp2_set_callback_stream_get_trailers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_stream_get_trailers_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_get_trailers = cb;
}

inline void nghttp2_set_callback_get_padding(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_get_padding_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_get_padding = cb;
}

inline void nghttp2_set_callback_send(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_send_cb cb) {
  assert(callbacks != nullptr);
  callbacks->send = cb;
}

inline void nghttp2_set_callback_on_headers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_headers_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_headers = cb;
}

inline void nghttp2_set_callback_on_stream_close(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_stream_close_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_stream_close = cb;
}

inline void nghttp2_set_callback_on_data_chunks(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_data_chunks_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_data_chunks = cb;
}

inline void nghttp2_set_callback_stream_init(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_init_cb cb) {
  assert(callbacks != nullptr);
  callbacks->stream_init = cb;
}

inline void nghttp2_set_callback_stream_free(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_free_cb cb) {
  assert(callbacks != nullptr);
  callbacks->stream_free = cb;
}

inline void nghttp2_set_callback_on_settings(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_settings_cb cb) {
  assert(callbacks != nullptr);
  callbacks->on_settings = cb;
}

inline void nghttp2_queue_pending_callback(nghttp2_session_t* handle,
                                           nghttp2_pending_cb_list* item) {
  assert(handle != nullptr);
  LINKED_LIST_ADD(handle->pending_callbacks, item);
}

ssize_t OnStreamRead(nghttp2_session* session,
                     int32_t stream_id,
                     uint8_t* buf,
                     size_t length,
                     uint32_t* flags,
                     nghttp2_data_source* source,
                     void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  assert(nghttp2_session_find_stream(handle, stream_id, &stream_handle));

  size_t remaining = length;
  size_t offset = 0;

  while (stream_handle->queue_head != nullptr) {
    nghttp2_stream_write_queue* head = stream_handle->queue_head;
    for (unsigned int n = stream_handle->queue_head_index;
         n < head->nbufs; n++) {
      if (head->bufs[n].len > 0) {
        size_t len = head->bufs[n].len - stream_handle->queue_head_offset;
        len = len < remaining ? len : remaining;
        memcpy(buf + offset,
               head->bufs[n].base + stream_handle->queue_head_offset,
               len);
        offset += len;
        remaining -= len;
        if (len < head->bufs[n].len) {
          stream_handle->queue_head_offset += len;
        } else {
          stream_handle->queue_head_index++;
          stream_handle->queue_head_offset = 0;
        }
      } else {
        goto end;
      }
    }
    stream_handle->queue_head_offset = 0;
    stream_handle->queue_head_index = 0;
    stream_handle->queue_head = head->next;
    head->cb(head->req, 0);
    delete head;
  }

 end:
  int writable = stream_handle->queue_head != nullptr ||
                 nghttp2_stream_writable(stream_handle);
  if (offset == 0 && writable && stream_handle->queue_head == nullptr) {
    return NGHTTP2_ERR_DEFERRED;
  }
  if (!writable) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;

    if (handle->callbacks.on_get_trailers != nullptr) {
      MaybeStackBuffer<nghttp2_nv> trailers;
      handle->callbacks.on_get_trailers(handle, stream_handle, &trailers);
      if (trailers.length() > 0) {
        *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        nghttp2_submit_trailer(handle->session,
                               stream_handle->id,
                               *trailers,
                               trailers.length());
      }
      for (size_t n = 0; n < trailers.length(); n++) {
        free(trailers[n].name);
        free(trailers[n].value);
      }
    }
  }
  assert(offset <= length);
  return offset;
}

inline void nghttp2_free_headers_list(nghttp2_pending_headers_cb* cb) {
  while (cb->headers != nullptr) {
    nghttp2_header_list* item = cb->headers;
    nghttp2_rcbuf_decref(item->value);
    cb->headers = item->next;
    header_free_list.push(item);
  }
}

inline void nghttp2_session_drain_headers_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_headers_cb* cb) {
  assert(handle != nullptr);
  assert(cb != nullptr);
  if (handle->callbacks.on_headers != nullptr) {
    handle->callbacks.on_headers(handle,
                                 cb->handle,
                                 cb->headers,
                                 cb->category,
                                 cb->flags);
  }
  nghttp2_free_headers_list(cb);
  pending_headers_free_list.push(cb);
}

inline void nghttp2_session_drain_stream_close_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_stream_close_cb* cb) {
  assert(handle != nullptr);
  assert(cb != nullptr);
  if (handle->callbacks.on_stream_close != nullptr) {
    handle->callbacks.on_stream_close(handle,
                                      cb->handle->id,
                                      cb->error_code);
  }
  handle->streams.erase(cb->handle->id);
  pending_stream_close_free_list.push(cb);
}

inline void nghttp2_session_drain_send_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_session_send_cb* cb) {
  assert(handle != nullptr);
  assert(cb != nullptr);
  if (handle->callbacks.send != nullptr) {
    handle->callbacks.send(handle, cb->buf, cb->length);
  }
  pending_session_send_free_list.push(cb);
}

void DeleteDataChunks(nghttp2_data_chunks_t* chunks) {
  for (unsigned int n = 0; n < chunks->nbufs; n++) {
    delete[] chunks->buf[n].base;
  }
  data_chunks_free_list.push(chunks);
}

inline void nghttp2_session_drain_data_chunks(
    nghttp2_session_t* handle,
    nghttp2_pending_data_chunks_cb* cb) {
  assert(handle != nullptr);
  assert(cb != nullptr);
  std::shared_ptr<nghttp2_data_chunks_t> chunks;
  unsigned int n = 0;
  size_t amount = 0;
  if (handle->callbacks.on_data_chunks != nullptr) {
    while (cb->head != nullptr) {
      if (chunks == nullptr) {
        chunks = std::shared_ptr<nghttp2_data_chunks_t>(
            data_chunks_free_list.pop(), DeleteDataChunks);
      }
      nghttp2_data_chunk_t* item = cb->head;
      chunks->buf[n++] = uv_buf_init(item->buf.base, item->buf.len);
      amount += item->buf.len;
      cb->head = item->next;
      data_chunk_free_list.push(item);
      if (n == MAX_BUFFER_COUNT || cb->head == nullptr) {
        chunks->nbufs = n;
        handle->callbacks.on_data_chunks(handle, cb->handle, chunks);
        // Notify the nghttp2_session that a given chunk of data has been
        // consumed and we are ready to receive more data for this stream
        nghttp2_session_consume(handle->session, cb->handle->id, amount);
        n = 0;
        amount = 0;
      }
    }
  }
  pending_data_chunks_free_list.push(cb);
}

inline void nghttp2_session_drain_settings(
    nghttp2_session_t* handle,
    nghttp2_pending_settings_cb* cb) {
  assert(handle != nullptr);
  assert(cb != nullptr);
  if (handle->callbacks.on_settings != nullptr) {
    handle->callbacks.on_settings(handle);
  }
  pending_settings_free_list.push(cb);
}

inline void nghttp2_session_drain_callbacks(nghttp2_session_t* handle) {
  assert(handle != nullptr);
  while (handle->ready_callbacks_head != nullptr) {
    nghttp2_pending_cb_list* item = handle->ready_callbacks_head;
    switch (item->type) {
      case NGHTTP2_CB_SESSION_SEND:
        nghttp2_session_drain_send_cb(
            handle,
            static_cast<nghttp2_pending_session_send_cb*>(item->cb));
        break;
      case NGHTTP2_CB_HEADERS:
        nghttp2_session_drain_headers_cb(
            handle,
            static_cast<nghttp2_pending_headers_cb*>(item->cb));
        break;
      case NGHTTP2_CB_STREAM_CLOSE:
        nghttp2_session_drain_stream_close_cb(
            handle,
            static_cast<nghttp2_pending_stream_close_cb*>(item->cb));
        break;
      case NGHTTP2_CB_DATA_CHUNKS:
        nghttp2_session_drain_data_chunks(
            handle,
            static_cast<nghttp2_pending_data_chunks_cb*>(item->cb));
        break;
      case NGHTTP2_CB_SETTINGS:
        nghttp2_session_drain_settings(
            handle,
            static_cast<nghttp2_pending_settings_cb*>(item->cb));
      case NGHTTP2_CB_NONE:
        break;
    }
    handle->ready_callbacks_head = item->next;
    cb_free_list.push(item);
  }
  handle->ready_callbacks_tail = nullptr;
  assert(handle->ready_callbacks_tail == nullptr);
  assert(handle->ready_callbacks_head == nullptr);
}

inline void nghttp2_session_drain_send(nghttp2_session_t* handle) {
  const uint8_t* data;
  nghttp2_pending_session_send_cb* cb = nullptr;
  nghttp2_pending_cb_list* item;
  size_t amount = 0;
  size_t offset = 0;
  size_t src_offset = 0;
  uv_buf_t* current =
      handle->callbacks.allocate_send_buf(handle, SEND_BUFFER_RECOMMENDED_SIZE);
  assert(current);
  size_t remaining = current->len;
  while ((amount = nghttp2_session_mem_send(handle->session, &data)) > 0) {
    while (amount > 0) {
      if (amount > remaining) {
        // The amount copied does not fit within the remaining available
        // buffer, copy what we can tear it off and keep going.
        memcpy(current->base + offset, data + src_offset, remaining);
        offset += remaining;
        src_offset = remaining;
        amount -= remaining;
        cb = pending_session_send_free_list.pop();
        cb->buf = current;
        cb->length = offset;
        item = cb_free_list.pop();
        item->type = NGHTTP2_CB_SESSION_SEND;
        item->cb = cb;
        LINKED_LIST_ADD(handle->ready_callbacks, item);
        offset = 0;
        current =
            handle->callbacks.allocate_send_buf(handle,
                                                SEND_BUFFER_RECOMMENDED_SIZE);
        assert(current);
        remaining = current->len;
        continue;
      }
      memcpy(current->base + offset, data + src_offset, amount);
      offset += amount;
      remaining -= amount;
      amount = 0;
      src_offset = 0;
    }
  }
  cb = pending_session_send_free_list.pop();
  cb->buf = current;
  cb->length = offset;
  item = cb_free_list.pop();
  item->type = NGHTTP2_CB_SESSION_SEND;
  item->cb = cb;
  LINKED_LIST_ADD(handle->ready_callbacks, item);
}

inline void nghttp2_session_send_and_make_ready(nghttp2_session_t* handle) {
  assert(handle != nullptr);

  while (nghttp2_session_want_write(handle->session)) {
    nghttp2_session_drain_send(handle);
  }

  LINKED_LIST_ADD(handle->ready_callbacks,
                  handle->pending_callbacks_head);
  handle->pending_callbacks_head = nullptr;
  handle->pending_callbacks_tail = nullptr;
}

void OnSessionPrep(uv_prepare_t* t) {
  nghttp2_session_t* handle =
    container_of(t, nghttp2_session_t, prep);

  nghttp2_session_send_and_make_ready(handle);
  nghttp2_session_drain_callbacks(handle);
}

int OnBeginHeadersCallback(nghttp2_session* session,
                           const nghttp2_frame* frame,
                           void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  if (!nghttp2_session_has_stream(handle, frame->hd.stream_id)) {
    nghttp2_stream_init(handle, frame->hd.stream_id, frame->headers.cat);
  } else {
    std::shared_ptr<nghttp2_stream_t> stream_handle;
    nghttp2_session_find_stream(handle, frame->hd.stream_id, &stream_handle);
    stream_handle->current_headers_category = frame->headers.cat;
  }
  return 0;
}

int OnHeaderCallback(nghttp2_session* session,
                     const nghttp2_frame* frame,
                     nghttp2_rcbuf *name,
                     nghttp2_rcbuf *value,
                     uint8_t flags,
                     void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  assert(nghttp2_session_find_stream(
      handle, frame->hd.stream_id, &stream_handle));

  nghttp2_header_list* header = header_free_list.pop();
  header->name = name;
  header->value = value;
  nghttp2_rcbuf_incref(name);
  nghttp2_rcbuf_incref(value);
  LINKED_LIST_ADD(stream_handle->current_headers, header);
  return 0;
}

inline void nghttp2_queue_pending_data_chunks(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> handle,
    uint8_t flags = NGHTTP2_FLAG_NONE) {
  if (handle->current_data_chunks_cb != nullptr) {
    handle->current_data_chunks_cb->flags = flags;
    nghttp2_pending_cb_list* pending_cb = cb_free_list.pop();
    pending_cb->type = NGHTTP2_CB_DATA_CHUNKS;
    pending_cb->cb = handle->current_data_chunks_cb;
    handle->current_data_chunks_cb = nullptr;
    nghttp2_queue_pending_callback(session, pending_cb);
  }
}

int OnFrameReceive(nghttp2_session* session,
                   const nghttp2_frame* frame,
                   void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  nghttp2_pending_cb_list* pending_cb;
  nghttp2_pending_headers_cb* cb;
  switch (frame->hd.type) {
    case NGHTTP2_DATA:
      assert(nghttp2_session_find_stream(
          handle, frame->hd.stream_id, &stream_handle));
      if (nghttp2_stream_is_reading(stream_handle)) {
        // If the stream is in the reading state, push the currently
        // buffered data chunks into the callback queue for processing.
        nghttp2_queue_pending_data_chunks(handle,
                                          stream_handle,
                                          frame->hd.flags);
      }
      break;
    case NGHTTP2_HEADERS:
      assert(nghttp2_session_find_stream(
          handle, frame->hd.stream_id, &stream_handle));
      cb = pending_headers_free_list.pop();
      cb->handle = stream_handle;
      cb->category = stream_handle->current_headers_category;
      cb->headers = stream_handle->current_headers_head;
      cb->flags = frame->hd.flags;
      stream_handle->current_headers_head = nullptr;
      stream_handle->current_headers_tail = nullptr;
      pending_cb = cb_free_list.pop();
      pending_cb->type = NGHTTP2_CB_HEADERS;
      pending_cb->cb = cb;
      nghttp2_queue_pending_callback(handle, pending_cb);
      break;
    case NGHTTP2_SETTINGS:
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
        pending_cb = cb_free_list.pop();
        pending_cb->type = NGHTTP2_CB_SETTINGS;
        pending_cb->cb = pending_settings_free_list.pop();
        nghttp2_queue_pending_callback(handle, pending_cb);
      }
    default:
      break;
  }
  return 0;
}

int OnStreamClose(nghttp2_session *session,
                  int32_t stream_id,
                  uint32_t error_code,
                  void *user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  assert(nghttp2_session_find_stream(handle, stream_id, &stream_handle));
  nghttp2_pending_cb_list* pending_cb = cb_free_list.pop();
  pending_cb->type = NGHTTP2_CB_STREAM_CLOSE;
  nghttp2_pending_stream_close_cb* cb = pending_stream_close_free_list.pop();
  cb->handle = stream_handle;
  cb->error_code = error_code;
  pending_cb->cb = cb;
  nghttp2_queue_pending_callback(handle, pending_cb);
  return 0;
}

int OnBeginFrameReceived(nghttp2_session* session,
                         const nghttp2_frame_hd* hd,
                         void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  nghttp2_pending_data_chunks_cb* chunks_cb;
  switch (hd->type) {
    case NGHTTP2_DATA:
      assert(
          nghttp2_session_find_stream(handle, hd->stream_id, &stream_handle));
      if (stream_handle->current_data_chunks_cb == nullptr) {
        chunks_cb = pending_data_chunks_free_list.pop();
        chunks_cb->handle = stream_handle;
        stream_handle->current_data_chunks_cb = chunks_cb;
      }
      break;
    default:
      break;
  }
  return 0;
}

int OnDataChunkReceived(nghttp2_session *session,
                        uint8_t flags,
                        int32_t stream_id,
                        const uint8_t *data,
                        size_t len,
                        void *user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  assert(nghttp2_session_find_stream(handle, stream_id, &stream_handle));
  nghttp2_pending_data_chunks_cb* chunks_cb =
      stream_handle->current_data_chunks_cb;
  if (chunks_cb == nullptr) {
    chunks_cb = pending_data_chunks_free_list.pop();
    chunks_cb->handle = stream_handle;
    stream_handle->current_data_chunks_cb = chunks_cb;
  }
  nghttp2_data_chunk_t* chunk = data_chunk_free_list.pop();
  chunk->buf = uv_buf_init(new char[len], len);
  memcpy(chunk->buf.base, data, len);
  if (chunks_cb->tail == nullptr) {
    chunks_cb->head = chunk;
    chunks_cb->tail = chunk;
  } else {
    chunks_cb->tail->next = chunk;
    chunks_cb->tail = chunk;
  }
  return 0;
}

ssize_t OnSelectPadding(nghttp2_session* session,
                        const nghttp2_frame* frame,
                        size_t maxPayloadLen,
                        void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  assert(handle->get_padding != nullptr);
  return handle->get_padding(handle, frame->hd.length, maxPayloadLen);
}

// Initialize the nghttp2_session_t handle by creating and
// assigning the nghttp2_session instance and associated
// uv_loop_t.
inline int nghttp2_session_init(uv_loop_t* loop,
                                nghttp2_session_t* handle,
                                const node_nghttp2_session_callbacks* cb,
                                const nghttp2_session_type type,
                                nghttp2_option* options,
                                nghttp2_mem* mem) {
  handle->loop = loop;
  handle->session_type = type;
  int ret = 0;

  memcpy(&handle->callbacks, cb, sizeof(node_nghttp2_session_callbacks));

  nghttp2_session_callbacks* callbacks;
  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_begin_headers_callback(
    callbacks, OnBeginHeadersCallback);
  nghttp2_session_callbacks_set_on_header_callback2(
    callbacks, OnHeaderCallback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(
    callbacks, OnFrameReceive);
  nghttp2_session_callbacks_set_on_stream_close_callback(
    callbacks, OnStreamClose);
  nghttp2_session_callbacks_set_on_begin_frame_callback(
    callbacks, OnBeginFrameReceived);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
    callbacks, OnDataChunkReceived);

  if (cb->on_get_padding != nullptr) {
    nghttp2_session_callbacks_set_select_padding_callback(
      callbacks, OnSelectPadding);
    handle->get_padding = cb->on_get_padding;
  }

  nghttp2_option* opts;
  if (options != nullptr) {
    opts = options;
  } else {
    nghttp2_option_new(&opts);
  }
  nghttp2_option_set_no_auto_window_update(opts, 1);

  switch (type) {
    case NGHTTP2_SESSION_SERVER:
      ret = nghttp2_session_server_new3(&handle->session,
                                        callbacks,
                                        handle,
                                        opts,
                                        mem);
      break;
    case NGHTTP2_SESSION_CLIENT:
      ret = nghttp2_session_client_new3(&handle->session,
                                        callbacks,
                                        handle,
                                        opts,
                                        mem);
      break;
  }
  if (opts != options) {
    nghttp2_option_del(opts);
  }
  nghttp2_session_callbacks_del(callbacks);

  uv_prepare_init(loop, &(handle->prep));
  uv_prepare_start(&(handle->prep), OnSessionPrep);
  return ret;
}

void StreamDeleter(nghttp2_stream_t* handle) {
  nghttp2_session_t* session = handle->session;
  assert(session);
  if (session->callbacks.stream_free != nullptr)
    session->callbacks.stream_free(session, handle);
  stream_free_list.push(handle);
}

inline std::shared_ptr<nghttp2_stream_t> nghttp2_stream_init(
    nghttp2_session_t* handle,
    int32_t id,
    nghttp2_headers_category category = NGHTTP2_HCAT_HEADERS) {
  std::shared_ptr<nghttp2_stream_t> stream_handle =
      std::shared_ptr<nghttp2_stream_t>(stream_free_list.pop(), StreamDeleter);
  stream_handle->session = handle;
  stream_handle->id = id;
  stream_handle->current_headers_category = category;
  handle->streams[id] = stream_handle;
  if (handle->callbacks.stream_init != nullptr)
    handle->callbacks.stream_init(handle, stream_handle);
  return stream_handle;
}

// Returns non-zero if the session is alive, zero if it is not
// A session that is not alive is ok to be freed
inline int nghttp2_session_is_alive(nghttp2_session_t* handle) {
  if (nghttp2_session_want_read(handle->session) ||
      nghttp2_session_want_write(handle->session)) {
    return 1;
  }
  return 0;
}

inline int nghttp2_session_free(nghttp2_session_t* handle) {
  assert(handle != nullptr);
  assert(handle->session != nullptr);
  assert(handle->pending_callbacks_head == nullptr);
  assert(handle->pending_callbacks_tail == nullptr);
  assert(handle->ready_callbacks_head == nullptr);
  assert(handle->ready_callbacks_tail == nullptr);

  uv_prepare_stop(&(handle->prep));
  auto PrepClose = [](uv_handle_t* handle) {
    nghttp2_session_t* session = container_of(handle, nghttp2_session_t, prep);
    if (session->callbacks.on_free_session != nullptr) {
      session->callbacks.on_free_session(session);
    }
  };
  uv_close(reinterpret_cast<uv_handle_t*>(&(handle->prep)), PrepClose);

  nghttp2_session_terminate_session(handle->session, NGHTTP2_NO_ERROR);
  nghttp2_session_del(handle->session);
  handle->session = nullptr;
  handle->loop = nullptr;
  return 1;
}

// Write data received from the socket to the underlying nghttp2_session.
inline ssize_t nghttp2_session_write(nghttp2_session_t* handle,
                                     const uv_buf_t* bufs,
                                     unsigned int nbufs) {
  size_t total = 0;
  for (unsigned int n = 0; n < nbufs; n++) {
    ssize_t ret =
      nghttp2_session_mem_recv(handle->session,
                               reinterpret_cast<uint8_t*>(bufs[n].base),
                               bufs[n].len);
    if (ret < 0) {
      return ret;
    } else {
      total += ret;
    }
  }
  return total;
}

// Submits new settings to the underlying nghttp2_session.
inline int nghttp2_submit_settings(nghttp2_session_t* handle,
                                   const nghttp2_settings_entry iv[],
                                   size_t niv) {
  return nghttp2_submit_settings(handle->session,
                                 NGHTTP2_FLAG_NONE, iv, niv);
}

// Submit additional headers for a stream. Typically used to
// submit informational (1xx) headers
inline int nghttp2_submit_info(std::shared_ptr<nghttp2_stream_t> handle,
                               nghttp2_nv* nva, size_t len) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  return nghttp2_submit_headers(session->session,
                                NGHTTP2_FLAG_NONE,
                                h->id, nullptr,
                                nva, len, nullptr);
}

inline int nghttp2_submit_priority(std::shared_ptr<nghttp2_stream_t> handle,
                                   nghttp2_priority_spec* prispec,
                                   bool silent) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;

  return silent ?
      nghttp2_session_change_stream_priority(session->session,
                                             h->id, prispec) :
      nghttp2_submit_priority(session->session,
                              NGHTTP2_FLAG_NONE,
                              h->id, prispec);
}

// Submit an RST_STREAM frame
inline int nghttp2_submit_rst_stream(std::shared_ptr<nghttp2_stream_t> handle,
                                     const uint32_t code) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  return nghttp2_submit_rst_stream(session->session,
                                   NGHTTP2_FLAG_NONE,
                                   h->id,
                                   code);
}

// Submit a push promise
inline int32_t nghttp2_submit_push_promise(
    std::shared_ptr<nghttp2_stream_t> handle,
    nghttp2_nv* nva,
    size_t len,
    std::shared_ptr<nghttp2_stream_t>* assigned,
    bool emptyPayload) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;

  int32_t ret = nghttp2_submit_push_promise(session->session,
                                            NGHTTP2_FLAG_NONE,
                                            h->id, nva, len,
                                            nullptr);
  if (ret > 0) {
    *assigned = nghttp2_stream_init(session, ret);
    if (emptyPayload) nghttp2_stream_shutdown(*assigned);
  }
  return ret;
}

// Initiate a response. If the nghttp2_stream is still writable by
// the time this is called, then an nghttp2_data_provider will be
// initialized, causing at least one (possibly empty) data frame to
// be sent.
inline int nghttp2_submit_response(
    std::shared_ptr<nghttp2_stream_t> handle,
    nghttp2_nv* nva,
    size_t len,
    bool emptyPayload) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;

  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = &handle;
  prov.read_callback = OnStreamRead;
  if (!emptyPayload && nghttp2_stream_writable(h))
    provider = &prov;

  return nghttp2_submit_response(session->session, handle->id,
                                 nva, len, provider);
}


// Initiate a request. If writable is true (the default), then
// an nghttp2_data_provider will be initialized, causing at
// least one (possibly empty) data frame to to be sent.
inline int32_t nghttp2_submit_request(
    nghttp2_session_t* handle,
    nghttp2_priority_spec* prispec,
    nghttp2_nv* nva,
    size_t len,
    std::shared_ptr<nghttp2_stream_t>* assigned,
    bool emptyPayload) {
  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = &handle;
  prov.read_callback = OnStreamRead;
  if (!emptyPayload)
    provider = &prov;
  int32_t ret = nghttp2_submit_request(handle->session,
                                       prispec, nva, len,
                                       provider, nullptr);
  // Assign the nghttp2_stream_t handle
  if (ret > 0) {
    *assigned = nghttp2_stream_init(handle, ret);
    if (emptyPayload) nghttp2_stream_shutdown(*assigned);
  }
  return ret;
}

// Mark the writable side of the nghttp2_stream as being shutdown.
inline int nghttp2_stream_shutdown(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  h->flags |= NGHTTP2_STREAM_FLAG_SHUT;
  nghttp2_session_resume_data(session->session, h->id);
  return 0;
}

inline int nghttp2_stream_writable(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  return (h->flags & NGHTTP2_STREAM_FLAG_SHUT) == 0;
}

inline int nghttp2_stream_readable(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  return (h->flags & NGHTTP2_STREAM_FLAG_ENDED) == 0;
}

// Queue the given set of uv_but_t handles for writing to an
// nghttp2_stream. The callback will be invoked once the chunks
// of data have been flushed to the underlying nghttp2_session.
// Note that this does *not* mean that the data has been flushed
// to the socket yet.
inline int nghttp2_stream_write(nghttp2_stream_write_t* req,
                                std::shared_ptr<nghttp2_stream_t> handle,
                                const uv_buf_t bufs[],
                                unsigned int nbufs,
                                nghttp2_stream_write_cb cb) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  if (!nghttp2_stream_writable(h)) {
    if (cb != nullptr)
      cb(req, UV_EOF);
    return 0;
  }
  nghttp2_stream_write_queue* item = new nghttp2_stream_write_queue;
  item->cb = cb;
  item->req = req;
  item->nbufs = nbufs;
  item->bufs.AllocateSufficientStorage(nbufs);
  req->handle = h;
  req->item = item;
  memcpy(*(item->bufs), bufs, nbufs * sizeof(*bufs));

  if (h->queue_head == nullptr) {
    h->queue_head = item;
    h->queue_tail = item;
  } else {
    h->queue_tail->next = item;
    h->queue_tail = item;
  }
  nghttp2_session_resume_data(session->session, h->id);
  return 0;
}

inline void nghttp2_stream_read_start(
    std::shared_ptr<nghttp2_stream_t> handle) {
  nghttp2_session_t* session = handle->session;
  if (handle->reading == 0) {
    // If handle->reading is less than zero, read_start had never previously
    // been called. If handle->reading is zero, reading had started and read
    // stop had been previously called, meaning that the flow control window
    // has been explicitly set to zero. Reset the flow control window now to
    // restart the flow of data.
    nghttp2_session_set_local_window_size(session->session,
                                          NGHTTP2_FLAG_NONE,
                                          handle->id,
                                          handle->prev_local_window_size);
  }
  handle->reading = 1;
  nghttp2_queue_pending_data_chunks(session, handle);
}

inline void nghttp2_stream_read_stop(std::shared_ptr<nghttp2_stream_t> handle) {
  nghttp2_session_t* session = handle->session;
  handle->reading = 0;
  // When not reading, explicitly set the local window size to 0 so that
  // the peer does not keep sending data that has to be buffered
  int32_t ret =
    nghttp2_session_get_stream_local_window_size(session->session, handle->id);
  if (ret >= 0)
    handle->prev_local_window_size = ret;
  nghttp2_session_set_local_window_size(session->session,
                                        NGHTTP2_FLAG_NONE,
                                        handle->id, 0);
}

inline bool nghttp2_stream_is_reading(
    std::shared_ptr<nghttp2_stream_t> handle) {
  return handle->reading > 0;
}

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_CORE_INL_H_
