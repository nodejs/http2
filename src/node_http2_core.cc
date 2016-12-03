
#include "node_http2_core.h"
#include "util.h"
#include "util-inl.h"

#include "uv.h"
#include "nghttp2/nghttp2.h"
#include <string.h>

typedef enum {
  NGHTTP2_STREAM_FLAG_NONE,
  // Writable side has ended
  NGHTTP2_FLAG_SHUT,
  // Readable side has ended
  NGHTTP2_FLAG_ENDED
} nghttp2_stream_flags;

#define container_of(ptr, type, member)                                      \
  ((type*) ((char*) (ptr) - offsetof(type, member)))

bool nghttp2_session_has_stream(nghttp2_session_t* handle, int32_t id) {
  assert(handle);
  auto s = handle->streams.find(id);
  return s != handle->streams.end();
}

bool nghttp2_session_find_stream(
    nghttp2_session_t* handle,
    int32_t id,
    std::shared_ptr<nghttp2_stream_t>* stream_handle) {
  assert(handle);
  auto s = handle->streams.find(id);
  if (s != handle->streams.end()) {
    *stream_handle = s->second;
    return true;
  } else {
    return false;
  }
}

void nghttp2_set_callback_stream_get_trailers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_stream_get_trailers_cb cb) {
  assert(callbacks);
  callbacks->on_get_trailers = cb;
}

void nghttp2_set_callback_send(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_send_cb cb) {
  assert(callbacks);
  callbacks->send = cb;
}

void nghttp2_set_callback_on_headers(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_headers_cb cb) {
  assert(callbacks);
  callbacks->on_headers = cb;
};

void nghttp2_set_callback_on_stream_close(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_stream_close_cb cb) {
  assert(callbacks);
  callbacks->on_stream_close = cb;
};

void nghttp2_set_callback_on_data_chunks(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_data_chunks_cb cb) {
  assert(callbacks);
  callbacks->on_data_chunks = cb;
}

void nghttp2_set_callback_stream_init(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_init_cb cb) {
  assert(callbacks);
  callbacks->stream_init = cb;
}

void nghttp2_set_callback_stream_free(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_on_stream_free_cb cb) {
  assert(callbacks);
  callbacks->stream_free = cb;
}

void nghttp2_set_callback_on_settings(
    node_nghttp2_session_callbacks* callbacks,
    nghttp2_session_on_settings_cb cb) {
  assert(callbacks);
  callbacks->on_settings = cb;
}

void nghttp2_queue_pending_callback(nghttp2_session_t* handle,
                                    nghttp2_pending_cb_list* item) {
  assert(handle);
  if (handle->pending_callbacks_tail == nullptr) {
    handle->pending_callbacks_head = item;
    handle->pending_callbacks_tail = item;
  } else {
    handle->pending_callbacks_tail->next = item;
    handle->pending_callbacks_tail = item;
  }
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
      if (head->bufs[n].len <= remaining) {
        memcpy(buf + offset, head->bufs[n].base, head->bufs[n].len);
        offset += head->bufs[n].len;
        remaining -= head->bufs[n].len;
        stream_handle->queue_head_index++;
      } else {
        goto end;
      }
    }
    stream_handle->queue_head_index = 0;
    stream_handle->queue_head = head->next;
    head->cb(head->req, 0);
    delete head;
  }

 end:
  int writable = stream_handle->queue_head != nullptr ||
                 nghttp2_stream_writable(stream_handle);
  if (offset == 0 && writable) {
    return NGHTTP2_ERR_DEFERRED;
  }
  if (!writable) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;

    if (handle->callbacks.on_get_trailers != nullptr) {
      std::vector<nghttp2_nv> trailers;
      handle->callbacks.on_get_trailers(handle, stream_handle, &trailers);
      if (trailers.size() > 0) {
        *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
        nghttp2_submit_trailer(handle->session,
                               stream_handle->id,
                               &trailers[0],
                               trailers.size());
      }
    }
  }
  assert(offset <= length);
  return offset;
}

void nghttp2_free_headers_list(nghttp2_pending_headers_cb* cb) {
  while (cb->headers != nullptr) {
    nghttp2_header_list* item = cb->headers;
    nghttp2_rcbuf_decref(item->name);
    nghttp2_rcbuf_decref(item->value);
    cb->headers = item->next;
    delete item;
  }
}

void nghttp2_session_drain_headers_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_headers_cb* cb) {
  assert(handle);
  assert(cb);
  if (handle->callbacks.on_headers != nullptr) {
    handle->callbacks.on_headers(handle,
                                 cb->handle,
                                 cb->headers,
                                 cb->category,
                                 cb->flags);
  }
  nghttp2_free_headers_list(cb);
}

void nghttp2_session_drain_stream_close_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_stream_close_cb* cb) {
  assert(handle);
  assert(cb);
  if (handle->callbacks.on_stream_close != nullptr) {
    handle->callbacks.on_stream_close(handle,
                                      cb->handle->id,
                                      cb->error_code);
  }
  handle->streams.erase(cb->handle->id);
}

void nghttp2_session_drain_send_cb(
    nghttp2_session_t* handle,
    nghttp2_pending_session_send_cb* cb) {
  assert(handle);
  assert(cb);
  if (handle->callbacks.send != nullptr) {
    handle->callbacks.send(handle, *cb->bufs, cb->nbufs, cb->total);
  }
  for (unsigned int n = 0; n < cb->nbufs; n++) {
    delete[] (cb->bufs[n]).base;
  }
}

void DeleteDataChunks(nghttp2_data_chunks_t* chunks) {
  for (unsigned int n = 0; n < chunks->nbufs; n++) {
    delete[] chunks->buf[n].base;
  }
  delete chunks;
}

void nghttp2_session_drain_data_chunks(
    nghttp2_session_t* handle,
    nghttp2_pending_data_chunks_cb* cb) {
  assert(handle);
  assert(cb);
  std::shared_ptr<nghttp2_data_chunks_t> chunks;
  unsigned int n = 0;
  size_t amount = 0;
  if (handle->callbacks.on_data_chunks != nullptr) {
    while (cb->head != nullptr) {
      if (chunks == nullptr) {
        chunks = std::shared_ptr<nghttp2_data_chunks_t>(
            new nghttp2_data_chunks_t, DeleteDataChunks);
        chunks->buf.AllocateSufficientStorage(kSimultaneousBufferCount);
      }
      nghttp2_data_chunk_t* item = cb->head;
      chunks->buf[n++] = uv_buf_init(item->buf.base, item->buf.len);
      amount += item->buf.len;
      cb->head = item->next;
      delete item;
      if (n == kSimultaneousBufferCount || cb->head == nullptr) {
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
}

void nghttp2_session_drain_settings(
    nghttp2_session_t* handle,
    nghttp2_pending_settings_cb* cb) {
  assert(handle);
  assert(cb);
  if (handle->callbacks.on_settings != nullptr) {
    handle->callbacks.on_settings(handle);
  }
}

void nghttp2_session_drain_callbacks(nghttp2_session_t* handle) {
  assert(handle);
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
    }
    handle->ready_callbacks_head = item->next;
    delete item;
  }
  handle->ready_callbacks_tail = nullptr;
  assert(handle->ready_callbacks_tail == nullptr);
  assert(handle->ready_callbacks_head == nullptr);
}

void nghttp2_session_drain_send(nghttp2_session_t* handle) {
  const uint8_t* data;
  size_t total = 0;
  unsigned int idx = 0;
  nghttp2_pending_session_send_cb* cb = nullptr;
  size_t amount = nghttp2_session_mem_send(handle->session, &data);
  while (amount > 0) {
    if (cb == nullptr) {
      cb = new nghttp2_pending_session_send_cb;
      cb->bufs.AllocateSufficientStorage(kSimultaneousBufferCount);
    }
    cb->bufs[idx] = uv_buf_init(new char[amount], amount);
    memcpy(cb->bufs[idx++].base, data, amount);
    total += amount;
    if (idx == kSimultaneousBufferCount)
      break;
    amount = nghttp2_session_mem_send(handle->session, &data);
  }
  if (cb != nullptr) {
    cb->nbufs = idx;
    cb->total = total;
    nghttp2_pending_cb_list* item = new nghttp2_pending_cb_list;
    item->type = NGHTTP2_CB_SESSION_SEND;
    item->cb = cb;
    if (handle->ready_callbacks_tail == nullptr) {
      handle->ready_callbacks_head = item;
      handle->ready_callbacks_tail = item;
    } else {
      handle->ready_callbacks_tail->next = item;
      handle->ready_callbacks_tail = item;
    }
  }
}

void nghttp2_session_send_and_make_ready(nghttp2_session_t* handle) {
  assert(handle);

  while (nghttp2_session_want_write(handle->session)) {
    nghttp2_session_drain_send(handle);
  }

  if (handle->ready_callbacks_tail == nullptr) {
    handle->ready_callbacks_tail = handle->pending_callbacks_head;
    handle->ready_callbacks_head = handle->pending_callbacks_head;
  } else {
    handle->ready_callbacks_tail->next = handle->pending_callbacks_head;
    handle->ready_callbacks_tail = handle->pending_callbacks_head;
  }
  handle->pending_callbacks_head = nullptr;
  handle->pending_callbacks_tail = nullptr;
}

// Run on every loop of the event loop per session
void OnSessionIdle(uv_idle_t* t) {
  nghttp2_session_t* handle =
    container_of(t, nghttp2_session_t, idler);
  nghttp2_session_send_and_make_ready(handle);
  nghttp2_session_drain_callbacks(handle);
}

int OnBeginHeadersCallback(nghttp2_session* session,
                           const nghttp2_frame* frame,
                           void* user_data) {
  nghttp2_session_t* handle = static_cast<nghttp2_session_t*>(user_data);
  if (!nghttp2_session_has_stream(handle, frame->hd.stream_id))
    nghttp2_stream_init(handle, frame->hd.stream_id, frame->headers.cat);
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

  nghttp2_header_list* header = new nghttp2_header_list;
  header->name = name;
  header->value = value;
  nghttp2_rcbuf_incref(name);
  nghttp2_rcbuf_incref(value);
  if (stream_handle->current_headers_tail == nullptr) {
    stream_handle->current_headers_head = header;
    stream_handle->current_headers_tail = header;
  } else {
    stream_handle->current_headers_tail->next = header;
    stream_handle->current_headers_tail = header;
  }
  return 0;
}

void nghttp2_queue_pending_data_chunks(
    nghttp2_session_t* session,
    std::shared_ptr<nghttp2_stream_t> handle,
    uint8_t flags = NGHTTP2_FLAG_NONE) {
  if (handle->current_data_chunks_cb != nullptr) {
    handle->current_data_chunks_cb->flags = flags;
    nghttp2_pending_cb_list* pending_cb = new nghttp2_pending_cb_list;
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
      cb = new nghttp2_pending_headers_cb;
      cb->handle = stream_handle;
      cb->category = stream_handle->current_headers_category;
      cb->headers = stream_handle->current_headers_head;
      cb->flags = frame->hd.flags;
      stream_handle->current_headers_head = nullptr;
      stream_handle->current_headers_tail = nullptr;
      pending_cb = new nghttp2_pending_cb_list;
      pending_cb->type = NGHTTP2_CB_HEADERS;
      pending_cb->cb = cb;
      nghttp2_queue_pending_callback(handle, pending_cb);
      break;
    case NGHTTP2_SETTINGS:
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
        pending_cb = new nghttp2_pending_cb_list;
        pending_cb->type = NGHTTP2_CB_SETTINGS;
        pending_cb->cb = new nghttp2_pending_settings_cb;
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
  nghttp2_pending_cb_list* pending_cb = new nghttp2_pending_cb_list;
  pending_cb->type = NGHTTP2_CB_STREAM_CLOSE;
  nghttp2_pending_stream_close_cb* cb = new nghttp2_pending_stream_close_cb;
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
      assert(nghttp2_session_find_stream(handle, hd->stream_id, &stream_handle));
      if (stream_handle->current_data_chunks_cb == nullptr) {
        chunks_cb = new nghttp2_pending_data_chunks_cb;
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
    chunks_cb = new nghttp2_pending_data_chunks_cb;
    chunks_cb->handle = stream_handle;
    stream_handle->current_data_chunks_cb = chunks_cb;
  }
  nghttp2_data_chunk_t* chunk = new nghttp2_data_chunk_t;
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

// Initialize the nghttp2_session_t handle by creating and
// assigning the nghttp2_session instance and associated
// uv_loop_t.
int nghttp2_session_init(uv_loop_t* loop,
                         nghttp2_session_t* handle,
                         const node_nghttp2_session_callbacks* cb,
                         const nghttp2_session_type type,
                         nghttp2_option* options,
                         nghttp2_mem* mem) {
  handle->loop = loop;
  handle->type = NGHTTP2_SESSION;
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

  nghttp2_option* opts;
  if (options != nullptr) {
    opts = options;
  } else {
    nghttp2_option_new(&opts);
  }
  nghttp2_option_set_no_auto_window_update(opts, 1);

  switch(type) {
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

  uv_idle_init(loop, &handle->idler);
  uv_idle_start(&handle->idler, OnSessionIdle);
  return ret;
}

void StreamDeleter(nghttp2_stream_t* handle) {
  nghttp2_session_t* session = handle->session;
  assert(session);
  if (session->callbacks.stream_free != nullptr)
    session->callbacks.stream_free(session, handle);
  if (handle->current_data_chunks_cb != nullptr) {
    // Hmm.. technically this could be a problem because there's
    // data that has not yet been flushed... not sure what to
    // do about it yet tho. Clean up!
    nghttp2_pending_data_chunks_cb* chunks =
      handle->current_data_chunks_cb;
    while (chunks->head != nullptr) {
      nghttp2_data_chunk_t* chunk = chunks->head;
      chunks->head = chunk->next;
      delete[] chunk->buf.base;
      delete chunk;
    }
    delete chunks;
  }
  delete handle;
}

std::shared_ptr<nghttp2_stream_t> nghttp2_stream_init(
    nghttp2_session_t* handle,
    int32_t id,
    nghttp2_headers_category category = NGHTTP2_HCAT_HEADERS) {
  std::shared_ptr<nghttp2_stream_t> stream_handle =
    std::shared_ptr<nghttp2_stream_t>(new nghttp2_stream_t, StreamDeleter);
  stream_handle->loop = handle->loop;
  stream_handle->type = NGHTTP2_STREAM;
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
int nghttp2_session_is_alive(nghttp2_session_t* handle) {
  if (nghttp2_session_want_read(handle->session) ||
      nghttp2_session_want_write(handle->session)) {
    return 1;
  }
  return 0;
}

int nghttp2_session_free(nghttp2_session_t* handle, bool forced) {
  if (handle == nullptr)
    return 1;

  if (!forced && nghttp2_session_is_alive(handle))
    return 0;

  nghttp2_session_terminate_session(handle->session, NGHTTP2_NO_ERROR);

  if (uv_is_active(reinterpret_cast<uv_handle_t*>(&handle->idler))) {
    uv_idle_stop(&handle->idler);
  }

  nghttp2_session_del(handle->session);
  handle->session = nullptr;
  handle->loop = nullptr;

  return 1;
}

// Write data received from the socket to the underlying nghttp2_session.
ssize_t nghttp2_session_write(nghttp2_session_t* handle,
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
int nghttp2_submit_settings(nghttp2_session_t* handle,
                            const nghttp2_settings_entry iv[],
                            size_t niv) {
  return nghttp2_submit_settings(handle->session,
                                 NGHTTP2_FLAG_NONE, iv, niv);

}

// Submit additional headers for a stream. Typically used to
// submit informational (1xx) headers
int nghttp2_submit_info(std::shared_ptr<nghttp2_stream_t> handle,
                        const nghttp2_nv* nva,
                        size_t nvlen) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  return nghttp2_submit_headers(session->session,
                                NGHTTP2_FLAG_NONE,
                                h->id, nullptr,
                                nva, nvlen, nullptr);
}


// Submit a priority change for the stream
int nghttp2_submit_priority(std::shared_ptr<nghttp2_stream_t> handle,
                            nghttp2_priority_spec* prispec) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  return nghttp2_submit_priority(session->session,
                                 NGHTTP2_FLAG_NONE,
                                 h->id, prispec);
}

// Submit an RST_STREAM frame
int nghttp2_submit_rst_stream(std::shared_ptr<nghttp2_stream_t> handle,
                              const uint32_t code) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  return nghttp2_submit_rst_stream(session->session,
                                   NGHTTP2_FLAG_NONE,
                                   h->id,
                                   code);
}

// Submit a push promise
int32_t nghttp2_submit_push_promise(std::shared_ptr<nghttp2_stream_t> handle,
                                    const nghttp2_nv* nva,
                                    size_t nvlen,
                                    std::shared_ptr<nghttp2_stream_t>* assigned,
                                    bool writable) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;

  int32_t ret = nghttp2_submit_push_promise(session->session,
                                            NGHTTP2_FLAG_NONE,
                                            h->id, nva, nvlen, nullptr);
  if (ret > 0) {
    *assigned = nghttp2_stream_init(session, ret);
    if (!writable) nghttp2_stream_shutdown(*assigned);
  }
  return ret;
}

// Initiate a response. If the nghttp2_stream is still writable by
// the time this is called, then an nghttp2_data_provider will be
// initialized, causing at least one (possibly empty) data frame to
// be sent.
int nghttp2_submit_response(std::shared_ptr<nghttp2_stream_t> handle,
                            const nghttp2_nv* nva,
                            size_t nvlen,
                            bool emptyPayload) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;

  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = &handle;
  prov.read_callback = OnStreamRead;
  if (!emptyPayload && nghttp2_stream_writable(h))
    provider = &prov;
  return nghttp2_submit_response(session->session,
                                 handle->id,
                                 nva,
                                 nvlen,
                                 provider);
}


// Initiate a request. If writable is true (the default), then
// an nghttp2_data_provider will be initialized, causing at
// least one (possibly empty) data frame to to be sent.
int32_t nghttp2_submit_request(nghttp2_session_t* handle,
                               nghttp2_priority_spec* prispec,
                               const nghttp2_nv* nva,
                               size_t nvlen,
                               std::shared_ptr<nghttp2_stream_t>* assigned,
                               bool writable) {
  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = &handle;
  prov.read_callback = OnStreamRead;
  if (writable)
    provider = &prov;
  int32_t ret = nghttp2_submit_request(handle->session,
                                       prispec, nva, nvlen,
                                       provider, nullptr);
  // Assign the nghttp2_stream_t handle
  if (ret > 0) {
    *assigned = nghttp2_stream_init(handle, ret);
    if (!writable) nghttp2_stream_shutdown(*assigned);
  }
  return ret;
}

// Mark the writable side of the nghttp2_stream as being shutdown.
int nghttp2_stream_shutdown(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  nghttp2_session_t* session = h->session;
  h->flags |= NGHTTP2_FLAG_SHUT;
  nghttp2_session_resume_data(session->session, h->id);
  return 0;
}

int nghttp2_stream_writable(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  return (h->flags & NGHTTP2_FLAG_SHUT) == 0;
}

int nghttp2_stream_readable(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  return (h->flags & NGHTTP2_FLAG_ENDED) == 0;
}

// Queue the given set of uv_but_t handles for writing to an
// nghttp2_stream. The callback will be invoked once the chunks
// of data have been flushed to the underlying nghttp2_session.
// Note that this does *not* mean that the data has been flushed
// to the socket yet.
int nghttp2_stream_write(nghttp2_stream_write_t* req,
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
  req->handle = h;
  req->item = item;
  item->bufs.AllocateSufficientStorage(nbufs);
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

void nghttp2_stream_read_start(std::shared_ptr<nghttp2_stream_t> handle) {
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

void nghttp2_stream_read_stop(std::shared_ptr<nghttp2_stream_t> handle) {
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

bool nghttp2_stream_is_reading(std::shared_ptr<nghttp2_stream_t> handle) {
  return handle->reading > 0;
}
