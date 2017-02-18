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
    if (list ## _tail_ == nullptr) {                                          \
      list ## _head_ = item;                                                  \
      list ## _tail_ = item;                                                  \
    } else {                                                                  \
      list ## _tail_->next = item;                                            \
      list ## _tail_ = item;                                                  \
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
    handle->queue_head_ = nullptr;
    handle->queue_tail_ = nullptr;
    handle->queue_head_index = 0;
    handle->queue_head_offset = 0;
    handle->current_headers_head_ = nullptr;
    handle->current_headers_tail_ = nullptr;
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

inline void Nghttp2Session::SubmitShutdownNotice() {
  nghttp2_submit_shutdown_notice(session);
}

inline bool Nghttp2Session::HasStream(int32_t id) {
  auto s = streams_.find(id);
  return s != streams_.end();
}

inline std::shared_ptr<nghttp2_stream_t> Nghttp2Session::FindStream(
    int32_t id) {
  auto s = streams_.find(id);
  if (s != streams_.end()) {
    return s->second;
  } else {
    return std::shared_ptr<nghttp2_stream_t>(nullptr);
  }
}

void Nghttp2Session::QueuePendingCallback(nghttp2_pending_cb_list* item) {
  LINKED_LIST_ADD(pending_callbacks, item);
}

ssize_t Nghttp2Session::OnStreamRead(nghttp2_session* session,
                                     int32_t stream_id,
                                     uint8_t* buf,
                                     size_t length,
                                     uint32_t* flags,
                                     nghttp2_data_source* source,
                                     void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);

  size_t remaining = length;
  size_t offset = 0;

  while (stream_handle->queue_head_ != nullptr) {
    nghttp2_stream_write_queue* head = stream_handle->queue_head_;
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
    stream_handle->queue_head_ = head->next;
    head->cb(head->req, 0);
    delete head;
  }

 end:
  int writable = stream_handle->queue_head_ != nullptr ||
                 nghttp2_stream_writable(stream_handle);
  if (offset == 0 && writable && stream_handle->queue_head_ == nullptr) {
    /* TODO(addaleax): ask @jasnell what the correct semantics are...
       this is dead code right now */
    return NGHTTP2_ERR_DEFERRED;
  }
  if (!writable) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;

    MaybeStackBuffer<nghttp2_nv> trailers;
    handle->OnTrailers(stream_handle, &trailers);
    if (trailers.length() > 0) {
      *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      nghttp2_submit_trailer(session,
                             stream_handle->id,
                             *trailers,
                             trailers.length());
    }
    for (size_t n = 0; n < trailers.length(); n++) {
      free(trailers[n].name);
      free(trailers[n].value);
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

void Nghttp2Session::DrainHeaders(nghttp2_pending_headers_cb* cb) {
  assert(cb != nullptr);
  OnHeaders(cb->handle, cb->headers, cb->category, cb->flags);
  nghttp2_free_headers_list(cb);
  pending_headers_free_list.push(cb);
}

void Nghttp2Session::DrainStreamClose(nghttp2_pending_stream_close_cb* cb) {
  assert(cb != nullptr);
  OnStreamClose(cb->handle->id, cb->error_code);
  streams_.erase(cb->handle->id);
  pending_stream_close_free_list.push(cb);
}

void Nghttp2Session::DrainSend(nghttp2_pending_session_send_cb* cb) {
  assert(cb != nullptr);
  Send(cb->buf, cb->length);
  pending_session_send_free_list.push(cb);
}

void Nghttp2Session::DeleteDataChunks(nghttp2_data_chunks_t* chunks) {
  for (unsigned int n = 0; n < chunks->nbufs; n++) {
    delete[] chunks->buf[n].base;
  }
  data_chunks_free_list.push(chunks);
}

void Nghttp2Session::DrainDataChunks(nghttp2_pending_data_chunks_cb* cb) {
  assert(cb != nullptr);
  std::shared_ptr<nghttp2_data_chunks_t> chunks;
  unsigned int n = 0;
  size_t amount = 0;

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
      OnDataChunks(cb->handle, chunks);
      // Notify the nghttp2_session that a given chunk of data has been
      // consumed and we are ready to receive more data for this stream
      nghttp2_session_consume(session, cb->handle->id, amount);
      n = 0;
      amount = 0;
    }
  }
  pending_data_chunks_free_list.push(cb);
}

void Nghttp2Session::DrainSettings(nghttp2_pending_settings_cb* cb) {
  assert(cb != nullptr);
  OnSettings();
  pending_settings_free_list.push(cb);
}

void Nghttp2Session::DrainCallbacks() {
  while (ready_callbacks_head_ != nullptr) {
    nghttp2_pending_cb_list* item = ready_callbacks_head_;
    switch (item->type) {
      case NGHTTP2_CB_SESSION_SEND:
        DrainSend(static_cast<nghttp2_pending_session_send_cb*>(item->cb));
        break;
      case NGHTTP2_CB_HEADERS:
        DrainHeaders(static_cast<nghttp2_pending_headers_cb*>(item->cb));
        break;
      case NGHTTP2_CB_STREAM_CLOSE:
        DrainStreamClose(
            static_cast<nghttp2_pending_stream_close_cb*>(item->cb));
        break;
      case NGHTTP2_CB_DATA_CHUNKS:
        DrainDataChunks(static_cast<nghttp2_pending_data_chunks_cb*>(item->cb));
        break;
      case NGHTTP2_CB_SETTINGS:
        DrainSettings(static_cast<nghttp2_pending_settings_cb*>(item->cb));
      case NGHTTP2_CB_NONE:
        break;
    }
    ready_callbacks_head_ = item->next;
    cb_free_list.push(item);
  }
  ready_callbacks_tail_ = nullptr;
  assert(ready_callbacks_tail_ == nullptr);
  assert(ready_callbacks_head_ == nullptr);
}

void Nghttp2Session::DrainSend() {
  const uint8_t* data;
  nghttp2_pending_session_send_cb* cb = nullptr;
  nghttp2_pending_cb_list* item;
  size_t amount = 0;
  size_t offset = 0;
  size_t src_offset = 0;
  uv_buf_t* current = AllocateSend(SEND_BUFFER_RECOMMENDED_SIZE);
  assert(current);
  size_t remaining = current->len;
  while ((amount = nghttp2_session_mem_send(session, &data)) > 0) {
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
        LINKED_LIST_ADD(ready_callbacks, item);
        offset = 0;
        current = AllocateSend(SEND_BUFFER_RECOMMENDED_SIZE);
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
  LINKED_LIST_ADD(ready_callbacks, item);
}

inline void Nghttp2Session::SendAndMakeReady() {
  while (nghttp2_session_want_write(session)) {
    DrainSend();
  }

  LINKED_LIST_ADD(ready_callbacks,
                  pending_callbacks_head_);
  pending_callbacks_head_ = nullptr;
  pending_callbacks_tail_ = nullptr;
}

void Nghttp2Session::OnSessionPrep(uv_prepare_t* t) {
  Nghttp2Session* handle = ContainerOf(&Nghttp2Session::prep_, t);

  handle->SendAndMakeReady();
  handle->DrainCallbacks();
}

int Nghttp2Session::OnBeginHeadersCallback(nghttp2_session* session,
                                           const nghttp2_frame* frame,
                                           void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  if (!handle->HasStream(frame->hd.stream_id)) {
    handle->StreamInit(frame->hd.stream_id, frame->headers.cat);
  } else {
    std::shared_ptr<nghttp2_stream_t> stream_handle;
    stream_handle = handle->FindStream(frame->hd.stream_id);
    assert(stream_handle);
    stream_handle->current_headers_category = frame->headers.cat;
  }
  return 0;
}

int Nghttp2Session::OnHeaderCallback(nghttp2_session* session,
                                     const nghttp2_frame* frame,
                                     nghttp2_rcbuf *name,
                                     nghttp2_rcbuf *value,
                                     uint8_t flags,
                                     void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  stream_handle = handle->FindStream(frame->hd.stream_id);
  assert(stream_handle);

  nghttp2_header_list* header = header_free_list.pop();
  header->name = name;
  header->value = value;
  nghttp2_rcbuf_incref(name);
  nghttp2_rcbuf_incref(value);
  LINKED_LIST_ADD(stream_handle->current_headers, header);
  return 0;
}

void Nghttp2Session::QueuePendingDataChunks(
    std::shared_ptr<nghttp2_stream_t> handle,
    uint8_t flags) {
  if (handle->current_data_chunks_cb != nullptr) {
    handle->current_data_chunks_cb->flags = flags;
    nghttp2_pending_cb_list* pending_cb = cb_free_list.pop();
    pending_cb->type = NGHTTP2_CB_DATA_CHUNKS;
    pending_cb->cb = handle->current_data_chunks_cb;
    handle->current_data_chunks_cb = nullptr;
    QueuePendingCallback(pending_cb);
  }
}

int Nghttp2Session::OnFrameReceive(nghttp2_session* session,
                                   const nghttp2_frame* frame,
                                   void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  nghttp2_pending_cb_list* pending_cb;
  nghttp2_pending_headers_cb* cb;
  switch (frame->hd.type) {
    case NGHTTP2_DATA:
      stream_handle = handle->FindStream(frame->hd.stream_id);
      assert(stream_handle);
      if (nghttp2_stream_is_reading(stream_handle)) {
        // If the stream is in the reading state, push the currently
        // buffered data chunks into the callback queue for processing.
        handle->QueuePendingDataChunks(stream_handle, frame->hd.flags);
      }
      break;
    case NGHTTP2_HEADERS:
      stream_handle = handle->FindStream(frame->hd.stream_id);
      assert(stream_handle);
      cb = pending_headers_free_list.pop();
      cb->handle = stream_handle;
      cb->category = stream_handle->current_headers_category;
      cb->headers = stream_handle->current_headers_head_;
      cb->flags = frame->hd.flags;
      stream_handle->current_headers_head_ = nullptr;
      stream_handle->current_headers_tail_ = nullptr;
      pending_cb = cb_free_list.pop();
      pending_cb->type = NGHTTP2_CB_HEADERS;
      pending_cb->cb = cb;
      handle->QueuePendingCallback(pending_cb);
      break;
    case NGHTTP2_SETTINGS:
      if ((frame->hd.flags & NGHTTP2_FLAG_ACK) == 0) {
        pending_cb = cb_free_list.pop();
        pending_cb->type = NGHTTP2_CB_SETTINGS;
        pending_cb->cb = pending_settings_free_list.pop();
        handle->QueuePendingCallback(pending_cb);
      }
    default:
      break;
  }
  return 0;
}

int Nghttp2Session::OnStreamClose(nghttp2_session *session,
                                  int32_t stream_id,
                                  uint32_t error_code,
                                  void *user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);
  nghttp2_pending_cb_list* pending_cb = cb_free_list.pop();
  pending_cb->type = NGHTTP2_CB_STREAM_CLOSE;
  nghttp2_pending_stream_close_cb* cb = pending_stream_close_free_list.pop();
  cb->handle = stream_handle;
  cb->error_code = error_code;
  pending_cb->cb = cb;
  handle->QueuePendingCallback(pending_cb);
  return 0;
}

int Nghttp2Session::OnBeginFrameReceived(nghttp2_session* session,
                                         const nghttp2_frame_hd* hd,
                                         void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  nghttp2_pending_data_chunks_cb* chunks_cb;
  switch (hd->type) {
    case NGHTTP2_DATA:
      stream_handle = handle->FindStream(hd->stream_id);
      assert(stream_handle);
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

int Nghttp2Session::OnDataChunkReceived(nghttp2_session *session,
                                        uint8_t flags,
                                        int32_t stream_id,
                                        const uint8_t *data,
                                        size_t len,
                                        void *user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<nghttp2_stream_t> stream_handle;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);
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

ssize_t Nghttp2Session::OnSelectPadding(nghttp2_session* session,
                                        const nghttp2_frame* frame,
                                        size_t maxPayloadLen,
                                        void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  assert(handle->HasGetPaddingCallback());
  return handle->GetPadding(frame->hd.length, maxPayloadLen);
}

// Initialize the Nghttp2Session handle by creating and
// assigning the Nghttp2Session instance and associated
// uv_loop_t.
int Nghttp2Session::Init(uv_loop_t* loop,
                         const nghttp2_session_type type,
                         nghttp2_option* options,
                         nghttp2_mem* mem) {
  loop_ = loop;
  session_type_ = type;
  int ret = 0;

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

  if (HasGetPaddingCallback()) {
    nghttp2_session_callbacks_set_select_padding_callback(
      callbacks, OnSelectPadding);
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
      ret = nghttp2_session_server_new3(&session,
                                        callbacks,
                                        this,
                                        opts,
                                        mem);
      break;
    case NGHTTP2_SESSION_CLIENT:
      ret = nghttp2_session_client_new3(&session,
                                        callbacks,
                                        this,
                                        opts,
                                        mem);
      break;
  }
  if (opts != options) {
    nghttp2_option_del(opts);
  }
  nghttp2_session_callbacks_del(callbacks);

  uv_prepare_init(loop_, &prep_);
  uv_prepare_start(&prep_, OnSessionPrep);
  return ret;
}

void Nghttp2Session::StreamDeleter(nghttp2_stream_t* handle) {
  Nghttp2Session* session = handle->session;
  assert(session != nullptr);
  session->OnStreamFree(handle);
  stream_free_list.push(handle);
}

std::shared_ptr<nghttp2_stream_t> Nghttp2Session::StreamInit(
    int32_t id,
    nghttp2_headers_category category) {
  std::shared_ptr<nghttp2_stream_t> stream_handle =
      std::shared_ptr<nghttp2_stream_t>(stream_free_list.pop(), StreamDeleter);
  stream_handle->session = this;
  stream_handle->id = id;
  stream_handle->current_headers_category = category;
  streams_[id] = stream_handle;
  OnStreamInit(stream_handle);
  return stream_handle;
}

// Returns true if the session is alive, false if it is not
// A session that is not alive is ok to be freed
bool Nghttp2Session::IsAliveSession() {
  return nghttp2_session_want_read(session) ||
         nghttp2_session_want_write(session);
}

int Nghttp2Session::Free() {
  assert(session != nullptr);
  assert(pending_callbacks_head_ == nullptr);
  assert(pending_callbacks_tail_ == nullptr);
  assert(ready_callbacks_head_ == nullptr);
  assert(ready_callbacks_tail_ == nullptr);

  uv_prepare_stop(&prep_);
  auto PrepClose = [](uv_handle_t* handle) {
    Nghttp2Session* session =
        ContainerOf(&Nghttp2Session::prep_,
                    reinterpret_cast<uv_prepare_t*>(handle));

    session->OnFreeSession();
  };
  uv_close(reinterpret_cast<uv_handle_t*>(&prep_), PrepClose);

  nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
  nghttp2_session_del(session);
  session = nullptr;
  loop_ = nullptr;
  return 1;
}

// Write data received from the socket to the underlying nghttp2_session.
ssize_t Nghttp2Session::Write(const uv_buf_t* bufs, unsigned int nbufs) {
  size_t total = 0;
  for (unsigned int n = 0; n < nbufs; n++) {
    ssize_t ret =
      nghttp2_session_mem_recv(session,
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
int Nghttp2Session::SubmitSettings(const nghttp2_settings_entry iv[],
                                   size_t niv) {
  return nghttp2_submit_settings(session,
                                 NGHTTP2_FLAG_NONE, iv, niv);
}

// Submit additional headers for a stream. Typically used to
// submit informational (1xx) headers
inline int nghttp2_submit_info(std::shared_ptr<nghttp2_stream_t> handle,
                               nghttp2_nv* nva, size_t len) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  Nghttp2Session* session = h->session;
  return nghttp2_submit_headers(session->session,
                                NGHTTP2_FLAG_NONE,
                                h->id, nullptr,
                                nva, len, nullptr);
}

inline int nghttp2_submit_priority(std::shared_ptr<nghttp2_stream_t> handle,
                                   nghttp2_priority_spec* prispec,
                                   bool silent) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  Nghttp2Session* session = h->session;

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
  Nghttp2Session* session = h->session;
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
  Nghttp2Session* session = h->session;

  int32_t ret = nghttp2_submit_push_promise(session->session,
                                            NGHTTP2_FLAG_NONE,
                                            h->id, nva, len,
                                            nullptr);
  if (ret > 0) {
    *assigned = session->StreamInit(ret);
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
  Nghttp2Session* session = h->session;

  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = &handle;
  prov.read_callback = Nghttp2Session::OnStreamRead;
  if (!emptyPayload && nghttp2_stream_writable(h))
    provider = &prov;

  return nghttp2_submit_response(session->session, handle->id,
                                 nva, len, provider);
}


// Initiate a request. If writable is true (the default), then
// an nghttp2_data_provider will be initialized, causing at
// least one (possibly empty) data frame to to be sent.
inline int32_t Nghttp2Session::SubmitRequest(
    nghttp2_priority_spec* prispec,
    nghttp2_nv* nva,
    size_t len,
    std::shared_ptr<nghttp2_stream_t>* assigned,
    bool emptyPayload) {
  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = this;
  prov.read_callback = OnStreamRead;
  if (!emptyPayload)
    provider = &prov;
  int32_t ret = nghttp2_submit_request(session,
                                       prispec, nva, len,
                                       provider, nullptr);
  // Assign the nghttp2_stream_t handle
  if (ret > 0) {
    *assigned = StreamInit(ret);
    if (emptyPayload) nghttp2_stream_shutdown(*assigned);
  }
  return ret;
}

// Mark the writable side of the nghttp2_stream as being shutdown.
inline int nghttp2_stream_shutdown(std::shared_ptr<nghttp2_stream_t> handle) {
  std::shared_ptr<nghttp2_stream_t> h = handle;
  Nghttp2Session* session = h->session;
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
                                std::shared_ptr<nghttp2_stream_t> h,
                                const uv_buf_t bufs[],
                                unsigned int nbufs,
                                nghttp2_stream_write_cb cb) {
  Nghttp2Session* session = h->session;
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

  if (h->queue_head_ == nullptr) {
    h->queue_head_ = item;
    h->queue_tail_ = item;
  } else {
    h->queue_tail_->next = item;
    h->queue_tail_ = item;
  }
  nghttp2_session_resume_data(session->session, h->id);
  return 0;
}

inline void nghttp2_stream_read_start(
    std::shared_ptr<nghttp2_stream_t> handle) {
  Nghttp2Session* session = handle->session;
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
  session->QueuePendingDataChunks(handle);
}

inline void nghttp2_stream_read_stop(std::shared_ptr<nghttp2_stream_t> handle) {
  Nghttp2Session* session = handle->session;
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
