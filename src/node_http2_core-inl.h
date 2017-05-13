#ifndef SRC_NODE_HTTP2_CORE_INL_H_
#define SRC_NODE_HTTP2_CORE_INL_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node_http2_core.h"
#include "node_internals.h"  // arraysize
#include "freelist.h"

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

#define FREELIST_MAX 1024

extern Freelist<nghttp2_pending_data_chunks_cb, FREELIST_MAX>
    pending_data_chunks_free_list;
extern Freelist<nghttp2_data_chunk_t, FREELIST_MAX>
    data_chunk_free_list;

extern Freelist<Nghttp2Stream, FREELIST_MAX> stream_free_list;

extern Freelist<nghttp2_pending_cb_list, FREELIST_MAX> cb_free_list;

extern Freelist<nghttp2_header_list, FREELIST_MAX> header_free_list;

extern Freelist<nghttp2_pending_settings_cb, FREELIST_MAX>
    pending_settings_free_list;

extern Freelist<nghttp2_pending_stream_close_cb, FREELIST_MAX>
    pending_stream_close_free_list;

extern Freelist<nghttp2_pending_headers_cb, FREELIST_MAX>
    pending_headers_free_list;

extern Freelist<nghttp2_data_chunks_t, FREELIST_MAX>
    data_chunks_free_list;

extern Freelist<nghttp2_pending_session_send_cb, FREELIST_MAX>
    pending_session_send_free_list;

inline void Nghttp2Session::SubmitShutdownNotice() {
  nghttp2_submit_shutdown_notice(session_);
}

inline bool Nghttp2Session::HasStream(int32_t id) {
  auto s = streams_.find(id);
  return s != streams_.end();
}

inline std::shared_ptr<Nghttp2Stream> Nghttp2Session::FindStream(
    int32_t id) {
  auto s = streams_.find(id);
  if (s != streams_.end()) {
    return s->second;
  } else {
    return std::shared_ptr<Nghttp2Stream>(nullptr);
  }
}

void Nghttp2Session::QueuePendingCallback(nghttp2_pending_cb_list* item) {
  LINKED_LIST_ADD(pending_callbacks, item);
}

inline void nghttp2_free_headers_list(nghttp2_pending_headers_cb* cb) {
  assert(cb != nullptr);
  while (cb->headers != nullptr) {
    nghttp2_header_list* item = cb->headers;
    nghttp2_rcbuf_decref(item->value);
    cb->headers = item->next;
    header_free_list.push(item);
  }
}

void Nghttp2Session::DrainHeaders(nghttp2_pending_headers_cb* cb,
                                  bool freeOnly) {
  assert(cb != nullptr);
  if (!freeOnly)
    OnHeaders(cb->handle, cb->headers, cb->category, cb->flags);
  nghttp2_free_headers_list(cb);
  pending_headers_free_list.push(cb);
}

void Nghttp2Session::DrainStreamClose(nghttp2_pending_stream_close_cb* cb,
                                      bool freeOnly) {
  assert(cb != nullptr);
  if (!freeOnly)
    OnStreamClose(cb->handle->id(), cb->error_code);
  if (cb->handle != nullptr) {
    streams_.erase(cb->handle->id());
    pending_stream_close_free_list.push(cb);
  }
}

void Nghttp2Session::DrainSend(nghttp2_pending_session_send_cb* cb,
                               bool freeOnly) {
  assert(cb != nullptr);
  if (!freeOnly)
    Send(cb->buf, cb->length);
  pending_session_send_free_list.push(cb);
}

void Nghttp2Session::DrainDataChunks(nghttp2_pending_data_chunks_cb* cb,
                                     bool freeOnly) {
  assert(cb != nullptr);
  std::shared_ptr<nghttp2_data_chunks_t> chunks;
  unsigned int n = 0;

  while (cb->head != nullptr) {
    if (chunks == nullptr) {
      auto delete_data_chunks = [](nghttp2_data_chunks_t* chunks) {
        data_chunks_free_list.push(chunks);
      };

      chunks = std::shared_ptr<nghttp2_data_chunks_t>(
          data_chunks_free_list.pop(), delete_data_chunks);
    }
    nghttp2_data_chunk_t* item = cb->head;
    chunks->buf[n++] = uv_buf_init(item->buf.base, item->buf.len);
    cb->head = item->next;
    data_chunk_free_list.push(item);
    if (n == arraysize(chunks->buf) || cb->head == nullptr) {
      chunks->nbufs = n;
      if (!freeOnly)
        OnDataChunks(cb->handle, chunks);
      n = 0;
    }
  }
  pending_data_chunks_free_list.push(cb);
}

void Nghttp2Session::DrainSettings(nghttp2_pending_settings_cb* cb,
                                   bool freeOnly) {
  assert(cb != nullptr);
  if (!freeOnly)
    OnSettings();
  pending_settings_free_list.push(cb);
}

void Nghttp2Session::DrainCallbacks(bool freeOnly) {
  while (ready_callbacks_head_ != nullptr) {
    nghttp2_pending_cb_list* item = ready_callbacks_head_;
    ready_callbacks_head_ = item->next;
    switch (item->type) {
      case NGHTTP2_CB_SESSION_SEND:
        DrainSend(static_cast<nghttp2_pending_session_send_cb*>(item->cb),
                  freeOnly);
        break;
      case NGHTTP2_CB_HEADERS:
        DrainHeaders(static_cast<nghttp2_pending_headers_cb*>(item->cb),
                     freeOnly);
        break;
      case NGHTTP2_CB_STREAM_CLOSE:
        DrainStreamClose(
            static_cast<nghttp2_pending_stream_close_cb*>(item->cb), freeOnly);
        break;
      case NGHTTP2_CB_DATA_CHUNKS:
        DrainDataChunks(static_cast<nghttp2_pending_data_chunks_cb*>(item->cb),
                        freeOnly);
        break;
      case NGHTTP2_CB_SETTINGS:
        DrainSettings(static_cast<nghttp2_pending_settings_cb*>(item->cb),
                      freeOnly);
      case NGHTTP2_CB_NONE:
        break;
    }
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
  while ((amount = nghttp2_session_mem_send(session_, &data)) > 0) {
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
  while (nghttp2_session_want_write(session_)) {
    DrainSend();
  }

  LINKED_LIST_ADD(ready_callbacks,
                  pending_callbacks_head_);
  pending_callbacks_head_ = nullptr;
  pending_callbacks_tail_ = nullptr;
}

void Nghttp2Session::QueuePendingDataChunks(Nghttp2Stream* stream,
                                            uint8_t flags) {
  if (stream->current_data_chunks_cb_ != nullptr) {
    stream->current_data_chunks_cb_->flags = flags;
    nghttp2_pending_cb_list* pending_cb = cb_free_list.pop();
    pending_cb->type = NGHTTP2_CB_DATA_CHUNKS;
    pending_cb->cb = stream->current_data_chunks_cb_;
    stream->current_data_chunks_cb_ = nullptr;
    QueuePendingCallback(pending_cb);
  }
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

  nghttp2_session_callbacks* callbacks
      = callback_struct_saved[HasGetPaddingCallback() ? 1 : 0].callbacks;

  nghttp2_option* opts;
  if (options != nullptr) {
    opts = options;
  } else {
    nghttp2_option_new(&opts);
  }

  switch (type) {
    case NGHTTP2_SESSION_SERVER:
      ret = nghttp2_session_server_new3(&session_,
                                        callbacks,
                                        this,
                                        opts,
                                        mem);
      break;
    case NGHTTP2_SESSION_CLIENT:
      ret = nghttp2_session_client_new3(&session_,
                                        callbacks,
                                        this,
                                        opts,
                                        mem);
      break;
  }
  if (opts != options) {
    nghttp2_option_del(opts);
  }

  uv_prepare_init(loop_, &prep_);

  uv_prepare_start(&prep_, [](uv_prepare_t* t) {
    Nghttp2Session* handle = ContainerOf(&Nghttp2Session::prep_, t);
    assert(handle);
    handle->SendAndMakeReady();
    handle->DrainCallbacks();
  });
  return ret;
}

std::shared_ptr<Nghttp2Stream> Nghttp2Session::StreamInit(
    int32_t id,
    nghttp2_headers_category category) {
  std::shared_ptr<Nghttp2Stream> stream_handle =
      std::shared_ptr<Nghttp2Stream>(stream_free_list.pop(), StreamDeleter);
  stream_handle->session_ = this;
  stream_handle->id_ = id;
  stream_handle->current_headers_category_ = category;
  streams_[id] = stream_handle;
  OnStreamInit(stream_handle);
  return stream_handle;
}

// Returns true if the session is alive, false if it is not
// A session that is not alive is ok to be freed
bool Nghttp2Session::IsAliveSession() {
  return nghttp2_session_want_read(session_) ||
         nghttp2_session_want_write(session_);
}

int Nghttp2Session::Free() {
  assert(session_ != nullptr);

  // Stop the loop
  uv_prepare_stop(&prep_);
  auto PrepClose = [](uv_handle_t* handle) {
    Nghttp2Session* session =
        ContainerOf(&Nghttp2Session::prep_,
                    reinterpret_cast<uv_prepare_t*>(handle));

    session->OnFreeSession();
  };
  uv_close(reinterpret_cast<uv_handle_t*>(&prep_), PrepClose);

  // // If there are any pending callbacks, those need to be cleared out
  // // to avoid memory leaks. Normally this should only happen in abnormal
  // // cases, such as the premature destruction of the socket which forces
  // // us to simply drop pending data on the floor.
  LINKED_LIST_ADD(ready_callbacks,
                  pending_callbacks_head_);
  pending_callbacks_head_ = nullptr;
  pending_callbacks_tail_ = nullptr;
  DrainCallbacks(true);

  assert(pending_callbacks_head_ == nullptr);
  assert(pending_callbacks_tail_ == nullptr);
  assert(ready_callbacks_head_ == nullptr);
  assert(ready_callbacks_tail_ == nullptr);

  nghttp2_session_terminate_session(session_, NGHTTP2_NO_ERROR);
  nghttp2_session_del(session_);
  session_ = nullptr;
  loop_ = nullptr;
  return 1;
}

// Write data received from the socket to the underlying nghttp2_session.
ssize_t Nghttp2Session::Write(const uv_buf_t* bufs, unsigned int nbufs) {
  size_t total = 0;
  for (unsigned int n = 0; n < nbufs; n++) {
    ssize_t ret =
      nghttp2_session_mem_recv(session_,
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
  return nghttp2_submit_settings(session_,
                                 NGHTTP2_FLAG_NONE, iv, niv);
}

// Submit additional headers for a stream. Typically used to
// submit informational (1xx) headers
int Nghttp2Stream::SubmitInfo(nghttp2_nv* nva, size_t len) {
  return nghttp2_submit_headers(session_->session(),
                                NGHTTP2_FLAG_NONE,
                                id_, nullptr,
                                nva, len, nullptr);
}

int Nghttp2Stream::SubmitPriority(nghttp2_priority_spec* prispec,
                                  bool silent) {
  return silent ?
      nghttp2_session_change_stream_priority(session_->session(),
                                             id_, prispec) :
      nghttp2_submit_priority(session_->session(),
                              NGHTTP2_FLAG_NONE,
                              id_, prispec);
}

// Submit an RST_STREAM frame
int Nghttp2Stream::SubmitRstStream(const uint32_t code) {
  return nghttp2_submit_rst_stream(session_->session(),
                                   NGHTTP2_FLAG_NONE,
                                   id_,
                                   code);
}

// Submit a push promise
int32_t Nghttp2Stream::SubmitPushPromise(
    nghttp2_nv* nva,
    size_t len,
    std::shared_ptr<Nghttp2Stream>* assigned,
    bool emptyPayload) {
  int32_t ret = nghttp2_submit_push_promise(session_->session(),
                                            NGHTTP2_FLAG_NONE,
                                            id_, nva, len,
                                            nullptr);
  if (ret > 0) {
    auto stream = session_->StreamInit(ret);
    if (emptyPayload) stream->Shutdown();
    if (assigned != nullptr) *assigned = stream;
  }
  return ret;
}

// Initiate a response. If the nghttp2_stream is still writable by
// the time this is called, then an nghttp2_data_provider will be
// initialized, causing at least one (possibly empty) data frame to
// be sent.
int Nghttp2Stream::SubmitResponse(nghttp2_nv* nva,
                                  size_t len,
                                  bool emptyPayload) {
  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = this;
  prov.read_callback = Nghttp2Session::OnStreamRead;
  if (!emptyPayload && IsWritable())
    provider = &prov;

  return nghttp2_submit_response(session_->session(), id_,
                                 nva, len, provider);
}


// Initiate a request. If writable is true (the default), then
// an nghttp2_data_provider will be initialized, causing at
// least one (possibly empty) data frame to to be sent.
inline int32_t Nghttp2Session::SubmitRequest(
    nghttp2_priority_spec* prispec,
    nghttp2_nv* nva,
    size_t len,
    std::shared_ptr<Nghttp2Stream>* assigned,
    bool emptyPayload) {
  nghttp2_data_provider* provider = nullptr;
  nghttp2_data_provider prov;
  prov.source.ptr = this;
  prov.read_callback = OnStreamRead;
  if (!emptyPayload)
    provider = &prov;
  int32_t ret = nghttp2_submit_request(session_,
                                       prispec, nva, len,
                                       provider, nullptr);
  // Assign the Nghttp2Stream handle
  if (ret > 0) {
    auto stream = StreamInit(ret);
    if (emptyPayload) stream->Shutdown();
    if (assigned != nullptr) *assigned = stream;
  }
  return ret;
}

// Mark the writable side of the nghttp2_stream as being shutdown.
int Nghttp2Stream::Shutdown() {
  flags_ |= NGHTTP2_STREAM_FLAG_SHUT;
  nghttp2_session_resume_data(session_->session(), id_);
  return 0;
}

// Queue the given set of uv_but_t handles for writing to an
// nghttp2_stream. The callback will be invoked once the chunks
// of data have been flushed to the underlying nghttp2_session.
// Note that this does *not* mean that the data has been flushed
// to the socket yet.
int Nghttp2Stream::Write(nghttp2_stream_write_t* req,
                         const uv_buf_t bufs[],
                         unsigned int nbufs,
                         nghttp2_stream_write_cb cb) {
  if (!IsWritable()) {
    if (cb != nullptr)
      cb(req, UV_EOF);
    return 0;
  }
  nghttp2_stream_write_queue* item = new nghttp2_stream_write_queue;
  item->cb = cb;
  item->req = req;
  item->nbufs = nbufs;
  item->bufs.AllocateSufficientStorage(nbufs);
  req->handle = shared_from_this();
  req->item = item;
  memcpy(*(item->bufs), bufs, nbufs * sizeof(*bufs));

  if (queue_head_ == nullptr) {
    queue_head_ = item;
    queue_tail_ = item;
  } else {
    queue_tail_->next = item;
    queue_tail_ = item;
  }
  nghttp2_session_resume_data(session_->session(), id_);
  return 0;
}

void Nghttp2Stream::ReadStart() {
  if (reading_ == 0) {
    // If handle->reading is less than zero, read_start had never previously
    // been called. If handle->reading is zero, reading had started and read
    // stop had been previously called, meaning that the flow control window
    // has been explicitly set to zero. Reset the flow control window now to
    // restart the flow of data.
    nghttp2_session_set_local_window_size(session_->session(),
                                          NGHTTP2_FLAG_NONE,
                                          id_,
                                          prev_local_window_size_);
  }
  reading_ = 1;
  session_->QueuePendingDataChunks(this);
}

void Nghttp2Stream::ReadStop() {
  reading_ = 0;
  // When not reading, explicitly set the local window size to 0 so that
  // the peer does not keep sending data that has to be buffered
  int32_t ret =
    nghttp2_session_get_stream_local_window_size(session_->session(), id_);
  if (ret >= 0)
    prev_local_window_size_ = ret;
  nghttp2_session_set_local_window_size(session_->session(),
                                        NGHTTP2_FLAG_NONE,
                                        id_, 0);
}

bool Nghttp2Stream::IsWritable() const {
  return (flags_ & NGHTTP2_STREAM_FLAG_SHUT) == 0;
}

bool Nghttp2Stream::IsReadable() const {
  return (flags_ & NGHTTP2_STREAM_FLAG_ENDED) == 0;
}

bool Nghttp2Stream::IsReading() const {
  return reading_ > 0;
}

int32_t Nghttp2Stream::id() const {
  return id_;
}

Nghttp2Stream::~Nghttp2Stream() {
  if (current_data_chunks_cb_ != nullptr) {
    nghttp2_pending_data_chunks_cb* chunks = current_data_chunks_cb_;
    while (chunks->head != nullptr) {
      nghttp2_data_chunk_t* chunk = chunks->head;
      chunks->head = chunk->next;
      delete[] chunk->buf.base;
      data_chunk_free_list.push(chunk);
    }
    pending_data_chunks_free_list.push(chunks);
  }
}

nghttp2_data_chunks_t::~nghttp2_data_chunks_t() {
  for (unsigned int n = 0; n < nbufs; n++) {
    free(buf[n].base);
  }
}

Nghttp2Session::Callbacks::Callbacks(bool kHasGetPaddingCallback) {
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

  if (kHasGetPaddingCallback) {
    nghttp2_session_callbacks_set_select_padding_callback(
      callbacks, OnSelectPadding);
  }
}

Nghttp2Session::Callbacks::~Callbacks() {
  nghttp2_session_callbacks_del(callbacks);
}

}  // namespace http2
}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_NODE_HTTP2_CORE_INL_H_
