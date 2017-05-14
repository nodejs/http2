#include "node_http2_core-inl.h"

namespace node {
namespace http2 {

void Nghttp2Session::StreamDeleter(Nghttp2Stream* handle) {
  Nghttp2Session* session = handle->session_;
  assert(session != nullptr);
  session->OnStreamFree(handle);
  stream_free_list.push(handle);
}

int Nghttp2Session::OnBeginHeadersCallback(nghttp2_session* session,
                                           const nghttp2_frame* frame,
                                           void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  int32_t stream_id = (frame->hd.type == NGHTTP2_PUSH_PROMISE) ?
    frame->push_promise.promised_stream_id :
    frame->hd.stream_id;
  if (!handle->HasStream(stream_id)) {
    handle->StreamInit(stream_id, frame->headers.cat);
  } else {
    std::shared_ptr<Nghttp2Stream> stream_handle;
    stream_handle = handle->FindStream(stream_id);
    assert(stream_handle);
    stream_handle->current_headers_category_ = frame->headers.cat;
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
  std::shared_ptr<Nghttp2Stream> stream_handle;
  int32_t stream_id = (frame->hd.type == NGHTTP2_PUSH_PROMISE) ?
    frame->push_promise.promised_stream_id :
    frame->hd.stream_id;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);

  nghttp2_header_list* header = header_free_list.pop();
  header->name = name;
  header->value = value;
  nghttp2_rcbuf_incref(name);
  nghttp2_rcbuf_incref(value);
  LINKED_LIST_ADD(stream_handle->current_headers, header);
  return 0;
}

int Nghttp2Session::OnFrameReceive(nghttp2_session* session,
                                   const nghttp2_frame* frame,
                                   void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<Nghttp2Stream> stream_handle;
  nghttp2_pending_cb_list* pending_cb;
  nghttp2_pending_headers_cb* cb;
  nghttp2_pending_priority_cb* priority_cb;
  nghttp2_priority_spec pri_spec;
  nghttp2_priority priority_frame;
  int32_t stream_id;
  switch (frame->hd.type) {
    case NGHTTP2_DATA:
      stream_handle = handle->FindStream(frame->hd.stream_id);
      assert(stream_handle);
      if (stream_handle->IsReading()) {
        // If the stream is in the reading state, push the currently
        // buffered data chunks into the callback queue for processing.
        handle->QueuePendingDataChunks(stream_handle.get(), frame->hd.flags);
      }
      break;
    case NGHTTP2_PUSH_PROMISE:
    case NGHTTP2_HEADERS:
      stream_id = (frame->hd.type == NGHTTP2_PUSH_PROMISE) ?
        frame->push_promise.promised_stream_id :
        frame->hd.stream_id;
      stream_handle = handle->FindStream(stream_id);
      assert(stream_handle);
      cb = pending_headers_free_list.pop();
      cb->handle = stream_handle;
      cb->category = stream_handle->current_headers_category_;
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
    case NGHTTP2_PRIORITY:
      priority_frame = frame->priority;
      stream_id = frame->hd.stream_id;
      if (stream_id > 0) {
        pri_spec = priority_frame.pri_spec;
        priority_cb = pending_priority_free_list.pop();
        priority_cb->stream = stream_id;
        priority_cb->parent = pri_spec.stream_id;
        priority_cb->weight = pri_spec.weight;
        priority_cb->exclusive = pri_spec.exclusive;
        pending_cb = cb_free_list.pop();
        pending_cb->type = NGHTTP2_CB_PRIORITY;
        pending_cb->cb = priority_cb;
        handle->QueuePendingCallback(pending_cb);
      }
      break;
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
  std::shared_ptr<Nghttp2Stream> stream_handle;
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
  std::shared_ptr<Nghttp2Stream> stream_handle;
  nghttp2_pending_data_chunks_cb* chunks_cb;
  switch (hd->type) {
    case NGHTTP2_DATA:
      stream_handle = handle->FindStream(hd->stream_id);
      assert(stream_handle);
      if (stream_handle->current_data_chunks_cb_ == nullptr) {
        chunks_cb = pending_data_chunks_free_list.pop();
        chunks_cb->handle = stream_handle;
        stream_handle->current_data_chunks_cb_ = chunks_cb;
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
  std::shared_ptr<Nghttp2Stream> stream_handle;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);
  nghttp2_pending_data_chunks_cb* chunks_cb =
      stream_handle->current_data_chunks_cb_;
  if (chunks_cb == nullptr) {
    chunks_cb = pending_data_chunks_free_list.pop();
    chunks_cb->handle = stream_handle;
    stream_handle->current_data_chunks_cb_ = chunks_cb;
  }
  nghttp2_data_chunk_t* chunk = data_chunk_free_list.pop();
  chunk->buf = uv_buf_init(Malloc(len), len);
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

ssize_t Nghttp2Session::OnStreamRead(nghttp2_session* session,
                                     int32_t stream_id,
                                     uint8_t* buf,
                                     size_t length,
                                     uint32_t* flags,
                                     nghttp2_data_source* source,
                                     void* user_data) {
  Nghttp2Session* handle = static_cast<Nghttp2Session*>(user_data);
  std::shared_ptr<Nghttp2Stream> stream_handle;
  stream_handle = handle->FindStream(stream_id);
  assert(stream_handle);

  size_t remaining = length;
  size_t offset = 0;

  while (stream_handle->queue_head_ != nullptr) {
    nghttp2_stream_write_queue* head = stream_handle->queue_head_;
    while (stream_handle->queue_head_index_ < head->nbufs) {
      if (remaining == 0) {
        goto end;
      }

      unsigned int n = stream_handle->queue_head_index_;
      // len is the number of bytes in head->bufs[n] that are yet to be written
      size_t len = head->bufs[n].len - stream_handle->queue_head_offset_;
      size_t bytes_to_write = len < remaining ? len : remaining;
      memcpy(buf + offset,
             head->bufs[n].base + stream_handle->queue_head_offset_,
             bytes_to_write);
      offset += bytes_to_write;
      remaining -= bytes_to_write;
      if (bytes_to_write < len) {
        stream_handle->queue_head_offset_ += bytes_to_write;
      } else {
        stream_handle->queue_head_index_++;
        stream_handle->queue_head_offset_ = 0;
      }
    }
    stream_handle->queue_head_offset_ = 0;
    stream_handle->queue_head_index_ = 0;
    stream_handle->queue_head_ = head->next;
    head->cb(head->req, 0);
    delete head;
  }

 end:
  int writable = stream_handle->queue_head_ != nullptr ||
                 stream_handle->IsWritable();
  if (offset == 0 && writable && stream_handle->queue_head_ == nullptr) {
    return NGHTTP2_ERR_DEFERRED;
  }
  if (!writable) {
    *flags |= NGHTTP2_DATA_FLAG_EOF;

    MaybeStackBuffer<nghttp2_nv> trailers;
    handle->OnTrailers(stream_handle, &trailers);
    if (trailers.length() > 0) {
      *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      nghttp2_submit_trailer(session,
                             stream_handle->id(),
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


Freelist<nghttp2_pending_data_chunks_cb, FREELIST_MAX>
    pending_data_chunks_free_list;
Freelist<nghttp2_data_chunk_t, FREELIST_MAX>
    data_chunk_free_list;

Freelist<Nghttp2Stream, FREELIST_MAX> stream_free_list;

Freelist<nghttp2_pending_cb_list, FREELIST_MAX> cb_free_list;

Freelist<nghttp2_header_list, FREELIST_MAX> header_free_list;

Freelist<nghttp2_pending_settings_cb, FREELIST_MAX>
    pending_settings_free_list;

Freelist<nghttp2_pending_stream_close_cb, FREELIST_MAX>
    pending_stream_close_free_list;

Freelist<nghttp2_pending_headers_cb, FREELIST_MAX>
    pending_headers_free_list;

Freelist<nghttp2_pending_priority_cb, FREELIST_MAX>
    pending_priority_free_list;

Freelist<nghttp2_data_chunks_t, FREELIST_MAX>
    data_chunks_free_list;

Freelist<nghttp2_pending_session_send_cb, FREELIST_MAX>
    pending_session_send_free_list;

Nghttp2Session::Callbacks Nghttp2Session::callback_struct_saved[2] = {
  Callbacks(false),
  Callbacks(true)
};

}  // namespace http2
}  // namespace node
