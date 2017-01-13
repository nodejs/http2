#ifndef SRC_FREELIST_H_
#define SRC_FREELIST_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

namespace node {

template <typename T> using AllocatorCallback = T* (*)();
template <typename T> using ResetCallback = void (*)(T* item);
template <typename T> using FreeCallback = void (*)(T* item);


template <typename T, size_t MAX,
          AllocatorCallback<T> ALLOC,
          ResetCallback<T> RESET,
          FreeCallback<T> FREE>
class Freelist {
 public:
  typedef struct list_item {
    T* item = nullptr;
    list_item* next = nullptr;
  } list_item;

  Freelist() {}
  ~Freelist() {
    while (head_ != nullptr) {
      list_item* item = head_;
      head_ = item->next;
      FREE(item->item);
    }
  }

  void push(T* item) {
    if (size_ > MAX) {
      FREE(item);
    } else {
      size_++;
      RESET(item);
      list_item* li = new list_item;
      li->item = item;
      if (head_ == nullptr) {
        head_ = li;
        tail_ = li;
      } else {
        tail_->next = li;
        tail_ = li;
      }
    }
  }

  T* pop() {
    if (head_ != nullptr) {
      size_--;
      list_item* cur = head_;
      T* item = cur->item;
      head_ = cur->next;
      delete cur;
      return item;
    } else {
      return ALLOC();
    }
  }

 private:
  const size_t max_ = MAX;
  size_t size_ = 0;
  list_item* head_ = nullptr;
  list_item* tail_ = nullptr;
};

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#endif  // SRC_FREELIST_H_
