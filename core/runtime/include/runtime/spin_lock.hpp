#pragma once

#include <atomic>

namespace eippf::runtime {

class SpinLock final {
 public:
  SpinLock() noexcept = default;
  SpinLock(const SpinLock&) = delete;
  SpinLock& operator=(const SpinLock&) = delete;

  void lock() noexcept {
    while (flag_.test_and_set(std::memory_order_acquire)) {
      while (flag_.test(std::memory_order_relaxed)) {
      }
    }
  }

  void unlock() noexcept { flag_.clear(std::memory_order_release); }

 private:
  std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

class SpinLockGuard final {
 public:
  explicit SpinLockGuard(SpinLock& lock) noexcept : lock_(lock) { lock_.lock(); }
  SpinLockGuard(const SpinLockGuard&) = delete;
  SpinLockGuard& operator=(const SpinLockGuard&) = delete;
  ~SpinLockGuard() { lock_.unlock(); }

 private:
  SpinLock& lock_;
};

}  // namespace eippf::runtime
