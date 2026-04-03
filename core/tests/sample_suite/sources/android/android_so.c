#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define EIPPF_ANDROID_EXPORT __attribute__((visibility("default")))
#else
#define EIPPF_ANDROID_EXPORT
#endif

static const char kAnchorAndroidSo[] = "EIPPF_SAMPLE_ANCHOR_ANDROID_SO";

static int32_t android_mix(int32_t value) {
  int32_t acc = (value * 11) + 5;
  if ((acc & 1) == 0) {
    acc ^= 0x33CC;
  } else {
    acc += 0x19;
  }
  acc += (int32_t)kAnchorAndroidSo[8];
  return acc;
}

EIPPF_ANDROID_EXPORT int32_t sample_android_so_entry(int32_t value) {
  return android_mix(value);
}
