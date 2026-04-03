#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define EIPPF_ANDROID_EXPORT __attribute__((visibility("default")))
#else
#define EIPPF_ANDROID_EXPORT
#endif

static const char kAnchorAndroidSo[] = "EIPPF_SAMPLE_ANCHOR_ANDROID_SO";
static volatile uint32_t g_anchor_android_so_state = 0u;

static int32_t anchor_android_so_bias(uint32_t seed) {
  const uint32_t length = (uint32_t)(sizeof(kAnchorAndroidSo) - 1u);
  const uint32_t idx = (seed ^ g_anchor_android_so_state) % length;
  const uint32_t mirror = (length - 1u) - idx;
  const int32_t low = (int32_t)(uint8_t)kAnchorAndroidSo[idx];
  const int32_t high = (int32_t)(uint8_t)kAnchorAndroidSo[mirror];
  g_anchor_android_so_state = idx + 1u;
  return low ^ (high << 2);
}

static int32_t android_mix(int32_t value) {
  int32_t acc = (value * 11) + 5;
  if ((acc & 1) == 0) {
    acc ^= 0x33CC;
  } else {
    acc += 0x19;
  }
  acc += anchor_android_so_bias((uint32_t)acc);
  return acc;
}

EIPPF_ANDROID_EXPORT int32_t sample_android_so_entry(int32_t value) {
  return android_mix(value);
}
