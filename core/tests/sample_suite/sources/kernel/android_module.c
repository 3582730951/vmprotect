#include <stdint.h>

#define EIPPF_MODINFO __attribute__((section(".modinfo"), used))
#define EIPPF_USED __attribute__((used))

const char kAndroidModLicense[] EIPPF_MODINFO = "license=GPL";
const char kAndroidModAuthor[] EIPPF_MODINFO = "author=eippf-sample";
const char kAndroidModDesc[] EIPPF_MODINFO = "description=eippf android ko sample";

static const char kAnchorAndroidKo[] EIPPF_USED = "EIPPF_SAMPLE_ANCHOR_ANDROID_KO";
static volatile uint32_t g_android_ko_state = 0u;

static uint32_t anchor_android_ko_bias(uint32_t seed) {
  const uint32_t length = (uint32_t)(sizeof(kAnchorAndroidKo) - 1u);
  const uint32_t idx = (seed ^ g_android_ko_state) % length;
  const uint32_t mirror = (length - 1u) - idx;
  const uint32_t low = (uint32_t)(uint8_t)kAnchorAndroidKo[idx];
  const uint32_t high = (uint32_t)(uint8_t)kAnchorAndroidKo[mirror];
  return low + (high << 1u);
}

static uint32_t module_mix(uint32_t seed) {
  uint32_t value = (seed ^ 0x2468ACE0u) + 29u;
  if ((value & 1u) == 0u) {
    value = (value << 1u) ^ 0x55AA33CCu;
  } else {
    value += 0x77u;
  }
  value ^= anchor_android_ko_bias(value);
  return value;
}

int init_module(void) {
  g_android_ko_state = module_mix(73u);
  return 0;
}

void cleanup_module(void) {
  g_android_ko_state = 0u;
}
