#include <stdint.h>

#define EIPPF_MODINFO __attribute__((section(".modinfo"), used))
#define EIPPF_USED __attribute__((used))

const char kAndroidModLicense[] EIPPF_MODINFO = "license=GPL";
const char kAndroidModAuthor[] EIPPF_MODINFO = "author=eippf-sample";
const char kAndroidModDesc[] EIPPF_MODINFO = "description=eippf android ko sample";
const char kAndroidModAnchorMeta[] EIPPF_MODINFO =
    "eippf_anchor=EIPPF_SAMPLE_ANCHOR_ANDROID_KO";

static const char kAnchorAndroidKo[] EIPPF_USED = "EIPPF_SAMPLE_ANCHOR_ANDROID_KO";
static volatile uint32_t g_android_ko_state = 0u;

static uint32_t module_mix(uint32_t seed) {
  uint32_t value = (seed ^ 0x2468ACE0u) + 29u;
  if ((value & 1u) == 0u) {
    value = (value << 1u) ^ 0x55AA33CCu;
  } else {
    value += 0x77u;
  }
  value ^= (uint32_t)kAnchorAndroidKo[11];
  return value;
}

int init_module(void) {
  g_android_ko_state = module_mix(73u);
  return 0;
}

void cleanup_module(void) {
  g_android_ko_state = 0u;
}
