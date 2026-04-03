#include <stdint.h>

#define EIPPF_MODINFO __attribute__((section(".modinfo"), used))
#define EIPPF_USED __attribute__((used))

const char kLinuxModLicense[] EIPPF_MODINFO = "license=GPL";
const char kLinuxModAuthor[] EIPPF_MODINFO = "author=eippf-sample";
const char kLinuxModDesc[] EIPPF_MODINFO = "description=eippf linux ko sample";
const char kLinuxModAnchorMeta[] EIPPF_MODINFO =
    "eippf_anchor=EIPPF_SAMPLE_ANCHOR_LINUX_KO";

static const char kAnchorLinuxKo[] EIPPF_USED = "EIPPF_SAMPLE_ANCHOR_LINUX_KO";
static volatile uint32_t g_linux_ko_state = 0u;

static uint32_t module_mix(uint32_t seed) {
  uint32_t value = seed * 17u + 3u;
  if ((value & 8u) != 0u) {
    value ^= 0xAA00CC11u;
  } else {
    value += 0x102u;
  }
  value ^= (uint32_t)kAnchorLinuxKo[10];
  return value;
}

int init_module(void) {
  g_linux_ko_state = module_mix(41u);
  return 0;
}

void cleanup_module(void) {
  g_linux_ko_state = 0u;
}
