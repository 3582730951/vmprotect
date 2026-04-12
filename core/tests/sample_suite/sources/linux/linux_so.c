#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define EIPPF_SO_EXPORT __attribute__((visibility("default")))
#else
#define EIPPF_SO_EXPORT
#endif

static const char kAnchorLinuxSo[] = "EIPPF_SAMPLE_ANCHOR_LINUX_SO";
static volatile uint32_t g_anchor_linux_so_state = 0u;

static int32_t anchor_linux_so_bias(uint32_t seed) {
  const uint32_t length = (uint32_t)(sizeof(kAnchorLinuxSo) - 1u);
  const uint32_t idx = (seed ^ g_anchor_linux_so_state) % length;
  const uint32_t mirror = (length - 1u) - idx;
  const int32_t low = (int32_t)(uint8_t)kAnchorLinuxSo[idx];
  const int32_t high = (int32_t)(uint8_t)kAnchorLinuxSo[mirror];
  g_anchor_linux_so_state = idx + 1u;
  return low + (high << 1);
}

static int32_t so_mix(int32_t input) {
  int32_t value = (input * 7) - 13;
  if ((value & 2) != 0) {
    value ^= 0x1357;
  } else {
    value += 99;
  }
  value += anchor_linux_so_bias((uint32_t)value);
  return value;
}

EIPPF_SO_EXPORT int32_t p0(int32_t input) {
  return so_mix(input);
}
