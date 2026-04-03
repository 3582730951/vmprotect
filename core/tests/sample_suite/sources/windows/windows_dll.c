#include <stdint.h>

#if defined(_WIN32)
#define EIPPF_EXPORT __declspec(dllexport)
#else
#define EIPPF_EXPORT __attribute__((visibility("default")))
#endif

static const char kAnchorWindowsDll[] = "EIPPF_SAMPLE_ANCHOR_WINDOWS_DLL";
static volatile uint32_t g_anchor_windows_dll_state = 0u;

static int32_t anchor_windows_dll_bias(uint32_t seed) {
  const uint32_t length = (uint32_t)(sizeof(kAnchorWindowsDll) - 1u);
  const uint32_t idx = (seed ^ g_anchor_windows_dll_state) % length;
  const uint32_t mirror = (length - 1u) - idx;
  const int32_t low = (int32_t)(uint8_t)kAnchorWindowsDll[idx];
  const int32_t high = (int32_t)(uint8_t)kAnchorWindowsDll[mirror];
  g_anchor_windows_dll_state = idx + 1u;
  return low ^ (high << 1);
}

static int32_t dll_mix(int32_t left, int32_t right) {
  int32_t value = (left * 5) - (right * 3) + 11;
  if ((value & 1) != 0) {
    value ^= 0x5A5A;
  } else {
    value += 37;
  }
  value += anchor_windows_dll_bias((uint32_t)value);
  return value;
}

EIPPF_EXPORT int32_t sample_windows_dll_entry(int32_t left, int32_t right) {
  return dll_mix(left, right);
}
