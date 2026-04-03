#include <stdint.h>

#if defined(_WIN32)
#define EIPPF_EXPORT __declspec(dllexport)
#else
#define EIPPF_EXPORT __attribute__((visibility("default")))
#endif

static const char kAnchorWindowsDll[] = "EIPPF_SAMPLE_ANCHOR_WINDOWS_DLL";

static int32_t dll_mix(int32_t left, int32_t right) {
  int32_t value = (left * 5) - (right * 3) + 11;
  if ((value & 1) != 0) {
    value ^= 0x5A5A;
  } else {
    value += 37;
  }
  value += (int32_t)kAnchorWindowsDll[6];
  return value;
}

EIPPF_EXPORT int32_t sample_windows_dll_entry(int32_t left, int32_t right) {
  return dll_mix(left, right);
}
