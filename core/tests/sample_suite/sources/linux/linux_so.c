#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define EIPPF_SO_EXPORT __attribute__((visibility("default")))
#else
#define EIPPF_SO_EXPORT
#endif

static const char kAnchorLinuxSo[] = "EIPPF_SAMPLE_ANCHOR_LINUX_SO";

static int32_t so_mix(int32_t input) {
  int32_t value = (input * 7) - 13;
  if ((value & 2) != 0) {
    value ^= 0x1357;
  } else {
    value += 99;
  }
  value += (int32_t)kAnchorLinuxSo[5];
  return value;
}

EIPPF_SO_EXPORT int32_t sample_linux_so_entry(int32_t input) {
  return so_mix(input);
}
