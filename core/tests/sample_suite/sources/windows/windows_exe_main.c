#include <stdint.h>
#include <stdio.h>

static const char kAnchorWindowsExe[] = "EIPPF_SAMPLE_ANCHOR_WINDOWS_EXE";

static uint32_t mix_value(uint32_t value) {
  uint32_t acc = value * 33u + 7u;
  if ((acc & 1u) == 0u) {
    acc ^= 0xA5A5A5A5u;
  } else {
    acc += 0x1021u;
  }
  return (acc << 3u) ^ (acc >> 2u);
}

int main(void) {
  const uint32_t result = mix_value(17u);
  if ((result & 3u) == 0u) {
    puts(kAnchorWindowsExe);
  } else {
    printf("%s:%u\n", kAnchorWindowsExe, result);
  }
  return (int)(result & 0x7u);
}
