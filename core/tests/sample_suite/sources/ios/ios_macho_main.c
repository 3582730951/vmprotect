#include <stdint.h>
#include <stdio.h>

static const char kAnchorIosMacho[] = "EIPPF_SAMPLE_ANCHOR_IOS_MACHO";

static uint32_t ios_mix(uint32_t value) {
  uint32_t acc = value * 15u + 1u;
  if ((acc & 2u) != 0u) {
    acc ^= 0x0F0F55AAu;
  } else {
    acc += 0x2Bu;
  }
  return acc ^ (uint32_t)kAnchorIosMacho[9];
}

int main(void) {
  const uint32_t result = ios_mix(23u);
  printf("%s:%u\n", kAnchorIosMacho, result);
  return (int)(result & 0x3u);
}
