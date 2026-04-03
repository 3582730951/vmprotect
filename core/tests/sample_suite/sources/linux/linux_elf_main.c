#include <stdint.h>
#include <stdio.h>

static const char kAnchorLinuxElf[] = "EIPPF_SAMPLE_ANCHOR_LINUX_ELF";

static uint32_t elf_mix(uint32_t value) {
  uint32_t acc = (value * 9u) + 23u;
  if ((acc % 3u) == 0u) {
    acc ^= 0x44AA11CCu;
  } else {
    acc += 0x55u;
  }
  return (acc << 2u) | (acc >> 30u);
}

int main(void) {
  const uint32_t result = elf_mix(29u);
  printf("%s:%u\n", kAnchorLinuxElf, result);
  return (int)(result & 0x3u);
}
