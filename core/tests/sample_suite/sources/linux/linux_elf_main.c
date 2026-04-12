#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int eippf_rg0(void);

static const char kAnchorLinuxElf[] = "EIPPF_SAMPLE_ANCHOR_LINUX_ELF";

static void sleep_if_requested(void) {
  const char* value = getenv("EIPPF_SAMPLE_HOLD_MS");
  if (value == NULL || *value == '\0') {
    return;
  }

  const long hold_ms = strtol(value, NULL, 10);
  if (hold_ms <= 0) {
    return;
  }

  usleep((useconds_t)hold_ms * 1000u);
}

static uint32_t elf_mix(uint32_t value) {
  uint32_t acc = (value * 9u) + 23u;
  if ((acc % 3u) == 0u) {
    acc ^= 0x44AA11CCu;
  } else {
    acc += 0x55u;
  }
  return (acc << 2u) | (acc >> 30u);
}

static uint32_t run_workload(uint32_t seed) {
  uint32_t acc = seed;
  for (uint32_t i = 0; i < 3000000u; ++i) {
    acc = elf_mix(acc ^ (i * 13u + 7u));
  }
  return acc;
}

int main(void) {
  if (eippf_rg0() == 0) {
    return 120;
  }
  sleep_if_requested();
  if (eippf_rg0() == 0) {
    return 120;
  }
  const uint32_t result = run_workload(29u);
  printf("%s:%u\n", kAnchorLinuxElf, result);
  return 0;
}
