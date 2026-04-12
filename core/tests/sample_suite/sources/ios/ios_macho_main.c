#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern int eippf_rg0(void);

static const char kAnchorIosMacho[] = "EIPPF_SAMPLE_ANCHOR_IOS_MACHO";

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

static uint32_t ios_mix(uint32_t value) {
  uint32_t acc = value * 15u + 1u;
  if ((acc & 2u) != 0u) {
    acc ^= 0x0F0F55AAu;
  } else {
    acc += 0x2Bu;
  }
  return acc ^ (uint32_t)kAnchorIosMacho[9];
}

static uint32_t run_workload(uint32_t seed) {
  uint32_t acc = seed;
  for (uint32_t i = 0; i < 3000000u; ++i) {
    acc = ios_mix(acc ^ (i * 11u + 5u));
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
  const uint32_t result = run_workload(23u);
  printf("%s:%u\n", kAnchorIosMacho, result);
  return 0;
}
