#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

extern int eippf_rg0(void);

static const char kAnchorWindowsExe[] = "EIPPF_SAMPLE_ANCHOR_WINDOWS_EXE";

static void sleep_if_requested(void) {
  const char* value = getenv("EIPPF_SAMPLE_HOLD_MS");
  if (value == NULL || *value == '\0') {
    return;
  }

  const long hold_ms = strtol(value, NULL, 10);
  if (hold_ms <= 0) {
    return;
  }

  Sleep((DWORD)hold_ms);
}

static uint32_t mix_value(uint32_t value) {
  uint32_t acc = value * 33u + 7u;
  if ((acc & 1u) == 0u) {
    acc ^= 0xA5A5A5A5u;
  } else {
    acc += 0x1021u;
  }
  return (acc << 3u) ^ (acc >> 2u);
}

static uint32_t run_workload(uint32_t seed) {
  uint32_t acc = seed;
  for (uint32_t i = 0; i < 3000000u; ++i) {
    acc = mix_value(acc ^ (i * 17u + 3u));
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
  const uint32_t result = run_workload(17u);
  if ((result & 3u) == 0u) {
    puts(kAnchorWindowsExe);
  } else {
    printf("%s:%u\n", kAnchorWindowsExe, result);
  }
  return 0;
}
