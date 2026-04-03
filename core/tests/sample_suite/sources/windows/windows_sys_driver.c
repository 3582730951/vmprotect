#include <stdint.h>

typedef long NTSTATUS;
typedef void* PDRIVER_OBJECT;
typedef void* PUNICODE_STRING;

#define STATUS_SUCCESS ((NTSTATUS)0L)

#if defined(_WIN32)
#define EIPPF_DRIVER_EXPORT __declspec(dllexport)
#else
#define EIPPF_DRIVER_EXPORT
#endif

static const char kAnchorWindowsSys[] = "EIPPF_SAMPLE_ANCHOR_WINDOWS_SYS";

static uint32_t driver_mix(uint32_t seed) {
  uint32_t value = (seed ^ 0xD00DFEEDu) + 19u;
  if ((value & 4u) != 0u) {
    value = (value << 1u) ^ 0x1F123BB5u;
  } else {
    value = (value >> 1u) + 0x221u;
  }
  value ^= (uint32_t)kAnchorWindowsSys[7];
  return value;
}

EIPPF_DRIVER_EXPORT NTSTATUS DriverEntry(PDRIVER_OBJECT driver_object,
                                         PUNICODE_STRING registry_path) {
  const uintptr_t folded = (uintptr_t)driver_object ^ (uintptr_t)registry_path;
  volatile uint32_t guard = driver_mix((uint32_t)(folded & 0xFFFFFFFFu));
  (void)guard;
  return STATUS_SUCCESS;
}
