#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

void eippf_sd0(std::uint8_t* dest, const std::uint8_t* src, std::size_t size,
               std::uint8_t key);

void eippf_sw0(std::uint8_t* data, std::size_t size);

int eippf_rg0(void);

}  // extern "C"
