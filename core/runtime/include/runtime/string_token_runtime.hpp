#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

void eippf_string_token_decode(std::uint8_t* dest, const std::uint8_t* src, std::size_t size,
                               std::uint8_t key);

void eippf_string_token_wipe(std::uint8_t* data, std::size_t size);

}  // extern "C"
