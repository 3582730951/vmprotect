#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace eippf::post_link_mutator {

[[nodiscard]] bool ensure_parent_exists(const std::filesystem::path& path);

[[nodiscard]] std::filesystem::path pre_eippf_backup_path(
    const std::filesystem::path& output_path);

[[nodiscard]] bool read_binary_file(const std::filesystem::path& path,
                                    std::vector<std::uint8_t>& data_out);

[[nodiscard]] bool write_binary_file(const std::filesystem::path& path,
                                     const std::vector<std::uint8_t>& data);

}  // namespace eippf::post_link_mutator
