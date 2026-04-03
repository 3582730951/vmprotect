#include "post_link_mutator/binary_io.hpp"

#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

namespace eippf::post_link_mutator {

bool ensure_parent_exists(const std::filesystem::path& path) {
  const std::filesystem::path parent = path.parent_path();
  if (parent.empty()) {
    return true;
  }
  std::error_code ec;
  std::filesystem::create_directories(parent, ec);
  return !ec;
}

std::filesystem::path pre_eippf_backup_path(const std::filesystem::path& output_path) {
  if (output_path.empty()) {
    return {};
  }
  return std::filesystem::path(output_path.string() + ".pre_eippf");
}

bool read_binary_file(const std::filesystem::path& path, std::vector<std::uint8_t>& data_out) {
  std::ifstream input(path, std::ios::binary);
  if (!input.is_open()) {
    return false;
  }
  data_out.assign(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
  return static_cast<bool>(input) || input.eof();
}

bool write_binary_file(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
  if (!ensure_parent_exists(path)) {
    return false;
  }
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output.is_open()) {
    return false;
  }
  if (!data.empty()) {
    output.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  return static_cast<bool>(output);
}

}  // namespace eippf::post_link_mutator
