#include "post_link_mutator/artifact_detector.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <string>

namespace eippf::post_link_mutator {
namespace {

using eippf::contracts::ArtifactKind;

[[nodiscard]] std::array<std::uint8_t, 4u> read_magic(std::ifstream& stream) {
  std::array<std::uint8_t, 4u> magic{0u, 0u, 0u, 0u};
  stream.seekg(0, std::ios::beg);
  stream.read(reinterpret_cast<char*>(magic.data()), static_cast<std::streamsize>(magic.size()));
  return magic;
}

[[nodiscard]] bool is_pe_file(std::ifstream& stream, const std::array<std::uint8_t, 4u>& magic) {
  if (magic[0] != static_cast<std::uint8_t>('M') || magic[1] != static_cast<std::uint8_t>('Z')) {
    return false;
  }

  stream.seekg(0x3c, std::ios::beg);
  std::array<std::uint8_t, 4u> pe_offset_bytes{0u, 0u, 0u, 0u};
  stream.read(reinterpret_cast<char*>(pe_offset_bytes.data()),
              static_cast<std::streamsize>(pe_offset_bytes.size()));
  if (stream.gcount() != 4) {
    return true;
  }

  const std::uint32_t pe_offset = static_cast<std::uint32_t>(pe_offset_bytes[0]) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[1]) << 8u) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[2]) << 16u) |
                                  (static_cast<std::uint32_t>(pe_offset_bytes[3]) << 24u);
  stream.seekg(static_cast<std::streamoff>(pe_offset), std::ios::beg);
  std::array<std::uint8_t, 4u> pe_sig{0u, 0u, 0u, 0u};
  stream.read(reinterpret_cast<char*>(pe_sig.data()), static_cast<std::streamsize>(pe_sig.size()));
  if (stream.gcount() != 4) {
    return true;
  }
  return pe_sig[0] == static_cast<std::uint8_t>('P') &&
         pe_sig[1] == static_cast<std::uint8_t>('E') && pe_sig[2] == 0u && pe_sig[3] == 0u;
}

[[nodiscard]] bool is_elf_file(const std::array<std::uint8_t, 4u>& magic) {
  return magic[0] == 0x7fu && magic[1] == static_cast<std::uint8_t>('E') &&
         magic[2] == static_cast<std::uint8_t>('L') && magic[3] == static_cast<std::uint8_t>('F');
}

[[nodiscard]] bool is_macho_magic(std::uint32_t magic) {
  return magic == 0xFEEDFACEu || magic == 0xCEFAEDFEu || magic == 0xFEEDFACFu ||
         magic == 0xCFFAEDFEu || magic == 0xCAFEBABEu || magic == 0xBEBAFECAu ||
         magic == 0xCAFEBABFu || magic == 0xBFBAFECAu;
}

[[nodiscard]] std::string lower_copy(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
    return static_cast<char>(std::tolower(ch));
  });
  return value;
}

template <std::size_t Size>
[[nodiscard]] std::array<std::uint8_t, Size> read_prefix(std::ifstream& stream) {
  std::array<std::uint8_t, Size> bytes{};
  stream.clear();
  stream.seekg(0, std::ios::beg);
  stream.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
  return bytes;
}

[[nodiscard]] bool is_valid_dex_header(std::ifstream& stream) {
  const std::array<std::uint8_t, 8u> bytes = read_prefix<8u>(stream);
  if (stream.gcount() != 8) {
    return false;
  }
  if (bytes[0] != static_cast<std::uint8_t>('d') ||
      bytes[1] != static_cast<std::uint8_t>('e') ||
      bytes[2] != static_cast<std::uint8_t>('x') ||
      bytes[3] != static_cast<std::uint8_t>('\n')) {
    return false;
  }
  if (!std::isdigit(bytes[4]) || !std::isdigit(bytes[5]) || !std::isdigit(bytes[6])) {
    return false;
  }
  return bytes[7] == static_cast<std::uint8_t>('\0');
}

[[nodiscard]] bool is_valid_shell_shebang(std::ifstream& stream) {
  const std::array<std::uint8_t, 2u> bytes = read_prefix<2u>(stream);
  if (stream.gcount() != 2) {
    return false;
  }
  return bytes[0] == static_cast<std::uint8_t>('#') &&
         bytes[1] == static_cast<std::uint8_t>('!');
}

[[nodiscard]] ArtifactKind detect_from_input_suffix(std::ifstream& stream,
                                                    const std::filesystem::path& input_path) {
  if (input_path.empty()) {
    return ArtifactKind::kUnknown;
  }
  const std::string ext = lower_copy(input_path.extension().string());
  if (ext == ".dex") {
    return is_valid_dex_header(stream) ? ArtifactKind::kDex : ArtifactKind::kUnknown;
  }
  if (ext == ".sh") {
    return is_valid_shell_shebang(stream) ? ArtifactKind::kShellBundle : ArtifactKind::kUnknown;
  }
  return ArtifactKind::kUnknown;
}

}  // namespace

ArtifactKind detect_base_artifact_kind(const std::filesystem::path& input_path,
                                       const std::filesystem::path& output_path) {
  static_cast<void>(output_path);
  std::ifstream input(input_path, std::ios::binary);
  if (input) {
    const std::array<std::uint8_t, 4u> magic = read_magic(input);
    if (is_elf_file(magic)) {
      return ArtifactKind::kElf;
    }
    if (is_pe_file(input, magic)) {
      return ArtifactKind::kPe;
    }

    const std::uint32_t magic_u32 = static_cast<std::uint32_t>(magic[0]) << 24u |
                                    static_cast<std::uint32_t>(magic[1]) << 16u |
                                    static_cast<std::uint32_t>(magic[2]) << 8u |
                                    static_cast<std::uint32_t>(magic[3]);
    if (is_macho_magic(magic_u32)) {
      return ArtifactKind::kMachO;
    }

    return detect_from_input_suffix(input, input_path);
  }

  return ArtifactKind::kUnknown;
}

}  // namespace eippf::post_link_mutator
