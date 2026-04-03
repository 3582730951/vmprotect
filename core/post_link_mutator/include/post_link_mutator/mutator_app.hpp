#pragma once

#include <cstdint>
#include <ostream>

namespace eippf::post_link_mutator {

enum class TestFault : std::uint8_t {
  kNone,
  kForceReadInputFailure,
  kForceBackendUnknown,
  kForceMutationIdentity
};

int run_mutator(int argc, char** argv, std::ostream& out, std::ostream& err);

int run_mutator_with_test_fault(
    int argc,
    char** argv,
    std::ostream& out,
    std::ostream& err,
    TestFault fault);

}  // namespace eippf::post_link_mutator
