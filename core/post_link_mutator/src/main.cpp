#include <iostream>

#include "post_link_mutator/mutator_app.hpp"

int main(int argc, char** argv) {
  return eippf::post_link_mutator::run_mutator(argc, argv, std::cout, std::cerr);
}
