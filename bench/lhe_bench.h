#include <fstream>
#include <iostream>
#include <ostream>

#include "benchmark/benchmark.h"
#include "lhe25519.h"

namespace bench {

void precompute() {
  std::string filename = "decrypt_table.dat";
  std::ifstream f(filename.c_str());
  if (!f.good()) {
    LHE25519 scheme;
    std::cout<<"precomputing..."<<"\n";
    scheme.precompute_decrypt_table();
    std::ofstream ofs(filename.c_str(),
                      std::ofstream::out | std::ofstream::binary);
    scheme.save_table(ofs);
    ofs.close();
  } else {
    std::cout << "!file exists!"
              << "\n";
  }
}

}  // namespace bench