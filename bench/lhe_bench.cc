#include "lhe_bench.h"

namespace bench {

static void BM_LoadTable(benchmark::State& state) {
  for (auto _ : state) {
    LHE25519 scheme;

    // Load the precomputed decryption table.
    // The table content is fixed for curve Ed25519,
    // hence it only needs to be precomputed once.
    // We have precomputed this table and submitted it along with the code.
    // You can also use the above "precompute()" function to compute it again,
    // which will produce exactly the same output "decryption_table.dat".
    std::ifstream ifs("decrypt_table.dat",
                      std::ifstream::in | std::ifstream::binary);
    scheme.load_table(ifs);
    ifs.close();
  }
}

static void BM_KeyGen(benchmark::State& state) {
  for (auto _ : state) {
    LHE25519 scheme;
    scheme.key_gen();
  }
}

static void BM_Encrypt(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    state.ResumeTiming();

    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
  }
}

static void BM_Decrypt(benchmark::State& state) {
  LHE25519 scheme;
  std::ifstream ifs("decrypt_table.dat",
                    std::ifstream::in | std::ifstream::binary);
  scheme.load_table(ifs);
  ifs.close();

  for (auto _ : state) {
    state.PauseTiming();
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    state.ResumeTiming();

    int64_t result;
    scheme.decrypt(result, ct1);
  }
}

static void BM_HomAdd(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    Ciphertext ct2;
    scheme.encrypt(ct2, 111111);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_add(ct_result, ct1, ct2);
  }
}

static void BM_HomAddPlain(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    Plaintext pt_x;
    scheme.encode(pt_x, 111111);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_add_plain(ct_result, ct1, pt_x);
  }
}

static void BM_HomSub(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    Ciphertext ct2;
    scheme.encrypt(ct2, 111111);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_sub(ct_result, ct2, ct1);
  }
}

static void BM_HomSubPlain(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    Plaintext pt_x;
    scheme.encode(pt_x, 111111);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_sub_plain(ct_result, ct1, pt_x);
  }
}

static void BM_HomMulPlain(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    Plaintext pt_x;
    scheme.encode(pt_x, 3);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_mul(ct_result, ct1, pt_x);
  }
}

static void BM_HomNegate(benchmark::State& state) {
  for (auto _ : state) {
    state.PauseTiming();
    LHE25519 scheme;
    scheme.key_gen();
    Ciphertext ct1;
    scheme.encrypt(ct1, 555555);
    state.ResumeTiming();

    Ciphertext ct_result;
    scheme.hom_negate(ct_result, ct1);
  }
}

// Register the function as a benchmark
BENCHMARK(BM_LoadTable)->Iterations(1);
BENCHMARK(BM_KeyGen)->Iterations(1000);
BENCHMARK(BM_Encrypt)->Iterations(1000);
BENCHMARK(BM_Decrypt)->Iterations(1);
BENCHMARK(BM_HomAdd)->Iterations(1000);
BENCHMARK(BM_HomAddPlain)->Iterations(1000);
BENCHMARK(BM_HomSub)->Iterations(1000);
BENCHMARK(BM_HomSubPlain)->Iterations(1000);
BENCHMARK(BM_HomMulPlain)->Iterations(1000);
BENCHMARK(BM_HomNegate)->Iterations(1000);
}  // namespace bench

int main(int argc, char** argv) {
  // uncomment if no precomp
  bench::precompute();
  benchmark::Initialize(&argc, argv);
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}