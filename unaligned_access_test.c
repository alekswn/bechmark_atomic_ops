#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/mman.h>

#define M (4294967291) //2^32 - 5
#define A (1588635695)

#define XSTR(s) STR(s)
#define STR(s) #s
#define SHIFT(_x_) ((A*_x_)%M)
#define RUN_TIMED_LOOP(_seed_, _statement_)\
  {\
    printf("'%s'", XSTR(_statement_));\
    uint64_t _tstart_ = clock_gettime_nsec_np(CLOCK_MONOTONIC);\
    for (uint32_t _offset_ = SHIFT(_seed_); _offset_!=_seed_; _offset_ = SHIFT(_offset_)) {\
      _statement_;\
    }\
    uint64_t _tdiff_ = clock_gettime_nsec_np(CLOCK_MONOTONIC) - _tstart_;\
    printf(" took %llu.%09llu seconds\n", _tdiff_/1000000000, _tdiff_%1000000000);\
  }

void * allocate(size_t size, uint32_t seed) {
  void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  assert(p);
  char* cp = (char*)p;
  char xor = 0;
  while(size--) {
    *cp = seed%0xff;
    xor ^= *cp;
    seed = SHIFT(seed);
    cp++;
  }
  printf("XOR: %hhx\n", xor);
  return p;
}

void run_test_with_seed(uint32_t seed, const void* chunk4GB) {
  printf("Running tests with seed %u\n", seed);
  RUN_TIMED_LOOP(seed, )
  size_t count = 0;
  RUN_TIMED_LOOP(seed, count++)
  printf("COUNT: %zu\n", count);
  char ch = 0;
  char* chunk4GB_bytes = (char*) chunk4GB;
  RUN_TIMED_LOOP(seed, ch |= chunk4GB_bytes[_offset_])
  printf("OR: %hhx\n", ch);
  ch = 0;
  RUN_TIMED_LOOP(seed, ch ^= chunk4GB_bytes[_offset_])
  printf("XOR: %hhx\n", ch);
  uint64_t u64 = 0;
  uint64_t* chunk4GB_64bit_words = (uint64_t*) chunk4GB;
  RUN_TIMED_LOOP(seed, u64 ^= chunk4GB_64bit_words[_offset_/8])
  printf("XOR: %llx\n", u64);
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_1byte = (uint64_t*)(chunk4GB+1);
  RUN_TIMED_LOOP(seed, u64 ^= chunk4GB_64bit_words_shift_1byte[_offset_/8])
  printf("XOR: %llx\n", u64);
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_2bytes = (uint64_t*)(chunk4GB+1);
  RUN_TIMED_LOOP(seed, u64 ^= chunk4GB_64bit_words_shift_2bytes[_offset_/8])
  printf("XOR: %llx\n", u64);
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_4bytes = (uint64_t*)(chunk4GB+1);
  RUN_TIMED_LOOP(seed, u64 ^= chunk4GB_64bit_words_shift_4bytes[_offset_/8])
  printf("XOR: %llx\n", u64);
  ch=0;
  RUN_TIMED_LOOP(seed, ch ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_RELAXED))
  printf("XOR: %hhx\n", ch);
}

int main(int argc, char* argv[]) {
  printf("Allocating and filling 4 GB chunk on heap...\n");
  void* chunk4GB = allocate((size_t)(UINT32_MAX)+4, 42);
  if (argc == 1) {
    run_test_with_seed(42, chunk4GB);
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    run_test_with_seed(((uintptr_t)argv[i]), chunk4GB);
  }

  return 0;
}