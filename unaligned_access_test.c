#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>

#define M (4294967291) //2^32 - 5
#define A (1588635695)
#define THREAD_NUM (10)
#define MAX_THREAD_NAME (10)

#define XSTR(s) STR(s)
#define STR(s) #s
#define SHIFT(_x_) ((A*_x_)%M)
#define RUN_TIMED_LOOP(_thread_name_, _seed_, _statement_, _aggregator_)\
  {\
    uint64_t _tstart_ = clock_gettime_nsec_np(CLOCK_MONOTONIC);\
    for (uint32_t _offset_ = SHIFT(_seed_); _offset_!=_seed_; _offset_ = SHIFT(_offset_)) {\
      _statement_;\
    }\
    uint64_t _tdiff_ = clock_gettime_nsec_np(CLOCK_MONOTONIC) - _tstart_;\
    printf("%s: '%s' %s = %llx, took %llu.%09llu seconds, \n", _thread_name_, XSTR(_statement_), XSTR(_aggregator_), (unsigned long long)_aggregator_, _tdiff_/1000000000, _tdiff_%1000000000);\
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

void run_test_with_seed(const char* thread_name, uint32_t seed, const void* chunk4GB) {
  printf("%s: Running tests with seed %u\n", thread_name, seed);
  RUN_TIMED_LOOP(thread_name, seed, , 0)
  size_t count = 0;
  RUN_TIMED_LOOP(thread_name, seed, count++, count)
  char ch = 0;
  char* chunk4GB_bytes = (char*) chunk4GB;
  RUN_TIMED_LOOP(thread_name, seed, ch |= chunk4GB_bytes[_offset_], ch)
  ch = 0;
  RUN_TIMED_LOOP(thread_name, seed, ch ^= chunk4GB_bytes[_offset_], ch)
  uint64_t u64 = 0;
  uint64_t* chunk4GB_64bit_words = (uint64_t*) chunk4GB;
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words[_offset_/8], u64)
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_1byte = (uint64_t*)(chunk4GB+1);
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_1byte[_offset_/8], u64)
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_2bytes = (uint64_t*)(chunk4GB+2);
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_2bytes[_offset_/8], u64)
  u64=0;
  uint64_t* chunk4GB_64bit_words_shift_4bytes = (uint64_t*)(chunk4GB+4);
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_4bytes[_offset_/8], u64)
  ch=0;
  RUN_TIMED_LOOP(thread_name, seed, ch ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_RELAXED), ch)
}

struct thread_info {
  pthread_t thread_id;
  char thread_name[MAX_THREAD_NAME];
  uint32_t seed;
  const void* chunk;
};

static void* run_test_with_seed_thrd_wrapper(void* tinfo) {
  struct thread_info* args = (struct thread_info*)tinfo;
  run_test_with_seed(args->thread_name, args->seed, args->chunk);
  return NULL;
}

void run_tests_with_seed(uint32_t seed, const void* chunk) {
  run_test_with_seed("main", seed, chunk);

  pthread_attr_t tattr;
  assert(pthread_attr_init(&tattr) == 0);
  struct thread_info tinfo[THREAD_NUM];
  for (size_t tnum = 0; tnum < THREAD_NUM; tnum++) {
    assert(snprintf(tinfo[tnum].thread_name, MAX_THREAD_NAME, "Thread %zu", tnum) > 0);
    tinfo[tnum].seed = seed;
    tinfo[tnum].chunk = chunk;
    assert(pthread_create(&tinfo[tnum].thread_id, &tattr, &run_test_with_seed_thrd_wrapper, &tinfo[tnum]) == 0);
  }
  assert(pthread_attr_destroy(&tattr) == 0);
  for (size_t tnum = 0; tnum < THREAD_NUM; tnum++) {
    assert(pthread_join(tinfo[tnum].thread_id, NULL) == 0);
  }
}

int main(int argc, char* argv[]) {
  setlinebuf(stdout);
  printf("Allocating and filling 4 GB chunk on heap...\n");
  void* chunk4GB = allocate((size_t)(UINT32_MAX)+4, 42);
  if (argc == 1) {
    run_tests_with_seed(42, chunk4GB);
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    run_tests_with_seed(((uintptr_t)argv[i]), chunk4GB);
  }

  return 0;
}