#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sys/mman.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

#define M (4294967291) //2^32 - 5
#define A (1588635695)
#define THREAD_NUM (10)
#define MAX_THREAD_NAME (10)
#define CHUNK_SIZE ((size_t)(UINT32_MAX)+8)

#define XSTR(s) STR(s)
#define STR(s) #s
#define SHIFT(_x_) ((A*_x_)%M)

struct sync_context {
    const size_t total_count;
    size_t current_count;
    size_t generation;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};


static uint64_t clock_get_nsec() {
  struct timespec  ts;
  assert(clock_gettime(CLOCK_MONOTONIC, &ts)!=-1);
  return (uint64_t)(ts.tv_sec)*1000000000ULL + (uint64_t)(ts.tv_nsec);
}

#define MAKE_SYNC_CONTEXT(_thread_number) (struct sync_context){_thread_number, 0, 0, PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER}
#define SYNC_THREADS(_sync_context_ptr, _leader_statement)\
  {\
    assert(pthread_mutex_lock(&_sync_context_ptr->mutex) == 0);\
    if (++_sync_context_ptr->current_count == _sync_context_ptr->total_count) {\
      _leader_statement;\
      _sync_context_ptr->current_count = 0;\
      _sync_context_ptr->generation++;\
      assert(pthread_cond_broadcast(&_sync_context_ptr->cond) == 0);\
    } else {\
      const size_t current_generation = _sync_context_ptr->generation;\
      do {\
        assert(pthread_cond_wait(&_sync_context_ptr->cond, &_sync_context_ptr->mutex) == 0);\
      } while(_sync_context_ptr->generation == current_generation);\
    }\
    assert(pthread_mutex_unlock(&sync_context_ptr->mutex) == 0);\
  }

#define RUN_TIMED_LOOP(_thread_name_, _seed_, _test_statement_, _aggregator_, _sync_context_ptr, _setup_statement_)\
  {\
    SYNC_THREADS(_sync_context_ptr, _setup_statement_);\
    uint64_t _tstart_ = clock_get_nsec();\
    _aggregator_ = 0;\
    for (uint32_t _offset_ = SHIFT(_seed_); _offset_!=_seed_; _offset_ = SHIFT(_offset_)) {\
      _test_statement_;\
    }\
    uint64_t _tdiff_ = clock_get_nsec() - _tstart_;\
    printf("%s: '%s' %s = %llx, took %llu.%09llu seconds, \n", _thread_name_, XSTR(_test_statement_), XSTR(_aggregator_), (unsigned long long)_aggregator_, _tdiff_/1000000000, _tdiff_%1000000000);\
  }

#define NOOP

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

void zero_out_chunk(void* chunk) {
  memset(chunk, 0, CHUNK_SIZE);
}

void run_test_with_seed(const char* thread_name, struct sync_context* sync_context_ptr, uint32_t seed, void* chunk4GB) {
  printf("%s: Running tests with seed %u\n", thread_name, seed);
  size_t count; uint8_t u8; uint32_t u32; uint64_t u64; //agregators

  //arrays
  char* chunk4GB_bytes = (char*) chunk4GB;
  uint32_t* chunk4GB_32bit_words = (uint32_t*) chunk4GB;
  uint32_t* chunk4GB_32bit_words_shift_1byte = (uint32_t*)(chunk4GB+1);
  uint32_t* chunk4GB_32bit_words_shift_2bytes = (uint32_t*)(chunk4GB+2);
  uint64_t* chunk4GB_64bit_words = (uint64_t*) chunk4GB;
  uint64_t* chunk4GB_64bit_words_shift_1byte = (uint64_t*)(chunk4GB+1);
  uint64_t* chunk4GB_64bit_words_shift_2bytes = (uint64_t*)(chunk4GB+2);
  uint64_t* chunk4GB_64bit_words_shift_4bytes = (uint64_t*)(chunk4GB+4);

  //dry-runs
  RUN_TIMED_LOOP(thread_name, seed, NOOP, count, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, count++, count, sync_context_ptr, NOOP)

  //byte read
  RUN_TIMED_LOOP(thread_name, seed, u8 |= chunk4GB_bytes[_offset_], u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 ^= chunk4GB_bytes[_offset_], u8, sync_context_ptr, NOOP)

  //32-bit word read
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= chunk4GB_32bit_words[_offset_/4], u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= chunk4GB_32bit_words_shift_1byte[_offset_/4], u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= chunk4GB_32bit_words_shift_2bytes[_offset_/4], u32, sync_context_ptr, NOOP)

  //64-bit word read
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words[_offset_/8], u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_1byte[_offset_/8], u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_2bytes[_offset_/8], u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= chunk4GB_64bit_words_shift_4bytes[_offset_/8], u64, sync_context_ptr, NOOP)

  //atomic byte load
  RUN_TIMED_LOOP(thread_name, seed, u8 ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_RELAXED), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_SEQ_CST), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_ACQUIRE), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 ^= __atomic_load_n(chunk4GB_bytes + _offset_, __ATOMIC_CONSUME), u8, sync_context_ptr, NOOP)

  //atomic 32-bit word load
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words + _offset_/4, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words + _offset_/4, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words + _offset_/4, __ATOMIC_ACQUIRE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words + _offset_/4, __ATOMIC_CONSUME), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, __ATOMIC_ACQUIRE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, __ATOMIC_CONSUME), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, __ATOMIC_ACQUIRE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 ^= __atomic_load_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, __ATOMIC_CONSUME), u32, sync_context_ptr, NOOP)

  //atomic 64-bit word load
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words + _offset_/8, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words + _offset_/8, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words + _offset_/8, __ATOMIC_ACQUIRE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words + _offset_/8, __ATOMIC_CONSUME), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, __ATOMIC_ACQUIRE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, __ATOMIC_CONSUME), u64, sync_context_ptr, NOOP)
#endif
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, __ATOMIC_ACQUIRE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, __ATOMIC_CONSUME), u64, sync_context_ptr, NOOP)
#endif
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, __ATOMIC_ACQUIRE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 ^= __atomic_load_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, __ATOMIC_CONSUME), u64, sync_context_ptr, NOOP)
#endif

  //atomic byte store
  RUN_TIMED_LOOP(thread_name, seed, u8 = SHIFT(u8+1); __atomic_store_n(chunk4GB_bytes + _offset_, u8, __ATOMIC_RELAXED), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 = SHIFT(u8+2); __atomic_store_n(chunk4GB_bytes + _offset_, u8, __ATOMIC_SEQ_CST), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 = SHIFT(u8+3); __atomic_store_n(chunk4GB_bytes + _offset_, u8, __ATOMIC_RELEASE), u8, sync_context_ptr, NOOP)

  //atomic 32-bit word store
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+4); __atomic_store_n(chunk4GB_32bit_words + _offset_/4, u32, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+5); __atomic_store_n(chunk4GB_32bit_words + _offset_/4, u32, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+6); __atomic_store_n(chunk4GB_32bit_words + _offset_/4, u32, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+7); __atomic_store_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+8); __atomic_store_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+9); __atomic_store_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+10); __atomic_store_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+11); __atomic_store_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = SHIFT(u32+12); __atomic_store_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)

  //atomic 64-bit word store
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+13); __atomic_store_n(chunk4GB_64bit_words + _offset_/8, u64, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+14); __atomic_store_n(chunk4GB_64bit_words + _offset_/8, u64, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+15); __atomic_store_n(chunk4GB_64bit_words + _offset_/8, u64, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+16); __atomic_store_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+17); __atomic_store_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+18); __atomic_store_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
#endif
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+19); __atomic_store_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+20); __atomic_store_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+21); __atomic_store_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
#endif
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+22); __atomic_store_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+23); __atomic_store_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = SHIFT(u64+24); __atomic_store_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
#endif

  //atomic byte excahange
  RUN_TIMED_LOOP(thread_name, seed, u8 = __atomic_exchange_n(chunk4GB_bytes + _offset_, u8+23, __ATOMIC_RELAXED), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 = __atomic_exchange_n(chunk4GB_bytes + _offset_, u8+24, __ATOMIC_SEQ_CST), u8, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u8 = __atomic_exchange_n(chunk4GB_bytes + _offset_, u8+25, __ATOMIC_RELEASE), u8, sync_context_ptr, NOOP)

  //atomic 32-bit word exchange
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words + _offset_/4, u32+26, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words + _offset_/4, u32+27, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words + _offset_/4, u32+28, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32+29, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32+30, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, u32+31, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32+32, __ATOMIC_RELAXED), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32+33, __ATOMIC_SEQ_CST), u32, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u32 = __atomic_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, u32+34, __ATOMIC_RELEASE), u32, sync_context_ptr, NOOP)

  //atomic 64-bit word exchange
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words + _offset_/8, u64+35, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words + _offset_/8, u64+36, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words + _offset_/8, u64+37, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64+38, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64+39, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, u64+40, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64+41, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64+42, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, u64+43, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64+44, __ATOMIC_RELAXED), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64+45, __ATOMIC_SEQ_CST), u64, sync_context_ptr, NOOP)
  RUN_TIMED_LOOP(thread_name, seed, u64 = __atomic_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, u64+46, __ATOMIC_RELEASE), u64, sync_context_ptr, NOOP)
#endif

  //atomic byte compare-and-exchange
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u8, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, char t = 0; __atomic_compare_exchange_n(chunk4GB_bytes + _offset_, &t, u8 = SHIFT(u8+47)%0xff, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u8, sync_context_ptr, zero_out_chunk(chunk4GB));

  //atomic 32bit word compare-and-exchange
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));

  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_1byte + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));

  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint32_t t = 0; __atomic_compare_exchange_n(chunk4GB_32bit_words_shift_2bytes + _offset_/4, &t, u32 = SHIFT(u32+47)%0xffffffff, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u32, sync_context_ptr, zero_out_chunk(chunk4GB));

  //atomic 64bit word compare-and-exchange
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));

#ifndef __APPLE__//Crushes with `EXC_BAD_ACCESS (code=257, address=0x2e2e04a69)` on Apple M2
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_1byte + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));

  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_2bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));

  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_RELAXED, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_ACQUIRE, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_RELAXED), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_ACQUIRE), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), true, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
  RUN_TIMED_LOOP(thread_name, seed, uint64_t t = 0; __atomic_compare_exchange_n(chunk4GB_64bit_words_shift_4bytes + _offset_/8, &t, u64 = SHIFT(u64+47), false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST), u64, sync_context_ptr, zero_out_chunk(chunk4GB));
#endif
}

struct thread_info {
  pthread_t thread_id;
  char thread_name[MAX_THREAD_NAME];
  struct sync_context* sync_context_ptr;
  uint32_t seed;
  void* chunk;
};

static void* run_test_with_seed_thrd_wrapper(void* tinfo) {
  struct thread_info* args = (struct thread_info*)tinfo;
  run_test_with_seed(args->thread_name, args->sync_context_ptr, args->seed, args->chunk);
  return NULL;
}

void run_test_with_seed_in_threads(uint32_t seed, void* chunk) {
  pthread_attr_t tattr;
  assert(pthread_attr_init(&tattr) == 0);
  struct thread_info tinfo[THREAD_NUM];
  struct sync_context sync_context = MAKE_SYNC_CONTEXT(THREAD_NUM);
  for (size_t tnum = 0; tnum < THREAD_NUM; tnum++) {
    assert(snprintf(tinfo[tnum].thread_name, MAX_THREAD_NAME, "Thread %zu", tnum) > 0);
    tinfo[tnum].seed = seed;
    tinfo[tnum].chunk = chunk;
    tinfo[tnum].sync_context_ptr = &sync_context;
    assert(pthread_create(&tinfo[tnum].thread_id, &tattr, &run_test_with_seed_thrd_wrapper, &tinfo[tnum]) == 0);
  }
  for (size_t tnum = 0; tnum < THREAD_NUM; tnum++) {
    assert(pthread_join(tinfo[tnum].thread_id, NULL) == 0);
  }
  assert(pthread_attr_destroy(&tattr) == 0);
}

void run_tests_with_seed(uint32_t seed, void* chunk) {
  struct sync_context lonely_thread_context = MAKE_SYNC_CONTEXT(1);
  run_test_with_seed("main", &lonely_thread_context, seed, chunk);
  run_test_with_seed_in_threads(seed, chunk);
}

int main(int argc, char* argv[]) {
  setlinebuf(stdout);
  printf("Allocating and filling 4 GB chunk on heap...\n");
  void* chunk4GB = allocate(CHUNK_SIZE, 42);
  if (argc == 1) {
    run_tests_with_seed(42, chunk4GB);
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    run_tests_with_seed(((uintptr_t)argv[i]), chunk4GB);
  }

  return 0;
}