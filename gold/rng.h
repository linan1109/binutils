//===----------------------------------------------------------------------===//
//
//  This RNG is based on the RNG class used in the Multicompiler project.
//
//  Copyright (C) 2016 Immunant, Inc.
//
//===----------------------------------------------------------------------===//

#ifndef RANDOMNUMBERGENERATOR_H_
#define RANDOMNUMBERGENERATOR_H_

#include <string>
#include <vector>

#if HAVE_LIBCRYPTO
#include <openssl/aes.h>
#endif

#define AES_KEY_LENGTH 16 // bytes
#define AES_BLOCK_SIZE 16
#define PBKDF_ITERATIONS 1000

namespace gold
{

/* Random number generator based on either the AES block cipher from
 * openssl or an integrated linear congruential generator. DO NOT use
 * the LCG for any security application.
 */
class RandomNumberGenerator {
private:
  void Initialize(uint64_t Seed, std::string Salt);

  /** Imports state file from disk */
  void ReadStateFile(std::string StateFilename);

  /** Writes current RNG state to disk */
  void WriteStateFile(std::string StateFilename);

  void Reseed(uint64_t Seed, std::string Salt);

  // Internal state
#if HAVE_LIBCRYPTO
  unsigned char IV[AES_BLOCK_SIZE];
  AES_KEY AESKey;
  unsigned char Key[AES_KEY_LENGTH];
  unsigned char EcountBuffer[AES_BLOCK_SIZE];
  unsigned int Num;
  unsigned char Plaintext[AES_KEY_LENGTH];
#else
  uint64_t state;
#endif

public:
  RandomNumberGenerator(std::string Salt);
  RandomNumberGenerator(uint64_t Seed, std::string Salt);

  uint64_t Random();
  uint64_t Random(uint64_t Max);

  // This function is DEPRECATED! Do not use unless you have NO access to a
  // Module to call createRNG() with.
  static RandomNumberGenerator& Generator() {
    static RandomNumberGenerator instance("");
    return instance;
  };

  /**
   * Shuffles an *array* of type T.
   *
   * Uses the Durstenfeld version of the Fisher-Yates method (aka the Knuth
   * method).  See http://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle
   */
  template<typename T>
  void shuffle(T* array, size_t length) {
    if (length == 0) return;
    for (size_t i = length - 1; i > 0; i--) {
      size_t j = Random(i + 1);
      if (j < i)
        std::swap(array[j], array[i]);
    }
  }

  /**
   * Shuffles a Vector of type T
   */
  template<typename T>
  void shuffle(std::vector<T>& v) {
    if (v.empty()) return;
    for (size_t i = v.size() - 1; i > 0; i--) {
      size_t j = Random(i + 1);
      if (j < i)
        std::swap(v[j], v[i]);
    }
  }

  /**
   * Shuffles a random-access iterator
   */
  template<class RandomIt>
  void shuffle(RandomIt first, RandomIt last) {
    typename std::iterator_traits<RandomIt>::difference_type i, n;
    n = last - first;
    for (i = n-1; i > 0; --i) {
      size_t j = Random(i + 1);
      if (j < i)
        std::swap(first[j], first[i]);
    }
  }
};


}

#endif
