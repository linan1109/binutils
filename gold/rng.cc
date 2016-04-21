//===----------------------------------------------------------------------===//
//
//  This RNG is based on the RNG class used in the Multicompiler project.
//
//  Copyright (C) 2016 Immunant, Inc.
//
//===----------------------------------------------------------------------===//

#include "gold.h"
#include "rng.h"
#include "parameters.h"
#include "options.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#if defined(HAVE_UNISTD_H)
# include <unistd.h>
#endif
#if defined(HAVE_FCNTL_H)
# include <fcntl.h>
#endif
#if defined(HAVE_SYS_UIO_H) && defined(HAVE_WRITEV)
#  include <sys/uio.h>
#endif

#if defined(__CYGWIN__)
#include <io.h>
#endif

#if defined(_MSC_VER)
#include <io.h>
#include <fcntl.h>
#ifndef STDIN_FILENO
# define STDIN_FILENO 0
#endif
#ifndef STDOUT_FILENO
# define STDOUT_FILENO 1
#endif
#ifndef STDERR_FILENO
# define STDERR_FILENO 2
#endif
#endif

#if HAVE_LIBCRYPTO
#include <openssl/aes.h>
#include <openssl/evp.h>
#endif


namespace gold
{

#if HAVE_LIBCRYPTO

RandomNumberGenerator::RandomNumberGenerator(std::string Salt) {
  Initialize(parameters->options().random_seed(), Salt);
}

RandomNumberGenerator::RandomNumberGenerator(uint64_t Seed, std::string Salt) {
  Initialize(Seed, Salt);
}

void RandomNumberGenerator::Initialize(uint64_t Seed, std::string Salt) {
  // Initialize temporary buffers for encryption
  memset(EcountBuffer, 0, AES_BLOCK_SIZE);
  Num = 0;

  if (Seed != 0 && !Salt.empty()) {
    // Seed properly
    Reseed(Seed, Salt);

  } else{
    gold_warning("Warning! Using unseeded random number generator\n");

    Reseed(Seed, Salt);
  }
}

void RandomNumberGenerator::Reseed(uint64_t Seed, std::string Salt) {
  unsigned KeyLen = AES_KEY_LENGTH + 2*AES_BLOCK_SIZE;
  unsigned char *RandomBytes = (unsigned char*) malloc(KeyLen);
  PKCS5_PBKDF2_HMAC_SHA1((char*) Salt.data(), Salt.size(),
                         (const unsigned char*)&Seed, sizeof(Seed),
                         PBKDF_ITERATIONS, KeyLen, RandomBytes);

  // TODO(sjcrane): check return val
  memcpy(Key, RandomBytes, AES_KEY_LENGTH);
  AES_set_encrypt_key(Key, AES_KEY_LENGTH*8, &AESKey);
  memcpy(IV, RandomBytes + AES_KEY_LENGTH, AES_BLOCK_SIZE);
  memcpy(Plaintext, RandomBytes + AES_KEY_LENGTH + AES_BLOCK_SIZE, AES_BLOCK_SIZE);

  free(RandomBytes);
}

void RandomNumberGenerator::ReadStateFile(std::string StateFilename) {
  struct stat s;
  /* Don't read if there's no file specified.
   * TODO(tmjackso): This probably shouldn't fail silently. */
  if (StateFilename.empty() || stat(StateFilename.data(), &s) != 0) {
    return;
  }

  int fhandle = open(StateFilename.data(), O_RDONLY);
  int bytes_read = 0;

  uint16_t keylength;

  /* uint16_t: keysize */
  bytes_read += read(fhandle, (char *)&keylength, sizeof(uint16_t));
  gold_assert(keylength == AES_KEY_LENGTH && "Invalid key length");

  /* keylength * uint8_t: key */
  bytes_read += read(fhandle, (char *)Key, AES_KEY_LENGTH);
  
  /* 16 * uint8_t: plaintext */
  bytes_read += read(fhandle, (char *)Plaintext, AES_BLOCK_SIZE);

  /* 8 * uint8_t: IV (nonce+counter) */
  bytes_read += read(fhandle, (char *)IV, AES_BLOCK_SIZE);

  if (bytes_read != s.st_size) {
    // We didn't read the whole file
  }

  close(fhandle);

  // TODO(sjcrane): check return val
  AES_set_encrypt_key(Key, AES_KEY_LENGTH*8, &AESKey);
}

void RandomNumberGenerator::WriteStateFile(std::string StateFilename) {
  /* Don't serialise without a file name */
  gold_assert(!StateFilename.empty() && "Cannot serialize RNG state file without a filename");

  uint16_t keylength = AES_KEY_LENGTH;

  int fhandle = open(StateFilename.data(), O_WRONLY);
  int byte_count = 0;
  byte_count += write(fhandle, (char *)&keylength, sizeof(uint16_t));
  byte_count += write(fhandle, (char *)Key, AES_KEY_LENGTH);
  byte_count += write(fhandle, (char *)Plaintext, AES_BLOCK_SIZE);
  byte_count += write(fhandle, (char *)IV, AES_BLOCK_SIZE);
  close(fhandle);
}

uint64_t RandomNumberGenerator::Random() {
  unsigned char Output[AES_BLOCK_SIZE];
  AES_ctr128_encrypt(Plaintext, Output, AES_BLOCK_SIZE, &AESKey, IV, EcountBuffer, &Num);

  uint64_t OutValue;
  memcpy(&OutValue, Output, sizeof(uint64_t));
  return OutValue;
}

uint64_t RandomNumberGenerator::Random(uint64_t Max) {
  uint64_t t = Max * (((uint64_t)1 << 63) / Max);
  uint64_t r;
  while ((r = Random()) >= t) { /* NOOP */ }

  return r % Max;
}

#else // do not use libcrypto

namespace {
  static const uint64_t LOW = 0x330e;
  static const uint64_t A = 0x5deece66dULL;
  static const uint64_t C = 0xb;
  static const uint64_t M = 0x0000ffffffffffffULL;
}

RandomNumberGenerator::RandomNumberGenerator(std::string Salt) : state(0) {
  Initialize(parameters->options().random_seed(), Salt);
}

RandomNumberGenerator::RandomNumberGenerator(uint64_t Seed, std::string Salt) : state(0) {
  Initialize(Seed, Salt);
}

void RandomNumberGenerator::Initialize(uint64_t Seed, std::string) {
  gold_warning("Warning! Using insecure random number generator. Do not use for security.\n");
  if (Seed != 0) {
    // Seed properly
    state = (Seed << 16) | LOW;
  } else{
    gold_warning("Warning! Using unseeded random number generator\n");

    state = (Seed << 16) | LOW;
  }
}

void RandomNumberGenerator::ReadStateFile(std::string StateFilename) {
  struct stat s;
  // Don't read if there's no file specified.
  if (StateFilename.empty() || stat(StateFilename.data(), &s) != 0) {
    return;
  }

  int fhandle = open(StateFilename.data(), O_RDONLY);
  int bytes_read = 0;


  bytes_read += read(fhandle, &state, sizeof(uint64_t));

  close(fhandle);
}

void RandomNumberGenerator::WriteStateFile(std::string StateFilename) {
  /* Don't serialise without a file name */
  gold_assert(!StateFilename.empty() && "Cannot serialize RNG state file without a filename");


  int fhandle = open(StateFilename.data(), O_WRONLY);
  int byte_count = 0;
  byte_count += write(fhandle, (char *)&state, sizeof(uint64_t));
  close(fhandle);
}

/* This RNG only generates 32 bits of randomness, so we have to cast it down
 * and then up
 */
uint64_t RandomNumberGenerator::Random() {
  state = (A * state + C) & M;
  return static_cast<uint32_t>(state >> 17);
}

/*
 * With only 32 bits of randomness, we do a proportional shift to ensure we
 * get even distribution over the potential max.
 */
uint64_t RandomNumberGenerator::Random(uint64_t max) {
  return (static_cast<double>(Random()) / UINT32_MAX) * max;
}

#endif // HAVE_LIBCRYPTO

}
