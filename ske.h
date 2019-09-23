/* interface for CCA2 symmetric key encryption (SKE) */
#pragma once

#include <openssl/aes.h>
#include <inttypes.h>
#include <stdio.h>

#define KLEN_SKE 32
/* struct for a key.  we need one key for the mac, and one for AES */
typedef struct _SKE_KEY {
	unsigned char hmacKey[KLEN_SKE];
	unsigned char aesKey[KLEN_SKE];
} SKE_KEY;

/* for allocating buffers, this tells you the size a ciphertext will have. */
size_t ske_getOutputLen(size_t inputLen);
/* we push the KDF into the keyGen function below.  it just needs a buffer
 * with at least 256 bits of entropy. */
int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen);
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV);
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K);
/* NOTE: offset determines where to begin writing to the output file.
 * set to 0 to erase the file and write it from scratch. */
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out);
/* NOTE: offset determines where to begin reading the input file. */
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in);
