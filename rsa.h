/* interface for plain RSA.
 * NOTE: this is *INSECURE* for almost any application other
 * than the KEM to which we apply it.  Don't use it alone. */
#pragma once
#include <gmp.h>

typedef struct _RSA_KEY {
	mpz_t p;
	mpz_t q;
	mpz_t n;
	mpz_t e;
	mpz_t d;
} RSA_KEY;

/* NOTE: keyBits should be a multiple of 16 to avoid rounding. */
int    rsa_keyGen(size_t keyBits, RSA_KEY* K);
/* NOTE: inBuf, when interpreted as a integer, must be less than K->n */
size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K);
size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K);
size_t rsa_numBytesN(RSA_KEY* K);
int rsa_writePublic(FILE* f, RSA_KEY* K);
int rsa_writePrivate(FILE* f, RSA_KEY* K);
int rsa_readPublic(FILE* f, RSA_KEY* K);
int rsa_readPrivate(FILE* f, RSA_KEY* K);
int rsa_initKey(RSA_KEY* K);
int rsa_shredKey(RSA_KEY* K);
