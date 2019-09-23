#include "prf.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <gmp.h>

/* PRF state: */
#define BLOCK_LEN 64 /* we will use SHA512 */
static mpz_t rcount;
static unsigned char rkey[BLOCK_LEN];
static int prf_initialized;
/* NOTE: for those that don't know, static variables in C will be
 * initialized to 0.  This is important for us. */
#define VERY_YES 9191919

int setSeed(unsigned char* entropy, size_t len)
{
	if (prf_initialized != VERY_YES) mpz_init(rcount);
	mpz_set_ui(rcount,1);
	int callFree = 0;
	if (!entropy) {
		callFree = 1;
		len = 32;
		entropy = malloc(len);
		FILE* frand = fopen("/dev/urandom", "rb");
		fread(entropy,1,len,frand);
		fclose(frand);
	}
	SHA512(entropy, len, rkey);
	if (callFree) free(entropy);
	prf_initialized = VERY_YES;
	return 0;
}

int randBytes(unsigned char* outBuf, size_t len)
{
	if (prf_initialized != VERY_YES) setSeed(0,0);
	size_t nBlocks = len / BLOCK_LEN;
	size_t i;
	for (i = 0; i < nBlocks; i++) {
		HMAC(EVP_sha512(),rkey,BLOCK_LEN,(unsigned char*)mpz_limbs_read(rcount),
				sizeof(mp_limb_t)*mpz_size(rcount),outBuf,NULL);
		mpz_add_ui(rcount,rcount,1);
		outBuf += BLOCK_LEN;
	}
	/* handle final block: */
	unsigned char fblock[BLOCK_LEN];
	if (len % BLOCK_LEN) {
		HMAC(EVP_sha512(),rkey,BLOCK_LEN,(unsigned char*)mpz_limbs_read(rcount),
				sizeof(mp_limb_t)*mpz_size(rcount),fblock,NULL);
		mpz_add_ui(rcount,rcount,1);
		memcpy(outBuf,fblock,len%BLOCK_LEN);
	}
	return 0;
}

