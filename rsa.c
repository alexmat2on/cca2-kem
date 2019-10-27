#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "rsa.h"
#include "prf.h"

/* NOTE: a random composite surviving 10 Miller-Rabin tests is extremely
 * unlikely.  See Pomerance et al.:
 * http://www.ams.org/mcom/1993-61-203/S0025-5718-1993-1189518-9/
 * */
#define ISPRIME(x) mpz_probab_prime_p(x,10)
#define NEWZ(x) mpz_t x; mpz_init(x)
#define BYTES2Z(x,buf,len) mpz_import(x,len,-1,1,0,0,buf)
#define Z2BYTES(buf,len,x) mpz_export(buf,&len,-1,1,0,0,x)

/* utility function for read/write mpz_t with streams: */
int zToFile(FILE* f, mpz_t x)
{
	size_t i,len = mpz_size(x)*sizeof(mp_limb_t);
	unsigned char* buf = malloc(len);
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b = (len >> 8*i) % 256;
		fwrite(&b,1,1,f);
	}
	Z2BYTES(buf,len,x);
	fwrite(buf,1,len,f);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}
int zFromFile(FILE* f, mpz_t x)
{
	size_t i,len=0;
	/* force little endian-ness: */
	for (i = 0; i < 8; i++) {
		unsigned char b;
		/* XXX error check this; return meaningful value. */
		fread(&b,1,1,f);
		len += (b << 8*i);
	}
	unsigned char* buf = malloc(len);
	fread(buf,1,len,f);
	BYTES2Z(x,buf,len);
	/* kill copy in buffer, in case this was sensitive: */
	memset(buf,0,len);
	free(buf);
	return 0;
}

int rsa_keyGen(size_t keyBits, RSA_KEY* K)
{
	/* Use the prf to get random byte strings of
	 * the right length, and then test for primality (see the ISPRIME
	 * macro above).  Once you've found the primes, set up the other
	 * pieces of the key ({en,de}crypting exponents, and n=pq). */

	// initialize key struct that will store all rsa variables
	rsa_initKey(K);

	// character array length is counted in bytes, not bits
	size_t keyBytes = keyBits/4; // whaatt??? if we divide by 8, which seems correct, then readFromFile crashes

	// find prime p
	unsigned char p_char[keyBytes];
	NEWZ(p_mpz);
	do {
		randBytes(p_char, keyBytes);
		BYTES2Z(p_mpz, p_char, keyBytes);
	} while(ISPRIME(p_mpz)==0);

	// find prime q
	unsigned char q_char[keyBytes];
	NEWZ(q_mpz);
	do {
		randBytes(q_char, keyBytes);
		BYTES2Z(q_mpz, q_char, keyBytes);
	} while(ISPRIME(q_mpz)==0);

	// find n = (p-1)(q-1)
	NEWZ(n_mpz);
	mpz_mul(n_mpz, p_mpz, q_mpz);

	// find the totient(n) = (p-1)(q-1)
	// which is used as a modulus
	// when finding to find e
	NEWZ(p_1_mpz);
	NEWZ(q_1_mpz);
	NEWZ(totient);
	mpz_sub_ui(p_1_mpz, p_mpz, 1); //p_1_mpz is (p-1) as mpz
	mpz_sub_ui(q_1_mpz, q_mpz, 1); //q_1_mpz is (q-1) as mpz
	mpz_mul(totient, p_1_mpz, q_1_mpz);

	// find e = 2^x +1
	// where  16 < x < 20 and gcd(e,totient)=1
	NEWZ(e_1_mpz); //e-1 a.k.a. 2^x as mpz
	NEWZ(e_mpz); //e a.k.a. 2^x +1 as mpz
	NEWZ(gcd_mpz);
	unsigned int rand_exponent;
	do {
		rand_exponent = rand()%5 + 16;
		mpz_ui_pow_ui(e_1_mpz, 2, rand_exponent);
		mpz_add_ui(e_mpz, e_1_mpz, 1);
		mpz_gcd(gcd_mpz, e_mpz, totient); //e and totient(n) must be coprime
	}
	while (mpz_cmp_ui(gcd_mpz,1)!=0); //while the totient and gcd are not coprime, try again

	NEWZ(d_mpz);
	mpz_invert(d_mpz, e_mpz, totient);

	mpz_set(K->p,p_mpz);
	mpz_set(K->q,q_mpz);
	mpz_set(K->n,n_mpz);
	mpz_set(K->e,e_mpz);
	mpz_set(K->d,d_mpz);

// TODO: fix memory leak by addressing the segmentation fault that results from the following
// line of code.
	mpz_clear(p_mpz);   mpz_clear(q_mpz);   mpz_clear(n_mpz);
	mpz_clear(e_mpz);   mpz_clear(d_mpz);   mpz_clear(gcd_mpz);
	mpz_clear(e_1_mpz); mpz_clear(totient); mpz_clear(p_1_mpz);
	mpz_clear(q_1_mpz);

	return 0;
}

size_t rsa_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	// m_mpz is the plaintext message, m, as an mpz type
	NEWZ(m_mpz);
	BYTES2Z(m_mpz,inBuf,len);

	// c_mpz is the ciphertext, c, as an mpz type
	NEWZ(c_mpz);
	mpz_powm(c_mpz, m_mpz, K->e, K->n); // c = m^e mod n

	//note: len is reassigned to number of bytes successfully written by Z2BYTES()
	// Z2BYTES() reassignes outbuf as pointer to ciphertext in bytes
	Z2BYTES(outBuf, len, c_mpz);

	mpz_clear(c_mpz);
	mpz_clear(m_mpz);
	return len; //returns no. bytes written
}

size_t rsa_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		RSA_KEY* K)
{
	// c_mpz is the ciphertext, c, as an mpz type
	NEWZ(c_mpz);
	BYTES2Z(c_mpz,inBuf,len);

	// m_mpz is the plaintext, m, as an mpz type
	NEWZ(m_mpz);
	mpz_powm(m_mpz, c_mpz, K->d, K->n); // m = m^d mod n

	//note: len is reassigned to number of bytes successfully written by Z2BYTES()
	// Z2BYTES() reassignes outbuf as pointer to plaintext in bytes
	Z2BYTES(outBuf, len, m_mpz);

	mpz_clear(c_mpz);
	mpz_clear(m_mpz);
	return len; //returns no. bytes written
}

size_t rsa_numBytesN(RSA_KEY* K)
{
	return mpz_size(K->n) * sizeof(mp_limb_t);
}

int rsa_initKey(RSA_KEY* K)
{
	mpz_init(K->d); mpz_set_ui(K->d,0);
	mpz_init(K->e); mpz_set_ui(K->e,0);
	mpz_init(K->p); mpz_set_ui(K->p,0);
	mpz_init(K->q); mpz_set_ui(K->q,0);
	mpz_init(K->n); mpz_set_ui(K->n,0);
	return 0;
}

int rsa_writePublic(FILE* f, RSA_KEY* K)
{
	/* only write n,e */
	zToFile(f,K->n);
	zToFile(f,K->e);
	return 0;
}
int rsa_writePrivate(FILE* f, RSA_KEY* K)
{
	zToFile(f,K->n);
	zToFile(f,K->e);
	zToFile(f,K->p);
	zToFile(f,K->q);
	zToFile(f,K->d);
	return 0;
}
int rsa_readPublic(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K); /* will set all unused members to 0 */
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	return 0;
}
int rsa_readPrivate(FILE* f, RSA_KEY* K)
{
	rsa_initKey(K);
	zFromFile(f,K->n);
	zFromFile(f,K->e);
	zFromFile(f,K->p);
	zFromFile(f,K->q);
	zFromFile(f,K->d);
	return 0;
}
int rsa_shredKey(RSA_KEY* K)
{
	/* clear memory for key. */
	mpz_t* L[5] = {&K->d,&K->e,&K->n,&K->p,&K->q};
	size_t i;
	for (i = 0; i < 5; i++) {
		size_t nLimbs = mpz_size(*L[i]);
		if (nLimbs) {
			memset(mpz_limbs_write(*L[i],nLimbs),0,nLimbs*sizeof(mp_limb_t));
			mpz_clear(*L[i]);
		}
	}
	/* NOTE: a quick look at the gmp source reveals that the return of
	 * mpz_limbs_write is only different than the existing limbs when
	 * the number requested is larger than the allocation (which is
	 * of course larger than mpz_size(X)) */
	return 0;
}
