/* kem-enc.c
 * simple encryption utility providing CCA2 security.
 * based on the KEM/DEM hybrid model. */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <time.h>

#include "ske.h"
#include "rsa.h"
#include "prf.h"

static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Encrypt or decrypt data.\n\n"
"   -i,--in     FILE   read input from FILE.\n"
"   -o,--out    FILE   write output to FILE.\n"
"   -k,--key    FILE   the key.\n"
"   -r,--rand   FILE   use FILE to seed RNG (defaults to /dev/urandom).\n"
"   -e,--enc           encrypt (this is the default action).\n"
"   -d,--dec           decrypt.\n"
"   -g,--gen    FILE   generate new key and write to FILE{,.pub}\n"
"   -b,--BITS   NBITS  length of new key (NOTE: this corresponds to the\n"
"                      RSA key; the symmetric key will always be 256 bits).\n"
"                      Defaults to %lu.\n"
"   --help             show this message and exit.\n";

#define FNLEN 255

enum modes {
	ENC,
	DEC,
	GEN
};

/* Let SK denote the symmetric key.  Then to format ciphertext, we
 * simply concatenate:
 * +------------+----------------+
 * | RSA-KEM(X) | SKE ciphertext |
 * +------------+----------------+
 * NOTE: reading such a file is only useful if you have the key,
 * and from the key you can infer the length of the RSA ciphertext.
 * We'll construct our KEM as KEM(X) := RSA(X)|H(X), and define the
 * key to be SK = KDF(X).  Naturally H and KDF need to be "orthogonal",
 * so we will use different hash functions:  H := SHA256, while
 * KDF := HMAC-SHA512, where the key to the hmac is defined in ske.c
 * (see KDF_KEY).
 * */

#define HASHLEN 32 /* for sha256 */

void random_keygen(unsigned char* SK, size_t length) {
	srand(time(0));
    char alphabet[] = "0123456789"
                     "abcdefghijklmnopqrstuvwxyz"
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    while (length-- > 0) {
        size_t index = (double) rand() / RAND_MAX * (sizeof alphabet - 1);
        *SK++ = alphabet[index];
    }
}

void create_hash(unsigned char* output, unsigned char* input, size_t length) {
	//unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, length);
    SHA256_Final(output, &sha256);

    /*int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }*/
    //output[64] = 0;
    return;
}

void generate_IV(unsigned char* IV) {
	size_t i;
	for (i = 0; i < 16; i++) {
		IV[i] = i;
	}
}

int kem_encrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: encapsulate random symmetric key (SK) using RSA and SHA256;
	 * encrypt fnIn with SK; concatenate encapsulation and cihpertext;
	 * write to fnOut. */

	size_t rsa_key_size = rsa_numBytesN(K);

	//generate random key string 'x'
	unsigned char* x = malloc(rsa_key_size);
	/* ...fill x with random bytes (which fit in an RSA plaintext)... */
	randBytes(x, rsa_key_size);

	//encrypt x using RSA
	unsigned char* x_encrypted = malloc(rsa_key_size);
	size_t rsa_ct_len = rsa_encrypt(x_encrypted, x, rsa_key_size, K);

	//Hash x using SHA256
	unsigned char* x_hashed = malloc(HASHLEN);
	create_hash(x_hashed, x, rsa_key_size);
	//printf("%s\n%s\n", x, x_hashed);

	//Concatenate x_encrypted and x_hashed to form KEM
	unsigned char* kem = malloc(rsa_ct_len + HASHLEN);
	buffer_concat(x_encrypted, rsa_ct_len, x_hashed, HASHLEN, kem);

	//Generate symmetric key
	SKE_KEY SK;
	ske_keyGen(&SK,x,rsa_key_size);

	//Encrypt fnIn with SK
	unsigned char* IV = malloc(16);
	generate_IV(IV);
	FILE* ct_file = fopen("/tmp/fnInCt", "wb");  //create tmp file to store E(fnIn)
	fclose(ct_file);
	ske_encrypt_file("/tmp/fnInCt", fnIn, &SK, IV, 0);  //write E(fnIn) to file


	//Write concatenation of KEM and ciphertext to fnOut
	FILE* out_file = fopen(fnOut, "w");
	fwrite( kem, 1, rsa_ct_len + HASHLEN, out_file); // write KEM to fnOut
	ct_file = fopen("/tmp/fnInCt", "r"); //read ct from ct_file and write it to out_file
	fseek(ct_file, 0, SEEK_END);
	size_t ct_len = ftell(ct_file);
	rewind(ct_file);
	unsigned char* ct = malloc(ct_len);
	fread(ct, 1, ct_len, ct_file);
	fwrite(ct, 1, ct_len, out_file); //write CT to fnOut

	fclose(out_file);
	fclose(ct_file);
	//remove("/tmp/fnInCt");

	return 0;
}

/* NOTE: make sure you check the decapsulation is valid before continuing */
int kem_decrypt(const char* fnOut, const char* fnIn, RSA_KEY* K)
{
	/* TODO: write this. */
	/* step 1: recover the symmetric key (x) */
	FILE* ct_file = fopen(fnIn, "r");
	fseek(ct_file, 0L, SEEK_END);
	size_t ct_len = ftell(ct_file);
	rewind(ct_file);
	unsigned char* ct_f_in = malloc((ct_len) * sizeof(*ct_f_in)); //size of ct_f_in (RSA(x) + H(x) + ske(m))
	fread(ct_f_in, ct_len, 1, ct_file);

	//parse rsa ciphertext from fnIn
	size_t rsa_ct_len = rsa_numBytesN(K);
	unsigned char* x_encrypted = malloc(rsa_ct_len);
	memcpy(x_encrypted, ct_f_in, rsa_ct_len);

	//decrypt x_encrypted to recover symmetric key (x)
	unsigned char* x = malloc(rsa_ct_len);
	rsa_decrypt(x, x_encrypted, rsa_ct_len, K);

	/* step 2: check decapsulation */
	//hash x and compare with H(x) from fnIn
	unsigned char* x_hashed_candidate = malloc(HASHLEN);
	create_hash(x_hashed_candidate, x, HASHLEN);
	unsigned char* x_hashed = malloc(HASHLEN);
	memcpy(x_hashed, ct_f_in+rsa_ct_len, HASHLEN);
	if(memcmp(x_hashed_candidate, x_hashed, HASHLEN) != 0){
		fprintf(stderr, "decapsulation check failed...\n");
		return -1;
	}

	/* step 3: derive key from ephemKey and decrypt data. */
	SKE_KEY SK;	
	ske_keyGen(&SK,x,32);
	ske_decrypt_file(fnOut, fnIn, &SK, 0);

	return 0;
}

int main(int argc, char *argv[]) {
	/* define long options */
	static struct option long_opts[] = {
		{"in",      required_argument, 0, 'i'},
		{"out",     required_argument, 0, 'o'},
		{"key",     required_argument, 0, 'k'},
		{"rand",    required_argument, 0, 'r'},
		{"gen",     required_argument, 0, 'g'},
		{"bits",    required_argument, 0, 'b'},
		{"enc",     no_argument,       0, 'e'},
		{"dec",     no_argument,       0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{0,0,0,0}
	};
	/* process options: */
	char c;
	int opt_index = 0;
	char fnRnd[FNLEN+1] = "/dev/urandom";
	fnRnd[FNLEN] = 0;
	char fnIn[FNLEN+1];
	char fnOut[FNLEN+1];
	char fnKey[FNLEN+1];
	memset(fnIn,0,FNLEN+1);
	memset(fnOut,0,FNLEN+1);
	memset(fnKey,0,FNLEN+1);
	int mode = ENC;
	// size_t nBits = 2048;
	size_t nBits = 1024;
	while ((c = getopt_long(argc, argv, "edhi:o:k:r:g:b:", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				printf(usage,argv[0],nBits);
				return 0;
			case 'i':
				strncpy(fnIn,optarg,FNLEN);
				break;
			case 'o':
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'k':
				strncpy(fnKey,optarg,FNLEN);
				break;
			case 'r':
				strncpy(fnRnd,optarg,FNLEN);
				break;
			case 'e':
				mode = ENC;
				break;
			case 'd':
				mode = DEC;
				break;
			case 'g':
				mode = GEN;
				strncpy(fnOut,optarg,FNLEN);
				break;
			case 'b':
				nBits = atol(optarg);
				break;
			case '?':
				printf(usage,argv[0],nBits);
				return 1;
		}
	}

	/* TODO: finish this off.  Be sure to erase sensitive data
	 * like private keys when you're done with them (see the
	 * rsa_shredKey function). */

	RSA_KEY* K = malloc(sizeof(RSA_KEY));
	//rsa_initKey(K);

	switch (mode) {
		case ENC:
		{
			FILE* rsa_pub = fopen(fnKey, "rb");
			rsa_readPublic(rsa_pub, K);
			kem_encrypt(fnOut, fnIn, K);
			rsa_shredKey(K);
			break;
		}
		case DEC:
		{
			FILE* rsa_pvt = fopen(fnKey, "rb");
			rsa_readPrivate(rsa_pvt, K);
			kem_decrypt(fnOut, fnIn, K);
			rsa_shredKey(K);
			break;
		}
		case GEN:
		{
			//Generate and store RSA key K in key files
			rsa_keyGen(nBits, K);
			FILE* rsa_pvt = fopen(fnOut, "wb");
			strcat(fnOut, ".pub");
			FILE* rsa_pub = fopen(fnOut, "wb");
			rsa_writePrivate(rsa_pvt, K);
			rsa_writePublic(rsa_pub, K);
			rsa_shredKey(K);
			break;
		}
		default:
			return 1;
	}

	return 0;
}
