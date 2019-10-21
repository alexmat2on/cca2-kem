#include "ske.h"
#include "prf.h"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* memcpy */
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#ifdef LINUX
#define MMAP_SEQ MAP_PRIVATE|MAP_POPULATE
#else
#define MMAP_SEQ MAP_PRIVATE
#endif

/* NOTE: since we use counter mode, we don't need padding, as the
 * ciphertext length will be the same as that of the plaintext.
 * Here's the message format we'll use for the ciphertext:
 * +------------+--------------------+----------------------------------+
 * | 16 byte IV | C = AES(plaintext) | HMAC(IV|C) (32 bytes for SHA256) |
 * +------------+--------------------+----------------------------------+
 * */

/* we'll use hmac with sha256, which produces 32 byte output */
#define HM_LEN 64 //32
#define KDF_KEY "qVHqkOVJLb7EolR9dsAMVwH1hRCYVx#I"
/* need to make sure KDF is orthogonal to other hash functions, like
 * the one used in the KDF, so we use hmac with a key. */

int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen)
{
	/* TODO: write this.  If entropy is given, apply a KDF to it to get
	 * the keys (something like HMAC-SHA512 with KDF_KEY will work).
	 * If entropy is null, just get a random key (you can use the PRF). */
	randBytes(K->hmacKey, KLEN_SKE);
	randBytes(K->aesKey, KLEN_SKE);
	return 0;
}
size_t ske_getOutputLen(size_t inputLen)
{
	return AES_BLOCK_SIZE + inputLen + HM_LEN;
}
size_t ske_encrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K, unsigned char* IV)
{
	/* TODO: finish writing this.  Look at ctr_example() in aes-example.c
	 * for a hint.  Also, be sure to setup a random IV if none was given.
	 * You can assume outBuf has enough space for the result. */
	int bytesWritten = 0;
	int callFreeIV = 0;
	if (!IV) {
		callFreeIV = 1;
		IV = malloc(AES_BLOCK_SIZE);
		FILE* frand = fopen("/dev/urandom", "rb");
		fread(IV,1,AES_BLOCK_SIZE,frand);
		fclose(frand);
	}

	unsigned char ciphertext[len];// = malloc(512); //[512]
	unsigned char mac[HM_LEN];// = malloc(512); //[512]
	memset(ciphertext, 0, len);
	memset(mac, 0, HM_LEN);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,IV))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_EncryptUpdate(ctx,ciphertext,&bytesWritten,inBuf,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);

	int ivCtLen = AES_BLOCK_SIZE + len; // 16 + message length
	unsigned char iv_ct[ivCtLen];
	memset(iv_ct, 0, ivCtLen);

	buffer_concat(IV, AES_BLOCK_SIZE, ciphertext, len, iv_ct);

	HMAC(EVP_sha512(),K->hmacKey,HM_LEN,iv_ct,ivCtLen,mac,NULL);

	buffer_concat(iv_ct, ivCtLen, mac, HM_LEN, outBuf);

	bytesWritten = ivCtLen + HM_LEN;
	if (callFreeIV) free(IV);
	return ivCtLen + HM_LEN; /* TODO: should return number of bytes written, which
	             hopefully matches ske_getOutputLen(...). */
}
size_t ske_encrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, unsigned char* IV, size_t offset_out)
{
	/* TODO: write this.  Hint: mmap. */
	/* NOTE: offset determines where to begin writing to the output file.
 	 * set to 0 to erase the file and write it from scratch. */

	int fdin = open(fnin, O_RDONLY);
	struct stat sb1;
	if (fstat(fdin,&sb1) == -1) {
		perror("Could't get input file size.\n");
		return -1;
	}
	
	int fdout = open(fnout, O_RDWR|O_CREAT, S_IRWXU);
	// struct stat sb2;
	size_t ctlen = ske_getOutputLen(sb1.st_size);
	write(fdout, "tmp", ctlen);
	// if (fstat(fdout,&sb2) == -1) {
	// 	perror("Could't get output file size.\n");
	// 	return -1;
	// }

	char* input_map = mmap(NULL, sb1.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	char* output_map = mmap(NULL, ctlen, PROT_READ|PROT_WRITE, MAP_SHARED, fdout, 0);

	size_t len = sb1.st_size + 1; /* +1 to include null char */
	ske_encrypt((unsigned char*)output_map, (unsigned char*)input_map, len, K, IV);
	
	munmap(input_map, sb1.st_size);
	munmap(output_map,ctlen);

	close(fdin);
	close(fdout);

	return 0;
}
size_t ske_decrypt(unsigned char* outBuf, unsigned char* inBuf, size_t len,
		SKE_KEY* K)
{
	/* TODO: write this.  Make sure you check the mac before decypting!
	 * Oh, and also, return -1 if the ciphertext is found invalid.
	 * Otherwise, return the number of bytes written.  See aes-example.c
	 * for how to do basic decryption. */
	int bytesWritten = 0;
	int ivCtLen = len - HM_LEN;
	unsigned char ivCt[ivCtLen]; memset(ivCt, 0, ivCtLen);
	unsigned char macGiven[HM_LEN]; memset(macGiven, 0, HM_LEN);
	unsigned char macCheck[HM_LEN]; memset(macCheck, 0, HM_LEN);

	memcpy(ivCt, inBuf, ivCtLen);
	memcpy(macGiven, inBuf+ivCtLen, HM_LEN);

	HMAC(EVP_sha512(),K->hmacKey,HM_LEN,ivCt,ivCtLen,macCheck,NULL);

	if (memcmp(macGiven, macCheck, HM_LEN) != 0) return -1;

	// If the MAC verification passes, continue to decrypt...
	int ctLen = ivCtLen - AES_BLOCK_SIZE;
	unsigned char iv[AES_BLOCK_SIZE]; memset(iv, 0, AES_BLOCK_SIZE);
	unsigned char ct[ctLen]; memset(ct, 0, ctLen);

	memcpy(iv, ivCt, AES_BLOCK_SIZE);
	memcpy(ct, ivCt+AES_BLOCK_SIZE, ctLen);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,K->aesKey,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,outBuf,&bytesWritten,ct,ctLen))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);

	return ctLen;
}
size_t ske_decrypt_file(const char* fnout, const char* fnin,
		SKE_KEY* K, size_t offset_in)
{
	int fdin = open(fnin, O_RDONLY);
	struct stat sb1;
	if (fstat(fdin,&sb1) == -1) {
		perror("Could't get input file size.\n");
		return -1;
	}

	int fdout = open(fnout, O_RDWR|O_CREAT, S_IRWXU);
	size_t plainLen = sb1.st_size - AES_BLOCK_SIZE - HM_LEN;
	write(fdout, "tmp", plainLen);
	// struct stat sb2;
	// if (fstat(fdout,&sb2) == -1) {
	// 	perror("Could't get output file size.\n");
	// 	return -1;
	// }

	char* input_map = mmap(NULL, sb1.st_size, PROT_READ, MAP_PRIVATE, fdin, 0);
	char* output_map = mmap(NULL, plainLen, PROT_READ|PROT_WRITE, MAP_SHARED, fdout, 0);

	size_t len = sb1.st_size + 1; /* +1 to include null char */
	ske_decrypt((unsigned char*)output_map, (unsigned char*)input_map, len, K);
	
	munmap(input_map, sb1.st_size);
	munmap(output_map,plainLen);

	close(fdin);
	close(fdout);

	return 0;
}
