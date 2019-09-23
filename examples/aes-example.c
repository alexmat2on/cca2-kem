/* dumb example to illustrate AES in cbc and ctr modes. */
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int cbc_example()
{
	unsigned char key[32];
	size_t i;
	for (i = 0; i < 32; i++)
		key[i] = i;
	AES_KEY kenc;
	AES_KEY kdec;
	AES_set_encrypt_key(key,256,&kenc);
	AES_set_decrypt_key(key,256,&kdec);
	char* message = "this is a test message :D";
	size_t len = strlen(message);
	size_t ctLen = (len/AES_BLOCK_SIZE +
			(len%AES_BLOCK_SIZE?1:0)) * AES_BLOCK_SIZE;
	unsigned char ct[512];
	unsigned char pt[256];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,256);
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;
	/* NOTE: openssl's AES_cbc_encrypt *will destroy the iv*.
	 * So you have to make sure you have a copy: */
	unsigned char iv_dec[16]; memcpy(iv_dec,iv,16);
	AES_cbc_encrypt((unsigned char*)message,
			ct,len,&kenc,iv,AES_ENCRYPT);
	for (i = 0; i < ctLen; i++) {
		fprintf(stderr, "%02x",ct[i]);
	}
	fprintf(stderr, "\n");
	/* note the use of the copied iv_dec, since the original
	 * was modified by the first cbc_encrypt call. */
	AES_cbc_encrypt(ct,pt,ctLen,&kdec,iv_dec,AES_DECRYPT);
	fprintf(stderr, "%s\n",pt);
	return 0;
}

int ctr_example()
{
	unsigned char key[32];
	size_t i;
	for (i = 0; i < 32; i++) key[i] = i;
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	char* message = "this is a test message :D";
	size_t len = strlen(message);
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	int nWritten;
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctLen = nWritten;
	for (i = 0; i < ctLen; i++) {
		fprintf(stderr, "%02x",ct[i]);
	}
	fprintf(stderr, "\n");
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work. */
	nWritten = 0;
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctLen))
		ERR_print_errors_fp(stderr);
	fprintf(stderr, "%s\n",pt);
	return 0;
}

int main()
{
	return ctr_example();
	// return cbc_example();
}
