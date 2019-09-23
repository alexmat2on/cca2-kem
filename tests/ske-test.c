/* test code for SKE */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../ske.h"
#include "../prf.h"

/* turn this on to print more stuff. */
#define VDEBUG 0
/* turn this on for randomized tests. */
#define RANDKEY 0

/* encrypt / decrypt some strings, and make sure
 * this composition is the identity */
int soundCheck(char* message, SKE_KEY* K, unsigned char* IV, unsigned char errMask)
{
	size_t len = strlen(message) + 1; /* +1 to include null char */
	size_t ctLen = ske_getOutputLen(len);
	int rcode = 1;
	unsigned char* ct = malloc(ctLen);
	ske_encrypt(ct,(unsigned char*)message,len,K,IV);
	#if VDEBUG
	size_t i;
	for (i = 0; i < ctLen; i++) {
		fprintf(stderr, "%02x",ct[i]);
	}
	fprintf(stderr, "\n");
	#endif
	/* now try to decrypt it. */
	char* pt = malloc(len);
	/* tweak ct and see what happens: */
	ct[rand() % ctLen] ^= errMask;
	size_t r = ske_decrypt((unsigned char*)pt,ct,ctLen,K);
	if (r == -1) {
		#if VDEBUG
		fprintf(stderr, "Invalid ciphertext x_x\n");
		#endif
		rcode = -1;
		goto end;
	}
	#if VDEBUG
	fprintf(stderr, "%s\n",pt);
	#endif
	rcode = (strcmp(pt,message))?1:0;

end:
	free(ct);
	free(pt);
	return rcode;
}

int main(int argc, char *argv[])
{
	fprintf(stderr, "testing ske...\n");
	char *pass,*fail;
	if (isatty(fileno(stdout))) {
		pass = "\033[32mpassed\033[0m";
		fail = "\033[31mfailed\033[0m";
	} else {
		pass = "passed";
		fail = "failed";
	}
	int rcode;
	char* strings[8] = {
		"this is a test",
		"this is a longer test",
		"another even longer test.........",
		"asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdf",
		"909090898989787878676767565656454545343434232332121212abbcccddddeeeee",
		"XXXXXXXXXXXXXXXXXXX",
		"88888888888888888888888888888888888888",
		"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
	};
	size_t i;
	unsigned char IV[16];
	for (i = 0; i < 16; i++) IV[i] = i;
#if RANDKEY
	setSeed(0,0);
#else
	unsigned char seed[32];
	for (i = 0; i < 32; i++) seed[i] = (i*3+53) & 0xff;
	setSeed(seed,32);
#endif
	SKE_KEY K;
	ske_keyGen(&K,0,0);

	if (argc == 4) {
		ske_encrypt_file(argv[2],argv[1],&K,IV,0);
		ske_decrypt_file(argv[3],argv[2],&K,0);
		return 0;
	}

	for (i = 0; i < 8; i++) {
		rcode = soundCheck(strings[i],&K,IV,0);
		fprintf(stderr, "test[%02lu] %s\n",i,rcode?fail:pass);
	}
	/* now with some errors: */
	for (i = 0; i < 8; i++) {
		rcode = soundCheck(strings[i],&K,IV, i+1);
		fprintf(stderr, "test[%02lu] %s\n",i+8,(rcode!=-1)?fail:pass);
	}

	return 0;
}
