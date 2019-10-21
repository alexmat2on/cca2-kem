/* prf.h.  interface for simple pseudo-random function based
 * on HMAC.  NOTE:  This is pretty inefficient in comparison
 * to using a block cipher.  Convenience and simplicity were
 * prioritized. */
#pragma once
#include <stddef.h> /* for size_t */

void print_hex(const unsigned char* buffer, const int len);
void buffer_concat(unsigned char* bufferA, const int lenA, unsigned char* bufferB, const int lenB, unsigned char* newB);

int setSeed(unsigned char* entropy, size_t len);
int randBytes(unsigned char* outBuf, size_t len);
