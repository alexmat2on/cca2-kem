/* prf.h.  interface for simple pseudo-random function based
 * on HMAC.  NOTE:  This is pretty inefficient in comparison
 * to using a block cipher.  Convenience and simplicity were
 * prioritized. */
#pragma once
#include <stddef.h> /* for size_t */

int setSeed(unsigned char* entropy, size_t len);
int randBytes(unsigned char* outBuf, size_t len);
