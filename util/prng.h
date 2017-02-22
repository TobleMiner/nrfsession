#ifndef _PRNG_H_
#define _PRNG_H_

#include <stdint.h>

uint32_t prng_uint32();
uint16_t prng_uint16();
void prng_bytes(unsigned char* buff, uint8_t len);

#endif
