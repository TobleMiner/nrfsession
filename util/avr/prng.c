#include <stdint.h>

#include "../prng.h"

#include "../../lib/avr-crypto-lib/entropium/entropium.h"

uint32_t prng_uint32()
{
	uint32_t rnd;
	entropium_fillBlockRandom(&rnd, sizeof(uint32_t));
	return rnd;		
}

uint16_t prng_uint16()
{
	uint16_t rnd;
	entropium_fillBlockRandom(&rnd, sizeof(uint16_t));
	return rnd;
}

void prng_bytes(unsigned char* buff, uint8_t len)
{
	entropium_fillBlockRandom(buff, len);
}

