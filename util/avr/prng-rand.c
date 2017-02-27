#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "../prng.h"

uint32_t prng_uint32()
{
	return (uint32_t)rand();
}

uint16_t prng_uint16()
{
	return (uint16_t)rand();
}

void prng_bytes(unsigned char* buff, uint8_t len)
{
	uint8_t i;
	uint32_t rnd;
	for(i = 0; i + sizeof(uint32_t) <= len; i += sizeof(uint32_t))
	{
		rnd = prng_uint32();
		memcpy(buff + i, &rnd, sizeof(uint32_t));
	}
	if(i < len)
	{
		rnd = prng_uint32();
		memcpy(buff + i, &rnd, len - i);
	}
}
