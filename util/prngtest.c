#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "prng.h"

int main()
{
	const int memsize = 9;
	unsigned char* mem = malloc(memsize);
	memset(mem, 0, memsize);
	prng_bytes(mem, memsize - 1);
	for(int i = 0; i < memsize; i++)
	{
		printf("%02x ", mem[i]);
	}
	printf("\n");
	free(mem);	
}
