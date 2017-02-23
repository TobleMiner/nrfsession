#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>

void send_packet(void* ctx, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen)
{
	printf("TX => ");
	for(int i = 0; i < addrlen; i++)
	{
		printf("%02x", addr[i]);
	}
	printf(": ");
	for(int i = 0; i < datalen; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("(%u)\n", datalen);
}
