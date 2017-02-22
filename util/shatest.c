#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"

int main()
{
	char* msg = "Hello World!\n";
	int len = 4;
	unsigned char* digest = malloc(len);
	sha1(msg, strlen(msg), digest, len);
	for(int i = 0; i < len; i++)
	{
		printf("%02x ", digest[i]);
	}
	printf("\n");
}
