#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "hmac.h"

int main()
{
	char* data = "Hello World!";
	char* key = "foobar";
	unsigned char digest[20];
	ssize_t len = hmac_sha1((unsigned char*)data, strlen(data), (unsigned char*)key, strlen(key), &digest, 4);
	if(len < 0)
	{
		printf("Failed to compute hmac! (err=%d)\n");
		return len;
	}
	for(int i = 0; i < len; i++)
		printf("%02x", digest[i]);
	printf("\n");
	return 0;
}
