#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "aes.h"

int main()
{
	char* data = "Hello World!0000";
	unsigned char key[16] =	{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
	unsigned char iv[16] =	{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
	unsigned char ctext[16];
	struct aes_ctx ctx;
	int err;
	if((err = aes_init_encrypt_128(&ctx, (unsigned char*)iv, 16, (unsigned char*)key, 16)))
	{
		printf("Failed to initilize aes encryption (err=%d)\n", err);
		return err;
	}
	if((err = aes_encrypt(&ctx, (unsigned char*)data, strlen(data), ctext, 16)) < 0)
	{
		printf("Failed to encrypt data (err=%d)\n", err);
		return err;
	}
	for(int i = 0; i < 16; i++)
		printf("%02x", ctext[i]);
	printf("\n");
	if((err = aes_init_decrypt_128(&ctx, (unsigned char*)iv, 16, (unsigned char*)key, 16)))
	{
		printf("Failed to initilize aes decryption (err=%d)\n", err);
		return err;
	}
	char cleartext[17];
	cleartext[16] = 0;
	if((err = aes_decrypt(&ctx, ctext, 16, cleartext, 16)) < 0)
	{
		printf("Failed to decrypt data (err=%d)\n", err);
		return err;
	}
	printf("%s\n", cleartext);
	return 0;
}
