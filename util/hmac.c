#include <stdint.h>
#include <string.h>
#include <math.h>
#include <malloc.h>
#include <errno.h>
#include <openssl/hmac.h>

#include "../session/session.h"

ssize_t hmac(const EVP_MD *md, unsigned char* msg, uint8_t msglen, unsigned char* key, uint8_t keylen, unsigned char* buff, uint8_t bufflen)
{
	ssize_t err;
	HMAC_CTX ctx;
	unsigned int digestlen;
	unsigned char* digest = malloc(EVP_MAX_MD_SIZE);
	if(!digest)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	HMAC_CTX_init(&ctx);
	if(HMAC_Init_ex(&ctx, key, keylen, md, NULL) != 1)
	{
		err = -1;
		goto exit_digestalloc;
	}
	if(HMAC_Update(&ctx, msg, msglen) != 1)
	{
		err = -1;
		goto exit_hmac_init;
	}
	if(HMAC_Final(&ctx, digest, &digestlen) != 1)
	{
		err = -1;
		goto exit_hmac_init;
	}
	size_t len = digestlen;
	if(bufflen < digestlen)
		len = bufflen;
	memcpy(buff, digest, len);
	err = len;
exit_hmac_init:
	HMAC_CTX_cleanup(&ctx);	
exit_digestalloc:	
	free(digest);
exit_err:
	return err;
}
