#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <openssl/evp.h>

#include "../hash.h"

int sha1(unsigned char* msg, uint8_t msglen, unsigned char* buff, uint8_t bufflen)
{
	EVP_MD_CTX ctx;
	unsigned char* digest;
	int err, len;
	EVP_MD_CTX_init(&ctx);
	if(EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL) != 1)
	{
		err = -1;
		goto exit_err;
	}
	if(EVP_DigestUpdate(&ctx, msg, msglen) != 1)
	{
		err = -1;
		goto exit_err;
	}
	if(!(digest = malloc(EVP_MD_size(EVP_sha256()))))
	{
		err = -ENOMEM;
		goto exit_err;
	}
	if(EVP_DigestFinal_ex(&ctx, digest, &len) != 1)
	{
		err = -1;
		goto exit_digest;
	}
	if(bufflen < len)
		len = bufflen;
	memcpy(buff, digest, len);
exit_digest:	
	free(digest);
exit_err:
	return err;
}
