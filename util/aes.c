#include <stdint.h>
#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>

#include "aes.h"

int aes_init(uint8_t blocksize, struct aes_ctx* ctx, uint8_t ivlen, uint8_t keylen)
{
	int err = 0;
	if(ivlen != blocksize || keylen != blocksize)
	{
		err = -EINVAL;
		goto exit_err;
	}
	ctx->blocksize = blocksize;
	EVP_CIPHER_CTX_init(&ctx->ctx);
exit_err:
	return err;
}

int aes_init_endecrypt(enum mode mode, const EVP_CIPHER* cipher, uint8_t blocksize, struct aes_ctx* ctx, unsigned char* iv, uint8_t ivlen, unsigned char* key, uint8_t keylen)
{
	int err;
	if((err = aes_init(blocksize, ctx, ivlen, keylen)))
	{
		return err;
	}
	switch(mode)
	{
		case DECRYPT:
			if(EVP_DecryptInit_ex(&ctx->ctx, cipher, NULL, key, iv) != 1)
			{
				return -1;
			}
			break;
		case ENCRYPT:
			if(EVP_EncryptInit_ex(&ctx->ctx, cipher, NULL, key, iv) != 1)
			{
				return -1;
			}
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

ssize_t aes_deencrypt(enum mode mode, struct aes_ctx* ctx, unsigned char* msg, uint8_t msglen, unsigned char* buff, uint8_t bufflen)
{
	ssize_t len = 0;
	if(bufflen < msglen || msglen % ctx->blocksize != 0)
		return -EINVAL;
	switch(mode)
	{
		case(DECRYPT):
			if(EVP_DecryptUpdate(&ctx->ctx, buff, &len, msg, msglen) != 1)
			{
				return -1;
			}
			EVP_DecryptFinal_ex(&ctx->ctx, buff + len, &len);
			break;
		case(ENCRYPT):
			if(EVP_EncryptUpdate(&ctx->ctx, buff, &len, msg, msglen) != 1)
			{
				return -1;
			}
			break;
		default:
			return -EINVAL;
	}
	return len;
}
