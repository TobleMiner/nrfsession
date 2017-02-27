#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "aes.h"
#include "../../lib/avr-crypto-lib/bcal/bcal-cbc.h"
#include "../../lib/avr-crypto-lib/bcal/bcal_aes128.h"


int aes_init_endecrypt(enum mode mode, uint8_t blocksize, struct aes_ctx* ctx, unsigned char* iv, uint8_t ivlen, unsigned char* key, uint8_t keylen)
{
	int err = 0;
	if(blocksize != ivlen || keylen != ivlen)
	{
		err = -EINVAL;
		goto exit_err;
	}
	ctx->blocksize = blocksize;
	if((err = bcal_cbc_init(&aes128_desc, key, 128, &ctx->ctx)))
	{
		goto exit_err;
	}
	bcal_cbc_loadIV(iv, &ctx->ctx);
exit_err:
	return err;
}

int aes_deencrypt(enum mode mode, struct aes_ctx* ctx, unsigned char* block, uint8_t blocklen)
{
	if(blocklen != ctx->blocksize)
	{
		return -EINVAL;
	}
	switch(mode)
	{
		case(ENCRYPT):
			bcal_cbc_encNext(block, &ctx->ctx);
			break;
		case(DECRYPT):
			bcal_cbc_decNext(block, &ctx->ctx);			
			break;
		default:
			return -EINVAL;
	}
	return 0;
}
