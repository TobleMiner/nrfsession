#ifndef _AES_AVR_H_
#define _AES_AVR_H_

#include <stdint.h>

#include "../../lib/avr-crypto-lib/aes/aes.h"
#include "../../lib/avr-crypto-lib/bcal/bcal_aes128.h"
#include "../../lib/avr-crypto-lib/bcal/bcal-cbc.h"

typedef struct aes_ctx {
	uint8_t blocksize;
	bcal_cbc_ctx_t ctx;
	struct key* key;
} aes_ctx;

#include "../keychain.h"

enum mode {
	ENCRYPT,
	DECRYPT
};


int aes_init_endecrypt(enum mode mode, uint8_t blocksize, struct aes_ctx* ctx, unsigned char* iv, uint8_t ivlen, unsigned char* key, uint8_t keylen);
int aes_deencrypt(enum mode mode, struct aes_ctx* ctx, unsigned char* block, uint8_t msglen);
void aes_free(struct aes_ctx* ctx);

#define aes_init_decrypt_128(...) aes_init_endecrypt(ENCRYPT, 16, __VA_ARGS__)
#define aes_init_encrypt_128(...) aes_init_endecrypt(DECRYPT, 16, __VA_ARGS__)
#define aes_encrypt(...) aes_deencrypt(ENCRYPT, __VA_ARGS__)
#define aes_decrypt(...) aes_deencrypt(DECRYPT, __VA_ARGS__)

#endif
