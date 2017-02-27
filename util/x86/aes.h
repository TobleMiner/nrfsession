#ifndef _AES_X86_H_
#define _AES_X86_H_

#include <stdint.h>
#include <openssl/evp.h>

typedef struct aes_ctx {
	uint8_t blocksize;
	EVP_CIPHER_CTX ctx;
	struct key* key;
} aes_ctx;

#include "keychain.h"

enum mode {
	ENCRYPT,
	DECRYPT
};


int aes_init_endecrypt(enum mode mode, const EVP_CIPHER* cipher, uint8_t blocksize, struct aes_ctx* ctx, unsigned char* iv, uint8_t ivlen, unsigned char* key, uint8_t keylen);
ssize_t aes_deencrypt(enum mode mode, struct aes_ctx* ctx, unsigned char* block, uint8_t msglen);
void aes_free(struct aes_ctx* ctx);

#define aes_init_decrypt_128(...) aes_init_endecrypt(ENCRYPT, EVP_aes_128_ecb(), 16, __VA_ARGS__)
#define aes_init_encrypt_128(...) aes_init_endecrypt(DECRYPT, EVP_aes_128_ecb(), 16, __VA_ARGS__)
#define aes_encrypt(...) aes_deencrypt(ENCRYPT, __VA_ARGS__)
#define aes_decrypt(...) aes_deencrypt(DECRYPT, __VA_ARGS__)

#endif
