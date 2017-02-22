#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <openssl/evp.h>


typedef struct aes_ctx {
	uint8_t blocksize;
	EVP_CIPHER_CTX ctx;
} aes_ctx;

enum mode {
	ENCRYPT,
	DECRYPT
};


int aes_init_endecrypt(enum mode mode, const EVP_CIPHER* cipher, uint8_t blocksize, struct aes_ctx* ctx, unsigned char* iv, uint8_t ivlen, unsigned char* key, uint8_t keylen);
ssize_t aes_deencrypt(enum mode mode, struct aes_ctx* ctx, unsigned char* msg, uint8_t msglen, unsigned char* buff, uint8_t bufflen);

#define aes_init_decrypt_128(...) aes_init_endecrypt(ENCRYPT, EVP_aes_128_cbc(), 16, __VA_ARGS__)
#define aes_init_encrypt_128(...) aes_init_endecrypt(DECRYPT, EVP_aes_128_cbc(), 16, __VA_ARGS__)
#define aes_encrypt(...) aes_deencrypt(ENCRYPT, __VA_ARGS__)
#define aes_decrypt(...) aes_deencrypt(DECRYPT, __VA_ARGS__)

#endif
