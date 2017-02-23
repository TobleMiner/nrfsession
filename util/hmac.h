#ifndef _HMAC_H_
#define _HMAC_H_

#include <stdint.h>
#include <openssl/hmac.h>

ssize_t hmac_(const EVP_MD *md, unsigned char* msg, uint8_t msglen, unsigned char* key, uint8_t keylen, unsigned char* buff, uint8_t bufflen);

#define hmac_sha1(...) hmac_(EVP_sha1(), __VA_ARGS__)

#endif
