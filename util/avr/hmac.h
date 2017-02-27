#ifndef _HMAC_AVR_H_
#define _HMAC_AVR_H_

#include <stdint.h>

#include "../../lib/avr-crypto-lib/hmac-sha1/hmac-sha1.h"
#include "../../lib/avr-crypto-lib/sha1/sha1.h"

int hmac_sha1_err(unsigned char* msg, uint8_t msglen, unsigned char* key, uint8_t keylen, unsigned char* buff, uint8_t bufflen);
int hmac_md5_err(unsigned char* msg, uint8_t msglen, unsigned char* key, uint8_t keylen, unsigned char* buff, uint8_t bufflen);

#endif
