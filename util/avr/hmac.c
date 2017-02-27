#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "hmac.h"

#include "../../lib/avr-crypto-lib/hmac-sha1/hmac-sha1.h"
#include "../../lib/avr-crypto-lib/sha1/sha1.h"

int hmac_sha1_err(unsigned char* msg, uint8_t msglen, unsigned char* key, uint8_t keylen, unsigned char* buff, uint8_t bufflen)
{
	unsigned char* sha1_buff[SHA1_HASH_BYTES];
	hmac_sha1(&sha1_buff, key, ((uint16_t)keylen) * 8, msg, ((uint32_t)msglen) * 8);
	memcpy(buff, &sha1_buff, bufflen > SHA1_HASH_BYTES ? SHA1_HASH_BYTES : bufflen);
	return 0;
}
