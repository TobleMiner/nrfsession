#include <malloc.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "keychain.h"

struct keychain* alloc_keychain(uint8_t numkeys)
{
	struct keychain* keychain = malloc(sizeof(struct keychain));
	if(!keychain)
	{
		goto exit_err;
	}
	uint16_t len = sizeof(struct key*) * (numkeys + 1);
	keychain->keys = malloc(len);
	if(!keychain->keys)
	{
		goto exit_keychain;
	}
	memset(keychain->keys, 0, len);
	return keychain;
exit_keychain:
	free(keychain);
exit_err:
	return NULL;
}

void free_keychain(struct keychain* keychain)
{
	struct key** keys = keychain->keys;
	while(*keys)
	{
		free(*keys);
		keys++;
	}
	free(keychain);
}

int keychain_add_key(struct keychain* keychain, struct key* key)
{
	struct key** keys = keychain->keys;
	while(*keys)
	{
		keys++;
	}
	if(*(keys + 1))
		return -EINVAL;
	struct key* key_ = malloc(sizeof(struct key));
	memcpy(key_, key, sizeof(struct key));
	*keys = key_;
	return 0;
}

struct key* keychain_get_key(struct keychain* keychain, unsigned char* keyid)
{
	struct key** key = keychain->keys;
	while(*key)
	{
		if(!memcmp((*key)->keyid, keyid, KEYID_LENGTH))
		{
			return *key;
		}
		key++;
	}
	return NULL;
}
