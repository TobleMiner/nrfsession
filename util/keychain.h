#ifndef _KEYCHAIN_H_
#define _KEYCHAIN_H_

#include <stdint.h>

#include "../session/session.h"

typedef struct key {
	unsigned char key[KEY_LENGTH];
	unsigned char keyid[KEYID_LENGTH];
} key;

typedef struct keychain {
	struct key** keys;
} keychain;

struct keychain* alloc_keychain(uint8_t numkeys);
void free_keychain(struct keychain* keychain);
int keychain_add_key(struct keychain* keychain, struct key* key);
struct key* keychain_get_key(struct keychain* keychain, unsigned char* keyid);

#endif
