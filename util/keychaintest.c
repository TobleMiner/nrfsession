#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "keychain.h"

int main()
{
	struct keychain* chain = alloc_keychain(10);
	struct key key = {
		.key = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		.keyid = {0x13, 0x37}
	};
	keychain_add_key(chain, &key);
	unsigned char keyid[2] = {0x13, 0x37};
	printf("%x\n", keychain_get_key(chain, &keyid));
}
