#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "util/printfbackend.h"
#include "session/session.h"

int main()
{
	struct session_handler* shinji = alloc_session_handler(NULL, send_packet, recv_packet);
	struct session_handler* asuka = alloc_session_handler(shinji, send_packet, recv_packet);
	shinji->ctx = asuka;

	struct keychain* chain = alloc_keychain(10);
	struct key key = {
		.key = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		.keyid = {0x13, 0x37}
	};
	keychain_add_key(chain, &key);
	unsigned char keyid[2] = {0x13, 0x37};
	shinji->keychain = chain;
	asuka->keychain = chain;

	unsigned char addr[5] = {0x13, 0x37, 0x13, 0x37, 0x55};
	unsigned char peeraddr[5] = {0x42, 0x42, 0x42, 0x42, 0x42};
	char str[32] = "Hello World! Foo bar baz foobar";

	int err;
	struct session* session = handler_open_session(shinji, keyid, addr, 5, peeraddr, 5, (unsigned char*)str, strlen(str) + 1);
	printf("err=%d\n", err);
	printf("sessionsize=%d\n", sizeof(struct session));
	free_session(session);
	free_session_handler(shinji);
	free_session_handler(asuka);
	free_keychain(chain);
	return 0;
}
