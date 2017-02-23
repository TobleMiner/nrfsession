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
	
	unsigned char addr[5] = {0x42, 0x42, 0x42, 0x42, 0x42};
	char str[12] = "Hello World!";

	int err;
	struct session* session = handler_open_session(shinji, addr, 5, (unsigned char*)addr, strlen(addr));
	printf("err=%d\n", err);
	printf("sessionsize=%d\n", sizeof(struct session));
	return 0;
}
