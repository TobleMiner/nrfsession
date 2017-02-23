#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "util/printfbackend.h"
#include "session/session.h"

int main()
{
	struct session_handler* handler = alloc_session_handler(NULL, send_packet);
	unsigned char packet[31] = {0x12, 0x34, 0x00, 0x00,
				0x11, 0x22, 0x33, 0x44,
				0x42, 0x42, 0x42, 0x42, 0x42,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
				0xDE, 0xAD};
	int err = handler_process_packet(handler, packet, 31);
	printf("err=%d\n", err);
	printf("sessionsize=%d\n", sizeof(struct session));
	return 0;
}
