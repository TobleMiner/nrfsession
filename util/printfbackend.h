#ifndef _PRINTFBACKEND_H_
#define _PRINTFBACKEND_H_

#include <stdint.h>
#include "../session/session.h"

void send_packet(void* ctx, struct session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen);

#endif
