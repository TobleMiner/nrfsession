#ifndef _PRINTFBACKEND_H_
#define _PRINTFBACKEND_H_

void send_packet(void* ctx, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen);

#endif
