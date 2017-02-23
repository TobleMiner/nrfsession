#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <malloc.h>
#include <string.h>

#include "../session/session.h"

void send_packet(void* ctx, struct session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen)
{
	struct session_handler* handler = (struct session_handler*)ctx;
	printf("TX => ");
	for(int i = 0; i < addrlen; i++)
	{
		printf("%02x", addr[i]);
	}
	printf(": ");
	for(int i = 0; i < datalen; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("(%u) ", datalen);
	printf("TX: (");
	for(int i = 0; i < CHALLENGE_LENGTH; i++)
	{
		printf("%02x ", session->challenge_tx[i]);
	}
	printf(") ");
	printf("RX: (");
	for(int i = 0; i < CHALLENGE_LENGTH; i++)
	{
		printf("%02x ", session->challenge_rx[i]);
	}
	printf(")\n");
        session->cnt.tx++;
        session_update_challenge_tx(session);
	handler_process_packet(handler, data, datalen);
}

void recv_packet(void* ctx, session* session, unsigned char* data, uint8_t datalen)
{
	struct session_handler* handler = (struct session_handler*)ctx;
	printf("RX => ");
	for(int i = 0; i < datalen; i++)
	{
		printf("%02x ", data[i]);
	}
	printf("(%u)\n", datalen);		
}
