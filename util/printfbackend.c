#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../session/session.h"
#include "aes.h"

#ifdef TARGET_AVR


#pragma GCC push_options
#pragma GCC optimize ("O0")

#ifdef VISUAL_DEBUG

#define STRBUFFSIZE 32

volatile char strbuff[STRBUFFSIZE];
volatile uint16_t stroff = 0;

#endif
#endif

#ifdef TARGET_AVR
#pragma GCC pop_options
#endif

#ifdef TARGET_AVR
#ifdef VISUAL_DEBUG
void myprintf(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	if(STRBUFFSIZE - (int16_t)stroff < 16)
	{
		memset(strbuff, 0, STRBUFFSIZE);
		stroff = 0;
	}
	stroff += vsprintf(strbuff + stroff, fmt, args);	
	va_end(args);
}
#else
#define myprintf(...) __asm__("nop")
#endif
#else
#define myprintf(...) printf(__VA_ARGS__)
#endif

void send_packet(void* ctx, struct session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen)
{
	struct session_handler* handler = (struct session_handler*)ctx;
	myprintf("TX => ");
	for(int i = 0; i < addrlen; i++)
	{
		myprintf("%02x", addr[i]);
	}
	myprintf(": ");
	for(int i = 0; i < datalen; i++)
	{
		myprintf("%02x ", data[i]);
	}
	myprintf("(%u) ", datalen);
	myprintf("TX: (");
	for(int i = 0; i < CHALLENGE_LENGTH; i++)
	{
		myprintf("%02x ", session->challenge_tx[i]);
	}
	myprintf(") ");
	myprintf("RX: (");
	for(int i = 0; i < CHALLENGE_LENGTH; i++)
	{
		myprintf("%02x ", session->challenge_rx[i]);
	}
	myprintf(")\n");
	if(handler->sessions)
	{
		struct session* peersession = (struct session*)handler->sessions[0].data;
	        if(session_len_tx_data(peersession) || (peersession->state != SESSION_STATE_AUTH && !(peersession->state == SESSION_STATE_NEW && session->state == SESSION_STATE_AUTH)))
		{
			session->cnt.tx++;
		        session_update_challenge_tx(session);
		}
	}
	else
	{
		session->cnt.tx++;
	        session_update_challenge_tx(session);
	}
	handler_process_packet(handler, data, datalen);
}

void recv_packet(void* ctx, session* session, unsigned char* data, uint8_t datalen)
{
	struct session_handler* handler = (struct session_handler*)ctx;
	myprintf("RX => ");
	for(int i = 0; i < datalen; i++)
	{
		myprintf("%c", data[i]);
	}
	myprintf(" (%u)\n", datalen);
}

void meminfo()
{
	myprintf("sizeof(struct session): %u\n", sizeof(struct session));
	myprintf("sizeof(struct aes_ctx): %u\n", sizeof(struct aes_ctx));
	__asm__("nop");
}
