#ifndef _PACKETQUEUE_H_
#define _PACKETQUEUE_H_

#include <stdint.h>

#include "list.h"

typedef struct packet {
	unsigned char* data;
	uint8_t len;
} packet;

#define packetqueue llist_head

int packetqueue_push(struct packetqueue** queue, unsigned char* data, uint8_t len);
struct packet* packetqueue_pull(struct packetqueue** queue);
int packetqueue_empty(struct packetqueue* queue);
void packet_free(struct packet* packet);

#endif
