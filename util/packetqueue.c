#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "packetqueue.h"
#include "list.h"

int packetqueue_push(struct packetqueue** queue, unsigned char* data, uint8_t len)
{
	int err = 0;
	struct packet* packet = malloc(sizeof(struct packet));
	if(!packet)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	packet->data = malloc(len);
	if(!packet->data)
	{
		err = -ENOMEM;
		goto exit_packet;
	}
	if((err = llist_append(queue, packet)))
	{
		goto exit_data;
	}
	memcpy(packet->data, data, len);
	packet->len = len;
	return 0;
exit_data:
	free(packet->data);
exit_packet:
	free(packet);
exit_err:
	return err;
}

struct packet* packetqueue_pull(struct packetqueue** queue)
{
	struct packet* packet;
	if(llist_get_value_at_index(*queue, &packet, 0))
	{
		return NULL;
	}
	llist_remove_index(queue, 0);
	return packet;
}

int packetqueue_empty(struct packetqueue* queue)
{
	return queue == NULL;
}

void packet_free(struct packet* packet)
{
	free(packet->data);
	free(packet);
}
