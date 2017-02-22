#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "session.h"
#include "../util/list.h"
#include "../util/prng.h"

enum id_side {
	ID_A,
	ID_B
};

int handler_find_session_by_id(struct session_handler* handler, struct sessionid* id, struct session* session)
{
	unsigned int len = llist_length(handler->sessions);
	while(len-- > 0)
	{
		handler_get_session_at_index(handler, &session, len);
		if(!memcmp(id, session->id, sizeof(struct session)))
			return 0;
	}
	return -ENOENT;
}

int handler_find_session_by_idab(enum id_side id_side, struct session_handler* handler, uint16_t id, struct session* session)
{
	unsigned int len = llist_length(handler->sessions);
	while(len-- > 0)
	{
		handler_get_session_at_index(handler, &session, len);
		switch(id_side)
		{
			case(ID_A):
				if(id == session->id.id_a)
					return 0;
				break;
			case(ID_B):
				if(id == session->id.id_b)
					return 0;
				break;
			default:
				return -EINVAL;
		}
	}
	return -ENOENT;
}

#define handler_find_session_by_ida(...) handler_find_session_by_idab(ID_A, __VA_ARGS__)
#define handler_find_session_by_idb(...) handler_find_session_by_idab(ID_B, __VA_ARGS__)

int handler_get_session_at_index(struct session_handler* handler, struct session** session, int index)
{
	return llist_get_value_at_index(handler->sessions, session, index);
}

int handler_add_session(struct session_handler* handler, struct session_t* session)
{
	return llist_append(&handler->sessions, session);
}

void handler_remove_session(struct session_handler* handler, struct session_t* session)
{
	llist_remove_value(&handler->sessions, session);
}

int handler_num_sessions(struct session_handler* handler)
{
	return llist_lenght(handler->sessions);
}

struct session* alloc_session(struct session_handler* handler, struct sessionid* id)
{
	struct session* session = malloc(sizeof(struct session_t));
	if(!session)
	{
		goto exit_err;
	}
	memset(session, 0, sizeof(struct session_t));
	memcpy(session->id, id, sizeof(struct sessionid));
	session->handler = handler;
	if(handler && handler_add_session(handler, session))
	{
		free(session);
		session = NULL;
	}
exit_err:
	return session;
}

void free_session(struct session_t* session)
{
	if(session->iv)
	{
		free(session->iv);
	}
	if(session->challenge)
	{
		free(session->challenge);
	}
	if(session->handler)
	{
		handler_remove_session(session->handler, session);
	}
	free(session);
}

struct session_handler* alloc_session_handler()
{
	struct session_handler* handler = malloc(sizeof(struct session_handler));
	if(handler)
	{
		memset(handler, 0, sizeof(struct session_handler));
	}
	return handler;
}

void free_session_handler(struct session_handler* handler)
{
	while(handler_num_sessions(handler))
		free(handler_get_session_at_index(0));
	free(handler);
}

int session_process_packet(struct session* session, unsigned char* packet, uint8_t len)
{
	int err = 0;
	switch(session->state)
	{
		// Initiator receives auth response
		case(SESSION_STATE_INIT):
			break;
		// Peer receives auth response
		case(SESSION_STATE_NEW):
			break;
		// Any side receives data
		case SESSION_STATE_AUTH:
			break;
		default:
			err = -EINVAL;
	}
	return err;
}

uint16_t handler_get_free_idab(enum id_side id_side, struct session_handler* handler)
{
	struct session* session;
	uint16_t id;
	do
	{
		id = prng_uint16();
	}
	while(!handler_find_session_by_idab(id_side, handler, id, session));
	return id;
}

#define handler_get_free_ida(...) handler_get_free_idab(ID_A, __VA_ARGS__)
#define handler_get_free_idb(...) handler_get_free_idab(ID_B, __VA_ARGS__)

int session_new_challenge(struct session* session, unsigned char* buff, uint8_t len)
{
	if(len != CHALLENGE_LENGTH)
	{
		return -EINVAL;
	}
	if(session->handler && false)
	{
		if(sizeof(typeof(session->handler->packetcnt)) > len)
		{
			return -EINVAL;
		}
		memcpy(buff, &session->handler->packetcnt, sizeof(typeof(session->handler->packetcnt)));
		prng_bytes(buff + sizeof(typeof(session->handler->packetcnt)), len - sizeof(typeof(session->handler->packetcnt)));
	}
	else
	{
		prng_bytes(buff, len);
	}
	memcpy(session->challenge, buff, len);
	return 0;
}

int handler_process_packet(struct session_handler* handler, unsigned char* packet, uint8_t len)
{
	int err = 0;
	if(len < SESSION_MIN_PACKET_LEN)
	{	
		err = -EINVAL;
		goto exit_err;
	}
	struct sessionid id;
	struct session* session;
	memcpy(&id, packet, sizeof(struct sessionid));
	if(id.id_b)
	{
		// Find session by id
		if((err = handler_find_session_by_id(handler, id.id_b, session)))
		{
			goto exit_err;
		}
		err = session_process_packet(session, packet, len);
	}
	else
	{
		// New session
		if(!id.id_a || len < SESSION_PACKET_INIT_LEN)
		{
			err = -EINVAL;
			goto exit_err;
		}
		id.id_b = handler_get_free_idb(handler);
		if(!(session = alloc_session(handler, &id)))
		{
			err = -ENOMEM;
			goto exit_err;
		}
		// Keep this dynamic so we can free it once the aes context has
		// been initialized
		if(!(session->iv = malloc(IV_LENGTH)))
		{
			err = -ENOMEM;
			goto exit_session;
		}
		memcpy(session->iv, packet + SESSION_PACKET_INIT_IV_OFFSET, IV_LENGTH);
		memcpy(session->nrfaddress.addr, packet + SESSION_PACKET_ADDRESS_OFFSET, ADDRESS_LENGTH);
		session->nrfaddress.len = ADDRESS_LENGTH;
		memcpy(session->keyid, packet + SESSION_PACKET_INIT_KEYID_OFFSET, sizeof(uint16_t));
		session->state = SESSION_STATE_NEW;
		return 0;
exit_session:
		free_session(session);
	}
exit_err:
	return err;
}
