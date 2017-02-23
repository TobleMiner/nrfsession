#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include "session.h"
#include "../util/list.h"
#include "../util/prng.h"
#include "../util/hmac.h"

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
		if(!memcmp(id, &session->id, sizeof(struct session)))
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

int handler_add_session(struct session_handler* handler, struct session* session)
{
	return llist_append(&handler->sessions, session);
}

void handler_remove_session(struct session_handler* handler, struct session* session)
{
	llist_remove_data(&handler->sessions, session);
}

int handler_num_sessions(struct session_handler* handler)
{
	return llist_length(handler->sessions);
}

struct session* alloc_session(struct session_handler* handler, struct sessionid* id)
{
	struct session* session = malloc(sizeof(struct session));
	if(!session)
	{
		goto exit_err;
	}
	memset(session, 0, sizeof(struct session));
	memcpy(&session->id, id, sizeof(struct sessionid));
	session->handler = handler;
	if(handler && handler_add_session(handler, session))
	{
		free(session);
		session = NULL;
	}
exit_err:
	return session;
}

void free_session(struct session* session)
{
	if(session->iv_enc)
	{
		free(session->iv_enc);
	}
	if(session->iv_dec)
	{
		free(session->iv_dec);
	}
	if(session->handler)
	{
		handler_remove_session(session->handler, session);
	}
	free(session);
}

struct session_handler* alloc_session_handler(void* ctx, void (*send_packet)(unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen))
{
	struct session_handler* handler = malloc(sizeof(struct session_handler));
	if(handler)
	{
		memset(handler, 0, sizeof(struct session_handler));
		handler->ctx = ctx;
		handler->send_packet = send_packet;
	}
	return handler;
}

void free_session_handler(struct session_handler* handler)
{
	struct session* session;
	while(handler_num_sessions(handler))
	{
		handler_get_session_at_index(handler, &session, 0);
		free_session(session);
	}
	free(handler);
}

enum role {
	ROLE_RX,
	ROLE_TX
};

int session_init_challenge_rxtx(enum role role, struct session* session, unsigned char* challenge, uint8_t len)
{
	switch(role)
	{
		case(ROLE_RX):
			if(len != CHALLENGE_LENGTH - sizeof(typeof(session->cnt.rx)))
			{
				return -EINVAL;
			}
			memcpy(session->challenge_rx + sizeof(typeof(session->cnt.rx)), challenge + sizeof(typeof(session->cnt.rx)), len - sizeof(typeof(session->cnt.rx)));
			break;
		case(ROLE_TX):
			if(len != CHALLENGE_LENGTH - sizeof(typeof(session->cnt.tx)))
			{
				return -EINVAL;
			}
			memcpy(session->challenge_tx + sizeof(typeof(session->cnt.tx)), challenge + sizeof(typeof(session->cnt.tx)), len - sizeof(typeof(session->cnt.tx)));
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

#define session_init_challenge_rx(...) session_init_challenge_rxtx(ROLE_RX, __VA_ARGS__)
#define session_init_challenge_tx(...) session_init_challenge_rxtx(ROLE_TX, __VA_ARGS__)

int session_update_challenge_rxtx(enum role role, struct session* session)
{
	switch(role)
	{
		case(ROLE_RX):
			memcpy(session->challenge_rx, &session->cnt.rx, sizeof(typeof(session->cnt.rx)));			
			break;
		case(ROLE_TX):
			memcpy(session->challenge_tx, &session->cnt.tx, sizeof(typeof(session->cnt.tx)));
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

#define session_update_challenge_rx(...) session_update_challenge_rxtx(ROLE_RX, __VA_ARGS__)
#define session_update_challenge_tx(...) session_update_challenge_rxtx(ROLE_TX, __VA_ARGS__)

int session_generate_challenge_rxtx(enum role role, struct session* session, unsigned char* buff, uint8_t len)
{
	if(len != CHALLENGE_LENGTH)
	{
		return -EINVAL;
	}
	switch(role)
	{
		case ROLE_TX:
			if(sizeof(typeof(session->cnt.tx)) > len)
			{
				return -EINVAL;
			}
			memcpy(buff, &session->cnt.tx, sizeof(typeof(session->cnt.tx)));
			prng_bytes(buff + sizeof(typeof(session->cnt.tx)), len - sizeof(typeof(session->cnt.tx)));
			memcpy(session->challenge_tx, buff, len);
			break;
		case ROLE_RX:
			if(sizeof(typeof(session->cnt.rx)) > len)
			{
				return -EINVAL;
			}
			memcpy(buff, &session->cnt.rx, sizeof(typeof(session->cnt.rx)));
			prng_bytes(buff + sizeof(typeof(session->cnt.rx)), len - sizeof(typeof(session->cnt.rx)));
			memcpy(session->challenge_rx, buff, len);
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

#define session_generate_challenge_rx(...) session_generate_challenge_rxtx(ROLE_RX, __VA_ARGS__)
#define session_generate_challenge_tx(...) session_generate_challenge_rxtx(ROLE_TX, __VA_ARGS__)

void session_send_packet(struct session* session, unsigned char* packet, uint8_t len)
{
	session->handler->send_packet(session->handler->ctx, session, session->peeraddress.addr, ADDRESS_LENGTH, packet, len);
	session->cnt.tx++;
	session_update_challenge_tx(session);
}

void session_recv_packet(struct session* session, unsigned char* packet, uint8_t len)
{
	session->handler->recv_packet(session->handler->ctx, session, packet, len);
	session->cnt.rx++;
	session_update_challenge_rx(session);	
}

int session_validate_hmac(struct session* session, unsigned char* msg, uint8_t msglen, unsigned char* hmac, uint8_t hmaclen)
{
	int err;
	unsigned char* digest = malloc(hmaclen);
	if(!digest)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	if((err = hmac_sha1(msg, msglen, session->key.key, KEY_LENGTH, digest, hmaclen)) < 0)
	{
		goto exit_digest;
	}
	// TODO: REPLACE WITH CONST TIME MEMCMP!
	err = memcmp(digest, hmac, hmaclen);
exit_digest:
	free(digest);
exit_err:
	return err;
}

// fill header and challenge
int session_prepare_packet(unsigned char* packet, struct session* session)
{
	int err;
	memcpy(packet, &session->id, sizeof(struct sessionid));
	if((err = session_generate_challenge_rx(session, packet + SESSION_PACKET_CHALLENGE_OFFSET, CHALLENGE_LENGTH)))
	{
		goto exit_err;
	}
exit_err:
	return err;
}

uint16_t session_len_tx_data(struct session* session)
{
	if(session->tx_data.data)
	{
		return session->tx_data.end - session->tx_data.pos;
	}
	return 0;
}

uint8_t session_read_tx_data(struct session* session, unsigned char* buff, uint8_t maxlen)
{
	if(session->tx_data.data)
	{
		uint16_t diff = session->tx_data.end - session->tx_data.pos;
		if(diff > maxlen)
			diff = maxlen;
		memcpy(buff, session->tx_data.pos, diff);
		session->tx_data.pos += diff;
		return diff;
	}
	return 0;
}

int session_send_packets(struct session* session)
{
	int err;
	uint16_t len;
	while((len = session_len_tx_data(session)))
	{
		if(len > DATA_LENGTH)
			len = DATA_LENGTH;
		unsigned char* packet = malloc(HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + HMAC_LENGTH);
		if(!packet)
		{
			err = -ENOMEM;
			goto exit_err;
		}
		memcpy(packet, &session->id, sizeof(struct sessionid));
		len = session_read_tx_data(session, packet + HEADER_LENGTH + DATA_LENGTH_LENGTH, len);
		memcpy(packet + HEADER_LENGTH, &len, DATA_LENGTH_LENGTH);
		unsigned char* msg = malloc(HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + CHALLENGE_LENGTH);
		if(!msg)
		{
			err = -ENOMEM;
			goto exit_packet;
		}
		memcpy(msg, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH);
		memcpy(msg + HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, session->challenge_tx, CHALLENGE_LENGTH);
		if((err = hmac_sha1(msg, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + CHALLENGE_LENGTH, session->key.key, KEY_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)) < 0)
		{
			goto exit_msg;
		}
		session_send_packet(session, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + HMAC_LENGTH);
		err = 0;
exit_msg:
		free(msg);
exit_packet:
		free(packet);
	}
exit_err:
	return err;
}

int session_validate_packet(struct session* session, unsigned char* packet, uint8_t packetlen, unsigned char* hmac, uint8_t hmaclen)
{
	int err = 0;
	unsigned char* fulldata = malloc(packetlen + CHALLENGE_LENGTH);
	if(!fulldata)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	memcpy(fulldata, packet, packetlen);
	memcpy(fulldata + packetlen, session->challenge_rx, CHALLENGE_LENGTH);
	err = session_validate_hmac(session, fulldata, packetlen + CHALLENGE_LENGTH, hmac, hmaclen);
	free(fulldata);
exit_err:
	return err;
}

int session_process_packet(struct session* session, unsigned char* packet, uint8_t len)
{
	int err = 0;
	switch(session->state)
	{
		// Initiator receives auth response
		case(SESSION_STATE_INIT):
			if(len < SESSION_PACKET_AUTH_LEN)
			{
				err = -EINVAL;
				goto exit_err;
			}
			if((err = session_validate_packet(session, packet, HEADER_AND_CHALLENGE + IV_LENGTH, packet + SESSION_PACKET_NEW_HMAC_OFFSET, HMAC_LENGTH)))
			{
				goto exit_err;
			}
			session_init_challenge_tx(session, packet + HEADER_LENGTH, CHALLENGE_LENGTH);
			session->state = SESSION_STATE_AUTH;
			session->cnt.rx++;
			session_update_challenge_rx(session);
			// No processable data in packet, check if transmitable data present immediately
			session_send_packets(session);
			break;
		// Peer receives auth response
		case(SESSION_STATE_NEW):
			if(len < SESSION_PACKET_DATA_LEN)
			{
				err = -EINVAL;
				goto exit_err;
			}
			if((err = session_validate_packet(session, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)))
			{
				goto exit_err;
			}
			session->state = SESSION_STATE_AUTH;
			// Process received payload, transmit available data if any
			session_recv_packet(session, packet + HEADER_LENGTH + DATA_LENGTH_LENGTH, *(packet + HEADER_LENGTH));
			session_send_packets(session);
			break;
		// Any side receives data
		case SESSION_STATE_AUTH:
			if(len < SESSION_PACKET_DATA_LEN)
			{
				err = -EINVAL;
				goto exit_err;
			}
			if((err = session_validate_packet(session, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)))
			{
				goto exit_err;
			}
			// Process received payload, transmit available data if any
			session_recv_packet(session, packet + HEADER_LENGTH + DATA_LENGTH_LENGTH, *(packet + HEADER_LENGTH));
			session_send_packets(session);
			break;
		default:
			err = -EINVAL;
	}
exit_err:
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
	if(!id.id_a)
	{
		err = -EINVAL;
		goto exit_err;
	}
	if(id.id_b)
	{
		// Find session by id
		if((err = handler_find_session_by_id(handler, &id, session)))
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
		if(!(session->iv_dec = malloc(IV_LENGTH)))
		{
			err = -ENOMEM;
			goto exit_session;
		}
		if(!(session->iv_enc = malloc(IV_LENGTH)))
		{
			err = -ENOMEM;
			goto exit_session;
		}
		memcpy(session->iv_dec, packet + SESSION_PACKET_INIT_IV_OFFSET, IV_LENGTH);
		memcpy(session->peeraddress.addr, packet + SESSION_PACKET_ADDRESS_OFFSET, ADDRESS_LENGTH);
		session->peeraddress.len = ADDRESS_LENGTH;
		memcpy(&session->keyid, packet + SESSION_PACKET_INIT_KEYID_OFFSET, sizeof(uint16_t));
		session->state = SESSION_STATE_NEW;
		unsigned char* txpacket = malloc(HEADER_AND_CHALLENGE + IV_LENGTH + HMAC_LENGTH);
		if(!txpacket)
		{
			err = -ENOMEM;
			goto exit_session;
		}
		if((err = session_prepare_packet(txpacket, session)))
		{
			goto exit_packet;
		}
		prng_bytes(txpacket + HEADER_AND_CHALLENGE, IV_LENGTH);
		unsigned char* msg = malloc(HEADER_AND_CHALLENGE + IV_LENGTH + CHALLENGE_LENGTH);
		if(!msg)
		{
			err = -ENOMEM;
			goto exit_packet;
		}
		// Copy packet up to hmac
		memcpy(msg, txpacket, HEADER_AND_CHALLENGE + IV_LENGTH);
		// Copy challenge of received packet
		memcpy(msg + HEADER_AND_CHALLENGE + IV_LENGTH, packet + HEADER_LENGTH, CHALLENGE_LENGTH);
		session_init_challenge_tx(session, packet + HEADER_LENGTH, CHALLENGE_LENGTH);
		if((err = hmac_sha1(msg, HEADER_AND_CHALLENGE + IV_LENGTH + CHALLENGE_LENGTH, session->key.key, KEY_LENGTH, txpacket + HEADER_AND_CHALLENGE + IV_LENGTH, HMAC_LENGTH)) < 0)
		{
			goto exit_msg;
		}
		session_send_packet(session, packet, HEADER_AND_CHALLENGE + IV_LENGTH + HMAC_LENGTH);
		err = 0;
exit_msg:
		free(msg);
exit_packet:
		free(txpacket);
exit_session:
		free_session(session); // takes care of IVs
	}
exit_err:
	return err;
}
