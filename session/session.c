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

int handler_find_session_by_idab(enum id_side id_side, struct session_handler* handler, uint16_t id, struct session** session)
{
	unsigned int len = llist_length(handler->sessions);
	while(len-- > 0)
	{
		handler_get_session_at_index(handler, session, len);
		switch(id_side)
		{
			case(ID_A):
				if(id == (*session)->id.id_a)
					return 0;
				break;
			case(ID_B):
				if(id == (*session)->id.id_b)
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
	if(session->flags.aes_init)
	{
		aes_free(&session->aes_enc);
		aes_free(&session->aes_dec);
	}
	if(session->handler)
	{
		handler_remove_session(session->handler, session);
	}
	free(session);
}

struct session_handler* alloc_session_handler(void* ctx, void (*send_packet)(void* ctx, session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen), void (*recv_packet)(void* ctx, session* session, unsigned char* data, uint8_t datalen))
{
	struct session_handler* handler = malloc(sizeof(struct session_handler));
	if(handler)
	{
		memset(handler, 0, sizeof(struct session_handler));
		handler->ctx = ctx;
		handler->send_packet = send_packet;
		handler->recv_packet = recv_packet;
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

int session_init_challenge_rxtx(enum role role, struct session* session, unsigned char* challenge, uint8_t len)
{
	switch(role)
	{
		case(ROLE_RX):
			if(len != CHALLENGE_RND_LENGTH)
			{
				return -EINVAL;
			}
			memcpy(session->challenge_rx + CHALLENGE_CNT_LENGTH, challenge, len);
			break;
		case(ROLE_TX):
			if(len > CHALLENGE_RND_LENGTH)
			{
				return -EINVAL;
			}
			memcpy(session->challenge_tx + CHALLENGE_CNT_LENGTH, challenge, len);
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
			memcpy(session->challenge_rx, &session->cnt.rx, CHALLENGE_CNT_LENGTH);			
			break;
		case(ROLE_TX):
			memcpy(session->challenge_tx, &session->cnt.tx, CHALLENGE_CNT_LENGTH);
			break;
		default:
			return -EINVAL;
	}
	return 0;
}

int session_generate_challenge_rxtx(enum role role, struct session* session, unsigned char* buff, uint8_t len)
{
	if(len < CHALLENGE_RND_LENGTH)
	{
		return -EINVAL;
	}
	switch(role)
	{
		case ROLE_RX:
			memcpy(session->challenge_rx, &session->cnt.rx, CHALLENGE_CNT_LENGTH);
			prng_bytes(buff, CHALLENGE_RND_LENGTH);
			memcpy(session->challenge_rx + CHALLENGE_CNT_LENGTH, buff, CHALLENGE_RND_LENGTH);
			break;
		case ROLE_TX:
			memcpy(session->challenge_tx, &session->cnt.tx, CHALLENGE_CNT_LENGTH);
			prng_bytes(buff, CHALLENGE_RND_LENGTH);
			memcpy(session->challenge_tx + CHALLENGE_CNT_LENGTH, buff, CHALLENGE_RND_LENGTH);
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
	int err = 0;
	unsigned char* digest = malloc(hmaclen);
	if(!digest)
	{
		err = -ENOMEM;
		goto exit_err;
	}
	if((err = hmac_sha1_err(msg, msglen, session->key->key, KEY_LENGTH, digest, hmaclen)) < 0)
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
	if((err = session_generate_challenge_rx(session, packet + SESSION_PACKET_CHALLENGE_OFFSET, CHALLENGE_RND_LENGTH)))
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

void session_set_tx_data(struct session* session, unsigned char* data, uint8_t len)
{
	session->tx_data.data = data;
	session->tx_data.pos = data;
	session->tx_data.end = data + len;
}

int session_send_packets(struct session* session)
{
	int err;
	uint16_t len;
	while((len = session_len_tx_data(session)))
	{
		if(len > DATA_LENGTH)
			len = DATA_LENGTH;
		unsigned char* packet = malloc(SESSION_PACKET_DATA_LEN);
		if(!packet)
		{
			err = -ENOMEM;
			goto exit_err;
		}
		memset(packet, 0, SESSION_PACKET_DATA_LEN);
		memcpy(packet, &session->id, sizeof(struct sessionid));
		len = session_read_tx_data(session, packet + SESSION_PACKET_DATA_OFFSET, len);
		memcpy(packet + SESSION_PACKET_DATA_LENGTH_OFFSET, &len, DATA_LENGTH_LENGTH);
#ifdef VISUAL_DEBUG
		printf("ENC: ");
		for(int i = 0; i < DATA_LENGTH; i++)
		{
			printf("%c", (packet + SESSION_PACKET_DATA_OFFSET)[i]);
		}
		printf("\n");
#endif
		aes_encrypt(&session->aes_enc, packet + SESSION_PACKET_DATA_OFFSET, DATA_LENGTH);
#ifdef VISUAL_DEBUG
		printf("hex(ENC): ");
		for(int i = 0; i < DATA_LENGTH; i++)
		{
			printf("%02x ", (packet + SESSION_PACKET_DATA_OFFSET)[i]);
		}
		printf("\n");
#endif
		unsigned char* msg = malloc(HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + CHALLENGE_LENGTH);
		if(!msg)
		{
			err = -ENOMEM;
			goto exit_packet;
		}
		memcpy(msg, packet, SESSION_PACKET_DATA_LEN);
		memcpy(msg + HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, session->challenge_tx, CHALLENGE_LENGTH);
		if((err = hmac_sha1_err(msg, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + CHALLENGE_LENGTH, session->key->key, KEY_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)) < 0)
		{
			goto exit_msg;
		}
		session_send_packet(session, packet, SESSION_PACKET_DATA_LEN);
		err = 0;
exit_msg:
		free(msg);
exit_packet:
		free(packet);
	}
exit_err:
	return err;
}

int session_validate_and_maybe_decrypt_packet(uint8_t decrypt, struct session* session, unsigned char* packet, uint8_t packetlen, unsigned char* hmac, uint8_t hmaclen)
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
	if(decrypt)
	{
#ifdef VISUAL_DEBUG
		printf("hex(DEC): ");
		for(int i = 0; i < DATA_LENGTH; i++)
		{
			printf("%02x ", (fulldata + SESSION_PACKET_DATA_OFFSET)[i]);
		}
		printf("\n");
#endif
		aes_decrypt(&session->aes_dec, packet + SESSION_PACKET_DATA_OFFSET, DATA_LENGTH);
#ifdef VISUAL_DEBUG
		printf("DEC: ");
		for(int i = 0; i < DATA_LENGTH; i++)
		{
			printf("%c", (packet + SESSION_PACKET_DATA_OFFSET)[i]);
		}
		printf("\n");
#endif
	}
	free(fulldata);
exit_err:
	return err;
}

#define session_validate_packet(...) session_validate_and_maybe_decrypt_packet(false, __VA_ARGS__)
#define session_validate_and_decrypt_packet(...) session_validate_and_maybe_decrypt_packet(true, __VA_ARGS__)


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
			memcpy(&session->id, packet, HEADER_LENGTH);
			session_init_challenge_tx(session, packet + SESSION_PACKET_CHALLENGE_OFFSET, CHALLENGE_RND_LENGTH);
			session->state = SESSION_STATE_AUTH;
			session->cnt.rx++;
			session_update_challenge_rx(session);
			memcpy(session->iv_dec, packet + SESSION_PACKET_AUTH_IV_OFFSET, IV_LENGTH);
			aes_init_decrypt_128(&session->aes_dec, session->iv_dec, IV_LENGTH, session->key->key, KEY_LENGTH);
			free(session->iv_dec);
			session->iv_dec = NULL;
			aes_init_encrypt_128(&session->aes_enc, session->iv_enc, IV_LENGTH, session->key->key, KEY_LENGTH);
			free(session->iv_enc);
			session->iv_enc = NULL;
			session->flags.aes_init = 1;
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
			aes_init_decrypt_128(&session->aes_dec, session->iv_dec, IV_LENGTH, session->key->key, KEY_LENGTH);
			free(session->iv_dec);
			session->iv_dec = NULL;
			aes_init_encrypt_128(&session->aes_enc, session->iv_enc, IV_LENGTH, session->key->key, KEY_LENGTH);
			free(session->iv_enc);
			session->iv_enc = NULL;
			session->flags.aes_init = 1;
			if((err = session_validate_and_decrypt_packet(session, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)))
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
			if((err = session_validate_and_decrypt_packet(session, packet, HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH, packet + SESSION_PACKET_AUTH_HMAC_OFFSET, HMAC_LENGTH)))
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
	while(!handler_find_session_by_idab(id_side, handler, id, &session));
	return id;
}

#define handler_get_free_ida(...) handler_get_free_idab(ID_A, __VA_ARGS__)
#define handler_get_free_idb(...) handler_get_free_idab(ID_B, __VA_ARGS__)

struct session* handler_open_session(struct session_handler* handler, unsigned char* keyid, unsigned char* address, uint8_t addrlen, unsigned char* peeraddr, uint8_t peeraddrlen, unsigned char* data, uint8_t datalen)
{
	struct sessionid id;
	struct session* session = NULL;
	if(addrlen != ADDRESS_LENGTH)
	{
		goto exit_err;
	}
	id.id_b = 0;
	id.id_a = handler_get_free_ida(handler);	
	session = alloc_session(handler, &id);
	if(!session)
	{
		goto exit_err;
	}
	session->key = keychain_get_key(handler->keychain, keyid);
	if(!session->key)
	{
		goto exit_session;
	}
	memcpy(session->peeraddress.addr, peeraddr, peeraddrlen);
	session->peeraddress.len = peeraddrlen;
	session_set_tx_data(session, data, datalen);
	if(!(session->iv_dec = malloc(IV_LENGTH)))
	{
		goto exit_session;
	}
	if(!(session->iv_enc = malloc(IV_LENGTH)))
	{
		goto exit_session;
	}
	prng_bytes(session->iv_enc, IV_LENGTH);
	unsigned char* packet = malloc(SESSION_PACKET_INIT_LEN);
	if(!packet)
	{
		goto exit_session;
	}
	if(session_prepare_packet(packet, session))
	{
		goto exit_packet;
	}
	memcpy(packet + SESSION_PACKET_ADDRESS_OFFSET, address, addrlen);
	memcpy(packet + SESSION_PACKET_INIT_IV_OFFSET, session->iv_enc, IV_LENGTH);
	memcpy(packet + SESSION_PACKET_INIT_KEYID_OFFSET, keyid, KEYID_LENGTH);
	session_send_packet(session, packet, SESSION_PACKET_INIT_LEN);
	free(packet);
	return session;
exit_packet:
	free(packet);
exit_session:
	free_session(session);
exit_err:
	return NULL;
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
	if(!id.id_a)
	{
		err = -EINVAL;
		goto exit_err;
	}
	if(id.id_b)
	{
		// Find session by id_a
		if((err = handler_find_session_by_ida(handler, id.id_a, &session)))
		{
			goto exit_err;
		}
		err = session_process_packet(session, packet, len);
	}
	else
	{
		if(!id.id_a || len < SESSION_PACKET_INIT_LEN)
		{
			err = -EINVAL;
			goto exit_err;
		}
		// New session
		id.id_b = handler_get_free_idb(handler);
		if(!(session = alloc_session(handler, &id)))
		{
			err = -ENOMEM;
			goto exit_err;
		}
		// Look up keyid
		session->key = keychain_get_key(handler->keychain, packet + SESSION_PACKET_INIT_KEYID_OFFSET);
		if(!session->key)
		{
			err = -EINVAL;
			goto exit_session;
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
		prng_bytes(session->iv_enc, IV_LENGTH);
		memcpy(session->iv_dec, packet + SESSION_PACKET_INIT_IV_OFFSET, IV_LENGTH);
		memcpy(session->peeraddress.addr, packet + SESSION_PACKET_ADDRESS_OFFSET, ADDRESS_LENGTH);
		session->peeraddress.len = ADDRESS_LENGTH;
		session_init_challenge_tx(session, packet + SESSION_PACKET_CHALLENGE_OFFSET, CHALLENGE_RND_LENGTH);
		session->state = SESSION_STATE_NEW;
		session->cnt.rx++;
		session_update_challenge_rx(session);	

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
		memcpy(txpacket + SESSION_PACKET_AUTH_IV_OFFSET, session->iv_enc, IV_LENGTH);
		unsigned char* msg = malloc(HEADER_AND_CHALLENGE + IV_LENGTH + CHALLENGE_LENGTH);
		if(!msg)
		{
			err = -ENOMEM;
			goto exit_packet;
		}
		// Copy packet up to hmac
		memcpy(msg, txpacket, HEADER_AND_CHALLENGE + IV_LENGTH);
		// Copy challenge of received packet
		memcpy(msg + SESSION_PACKET_NEW_HMAC_OFFSET, session->challenge_tx, CHALLENGE_LENGTH);
		if((err = hmac_sha1_err(msg, HEADER_AND_CHALLENGE + IV_LENGTH + CHALLENGE_LENGTH, session->key->key, KEY_LENGTH, txpacket + SESSION_PACKET_NEW_HMAC_OFFSET, HMAC_LENGTH)) < 0)
		{
			goto exit_msg;
		}
		session_send_packet(session, txpacket, SESSION_PACKET_AUTH_LEN);
		free(msg);
		free(txpacket);
		return 0;
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
