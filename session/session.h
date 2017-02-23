#ifndef _SESSION_H_
#define _SESSION_H_

#include <stdint.h>

#include "../util/list.h"
#include "../util/aes.h"

#define SESSION_PACKET_LEN 32

#define SESSION_MIN_PACKET_LEN	28
#define SESSION_PACKET_INIT_LEN	31
#define SESSION_PACKET_AUTH_LEN	28
#define SESSION_PACKET_DATA_LEN	24

#define SESSION_PACKET_CHALLENGE_OFFSET		4
#define SESSION_PACKET_ADDRESS_OFFSET		8
#define SESSION_PACKET_INIT_IV_OFFSET		13
#define SESSION_PACKET_AUTH_IV_OFFSET		8
#define SESSION_PACKET_INIT_KEYID_OFFSET	29
#define SESSION_PACKET_NEW_HMAC_OFFSET		24
#define SESSION_PACKET_AUTH_HMAC_OFFSET		21

#define ADDRESS_LENGTH 5

#define IV_LENGTH 16
#define KEY_LENGTH 16

#define CHALLENGE_LENGTH 4
#define HMAC_LENGTH 4

#define DATA_LENGTH_LENGTH 1
#define DATA_LENGTH 16

enum session_state {
	SESSION_STATE_INIT,
	SESSION_STATE_NEW,
	SESSION_STATE_AUTH,
	SESSION_STATE_DEAD
};

struct session_handler;

typedef struct aeskey {
	unsigned char* key;
	unsigned char* iv;
} aeskey;

typedef struct nrfaddress {
	unsigned char addr[ADDRESS_LENGTH];
	uint8_t len;
} nrfaddress;

typedef struct sessionid {
	uint16_t id_a;
	uint16_t id_b;
} sessionid;

typedef struct psk {
	unsigned char key[KEY_LENGTH];
} psk;

typedef struct packet_counter {
	uint16_t rx;
	uint16_t tx;
} packet_counter;

typedef struct session {
	struct session_handler* handler;
	struct sessionid id;
	struct nrfaddress peeraddress;
	struct aes_ctx aes;
	struct psk key;
	struct packet_counter cnt;
	unsigned char challenge_tx[CHALLENGE_LENGTH];
	unsigned char challenge_rx[CHALLENGE_LENGTH];
	unsigned char* iv_dec;
	unsigned char* iv_enc;
	uint32_t timeout;
	uint16_t keyid;
	enum session_state state;
	struct {
		uint8_t initiator : 1;
	} flags;
	
} session;

typedef struct session_handler {
	uint16_t packetcnt;
	struct llist_head* sessions;
	void* ctx;
	void (*send_packet)(void* ctx, session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen);
	void (*recv_packet)(void* ctx, session* session, unsigned char* data, uint8_t datalen); 
} session_handler;

#define HEADER_LENGTH sizeof(struct sessionid)
#define HEADER_AND_CHALLENGE HEADER_LENGTH + CHALLENGE_LENGTH

int handler_process_packet(struct session_handler* handler, unsigned char* packet, uint8_t len);
struct session* alloc_session(struct session_handler* handler, struct sessionid* id);
struct session_handler* alloc_session_handler();
int handler_get_session_at_index(struct session_handler* handler, struct session** session, int index);

#endif
