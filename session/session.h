#ifndef _SESSION_H_
#define _SESSION_H_

#include <stdint.h>

#include "../util/list.h"
#include "../util/aes.h"

#define SESSION_PACKET_LEN 32

#define SESSION_MIN_PACKET_LEN	28
#define SESSION_PACKET_INIT_LEN	31
#define SESSION_PACKET_AUTH_LEN	28
#define SESSION_PACKET_DATE_LEN	28

#define SESSION_PACKET_CHALLENGE_OFFSET		4
#define SESSION_PACKET_ADDRESS_OFFSET		8
#define SESSION_PACKET_INIT_IV_OFFSET		13
#define SESSION_PACKET_AUTH_IV_OFFSET		8
#define SESSION_PACKET_INIT_KEYID_OFFSET	29

#define ADDRESS_LENGTH 5

#define IV_LENGTH 16
#define KEY_LENGTH 16

#define CHALLENGE_LENGTH 4
#define HMAC_LENGTH 4

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
	unsigned char* addr;
	uint8_t len;
} nrfaddress;

typedef struct sessionid {
	uint16_t id_a;
	uint16_t id_b;
} sessionid;

typedef struct psk {
	//unsigned char[KEY_LENGTH] key;
	unsigned char* key;
} psk;

typedef struct session {
	struct session_handler* handler;
	struct sessionid id;
	struct nrfaddress peeraddress;
	struct aes_ctx aes;
	struct psk key;
	unsigned char challenge[CHALLENGE_LENGTH];
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
} session_handler;

#define HEADER_LENGTH sizeof(struct sessionid)
#define HEADER_AND_CHALLENGE HEADER_LENGTH + CHALLENGE_LENGTH

int handler_process_packet(struct session_handler* handler, unsigned char* packet, uint8_t len);
struct session* alloc_session(struct session_handler* handler, struct sessionid* id);
struct session_handler* alloc_session_handler();
int handler_get_session_at_index(struct session_handler* handler, struct session** session, int index);

#endif
