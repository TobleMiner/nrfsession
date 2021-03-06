#ifndef _SESSION_H_
#define _SESSION_H_

#include <stdint.h>

#define SESSION_PACKET_LEN 32

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define SESSION_MIN_PACKET_LEN	min(SESSION_PACKET_INIT_LEN, min(SESSION_PACKET_AUTH_LEN, SESSION_PACKET_DATA_LEN))
#define SESSION_PACKET_INIT_LEN	HEADER_LENGTH + CHALLENGE_RND_LENGTH + ADDRESS_LENGTH + IV_LENGTH + KEYID_LENGTH
#define SESSION_PACKET_AUTH_LEN	HEADER_LENGTH + CHALLENGE_RND_LENGTH + IV_LENGTH + HMAC_LENGTH
#define SESSION_PACKET_DATA_LEN	HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH + HMAC_LENGTH

#define SESSION_PACKET_CHALLENGE_OFFSET		HEADER_LENGTH
#define SESSION_PACKET_ADDRESS_OFFSET		HEADER_LENGTH + CHALLENGE_RND_LENGTH
#define SESSION_PACKET_INIT_IV_OFFSET		HEADER_LENGTH + CHALLENGE_RND_LENGTH + ADDRESS_LENGTH
#define SESSION_PACKET_AUTH_IV_OFFSET		HEADER_LENGTH + CHALLENGE_RND_LENGTH
#define SESSION_PACKET_INIT_KEYID_OFFSET	HEADER_LENGTH + CHALLENGE_RND_LENGTH + ADDRESS_LENGTH + IV_LENGTH
#define SESSION_PACKET_NEW_HMAC_OFFSET		HEADER_LENGTH + CHALLENGE_RND_LENGTH + IV_LENGTH
#define SESSION_PACKET_AUTH_HMAC_OFFSET		HEADER_LENGTH + DATA_LENGTH_LENGTH + DATA_LENGTH
#define SESSION_PACKET_DATA_LENGTH_OFFSET	HEADER_LENGTH
#define SESSION_PACKET_DATA_OFFSET		HEADER_LENGTH + DATA_LENGTH_LENGTH

#define ADDRESS_LENGTH 5

#define IV_LENGTH 16
#define KEY_LENGTH 16
#define KEYID_LENGTH sizeof(uint16_t)

#define CHALLENGE_LENGTH CHALLENGE_RND_LENGTH+ CHALLENGE_CNT_LENGTH
#define CHALLENGE_CNT_LENGTH sizeof(uint16_t)
#define CHALLENGE_RND_LENGTH 4
#define HMAC_LENGTH 4

#define DATA_LENGTH_LENGTH 1
#define DATA_LENGTH 16

#include "../util/list.h"
#include "../util/aes.h"
#include "../util/keychain.h"

enum session_state {
	SESSION_STATE_INIT,
	SESSION_STATE_NEW,
	SESSION_STATE_AUTH,
	SESSION_STATE_DEAD
};

struct session_handler;

typedef struct nrfaddress {
	unsigned char addr[ADDRESS_LENGTH];
	uint8_t len;
} nrfaddress;

typedef struct sessionid {
	uint16_t id_a;
	uint16_t id_b;
} sessionid;

typedef struct packet_counter {
	uint16_t rx;
	uint16_t tx;
} packet_counter;

typedef struct tx_data {
	unsigned char* data;
	unsigned char* pos;
	unsigned char* end;
} tx_data;

typedef struct session {
	struct session_handler* handler;
	struct sessionid id;
	struct nrfaddress peeraddress;
	struct aes_ctx aes_dec;
	struct aes_ctx aes_enc;
	struct key* key;
	struct packet_counter cnt;
	struct tx_data tx_data;
	unsigned char challenge_tx[CHALLENGE_LENGTH];
	unsigned char challenge_rx[CHALLENGE_LENGTH];
	unsigned char* iv_dec;
	unsigned char* iv_enc;
	uint32_t timeout;
	enum session_state state;
	struct {
		uint8_t initiator : 1;
		uint8_t aes_init : 1;
	} flags;
	
} session;

typedef struct session_handler {
	uint16_t packetcnt;
	struct llist_head* sessions;
	struct keychain* keychain;
	void* ctx;
	void (*send_packet)(void* ctx, session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen);
	void (*recv_packet)(void* ctx, session* session, unsigned char* data, uint8_t datalen); 
} session_handler;

#define HEADER_LENGTH sizeof(struct sessionid)
#define HEADER_AND_CHALLENGE HEADER_LENGTH + CHALLENGE_RND_LENGTH

enum role {
        ROLE_RX,
        ROLE_TX
};

int handler_process_packet(struct session_handler* handler, unsigned char* packet, uint8_t len);
struct session_handler* alloc_session_handler(void* ctx, void (*send_packet)(void* ctx, session* session, unsigned char* addr, uint8_t addrlen, unsigned char* data, uint8_t datalen), void (*recv_packet)(void* ctx, session* session, unsigned char* data, uint8_t datalen));
int handler_get_session_at_index(struct session_handler* handler, struct session** session, int index);
struct session* handler_open_session(struct session_handler* handler, unsigned char* keyid, unsigned char* address, uint8_t addrlen, unsigned char* peeraddr, uint8_t peeraddrlen, unsigned char* data, uint8_t datalen);
int session_update_challenge_rxtx(enum role role, struct session* session);
#define session_update_challenge_rx(...) session_update_challenge_rxtx(ROLE_RX, __VA_ARGS__)
#define session_update_challenge_tx(...) session_update_challenge_rxtx(ROLE_TX, __VA_ARGS__)
void free_session(struct session* session);
void free_session_handler(struct session_handler* handler);

#endif
