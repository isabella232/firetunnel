/*
 * Copyright (C) 2018 Firetunnel Authors
 *
 * This file is part of firetunnel project
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include "firetunnel.h"

// header compression scheme based on RFC 2507
// the session structure stores the bytes that don't change
//    - actually in the case of L2 MAC we store everything!
typedef struct mac_session_t {	// offset
	uint8_t mac[14];	// 0 - ethernet header
} __attribute__((__packed__)) MacSession;	// 38
#define FULL_HEADER_LEN 14

int compress_l2_size(void) {
	return FULL_HEADER_LEN ;
}

// fill up a session structure; ptr is the start of eth packet
static void set_session(uint8_t *ptr, MacSession *s) {
	assert(s);
	memcpy(s->mac, ptr, 14);
}

static void print_session(MacSession *s) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", PRINT_MAC(s->mac));
	printf("%02x:%02x:%02x:%02x:%02x:%02x ", PRINT_MAC(s->mac + 6));
	printf("%02x%02x\n", s->mac[12], s->mac[13]);
}


//*******************************************************************
// A MAC connection has a packet session associated, and counts the packets
// Tracking 256 IP connections in each directions
//*******************************************************************
typedef struct mac_connection_t {
	int active;	// TODO: get rid of active
	int cnt;	// packet counter for session s
	MacSession s;
} MacConnection;
static MacConnection connection_s2c[256];
static MacConnection connection_c2s[256];

void compress_l2_init(void) {
	memset(connection_s2c, 0, sizeof(connection_s2c));
	memset(connection_c2s, 0, sizeof(connection_c2s));
}

void print_compress_l2_table(int direction) {
	MacConnection *conn = (direction == S2C)? connection_s2c: connection_c2s;
	printf("Compression L2 hash table:\n");
	int i;
	for (i = 0; i < 256; i++, conn++) {
		if (conn->active) {
			char buf[22];
			snprintf(buf, 22, "   %d:%d", i, conn->cnt);
			printf("%-21s", buf);
			print_session(&conn->s);
		}
	}
}


// ptr points at the begining of Ethernet packet
// start a new session if this is a new packet (return 0)
// for an existing session:
//          send packet uncompressed from time to time (cnt 1, 2, 3, 8, 16 etc... - return 0)
//          else send packet compressed (return 1)
// store the hash in sid if sid not null
int classify_l2(uint8_t *pkt, uint8_t *sid, int direction) {
	int rv = 0; // send uncompressed packet
	MacSession s;
	set_session(pkt, &s);

	// calculate hash
	uint8_t hash = 0;
	unsigned i;
	uint8_t *ptr = (uint8_t *) &s;
	for ( i = 0; i < sizeof(s); i++, ptr++)
		hash ^= *ptr;
	if (sid)
		*sid = hash;

	MacConnection *conn = (direction == S2C)? &connection_s2c[hash]: &connection_c2s[hash];
	if (conn->active) {
		// is this our packet or a new one?
		if (memcmp(&s, &conn->s, sizeof(MacSession)) == 0) {
			conn->cnt++;
			int cnt = conn->cnt;

			if (cnt > 50 && cnt % 50)
				rv = 1;
			else if (cnt > 20 && cnt % 20)
				rv = 1;
			else if (cnt > 3 && cnt % 8)
				rv = 1;
		}
		else {
			// a new packet; replace the existing session
			dbg_printf("replace l2 hash %d\n", hash);
			tunnel.stats.compress_hash_collision++;
			memcpy(&conn->s, &s, sizeof(MacSession));
			conn->cnt = 1;
		}
	}
	else {
		// we are seeing this packet for the first time
		// store a new session
		memcpy(&conn->s, &s, sizeof(MacSession));
		conn->cnt = 1;
		conn->active = 1;
	}

	return rv;
}

int compress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	// since full MAC was stored in the session structure already, there is nothing to be done
	(void) pkt;
	(void) nbytes;
	(void) sid;
	(void) direction;
	tunnel.stats.udp_tx_compressed_pkt++;
	return FULL_HEADER_LEN;
}

int decompress_l2(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	(void) nbytes;
	MacConnection *conn = (direction == S2C)? &connection_s2c[sid]: &connection_c2s[sid];
	MacSession *s = &conn->s;

	// build the real header
	pkt -= FULL_HEADER_LEN;
	memcpy(pkt, s->mac, 14);

	return FULL_HEADER_LEN;
}
