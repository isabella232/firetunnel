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

//*******************************************************************
// header compression scheme based on RFC 2507
// the session structure stores the header bytes that don't change
// the bytes that change are sent out  -> structure NewHeader
//*******************************************************************
// MAC, IP, TCP or UDP
typedef struct l4_session_t {	// offset
	uint8_t mac[14];	// 0 - ethernet header
	uint16_t ver_ihl_tos;	// 14 - ip
	uint16_t len;		// 16 - use a default value and recalculate in decompress()
//	uint16_t id;		// 18
	uint16_t offset;	// 20
	uint8_t ttl;		// 22
	uint8_t protocol;	// 23
	uint16_t checksum;	// 24 - use a default value and recalculate in decompress()
	uint8_t addr[8];	// 26
	uint8_t port[4];	// 34
} __attribute__((__packed__)) L4Session;	// 38
#define FULL_HEADER_LEN 38

// fields not included in params above
typedef struct new_header_t {	// offset
	uint16_t id;		// 18
} __attribute__((__packed__)) NewHeader;

int compress_l4_size(void) {
	return FULL_HEADER_LEN - sizeof(NewHeader);
}

// fill up a session structure; ptr is the start of eth packet
static void set_session(uint8_t *ptr, L4Session *s) {
	assert(s);
	memcpy(s->mac, ptr, 14);
	memcpy(&s->ver_ihl_tos, ptr + 14, 2);
	s->len = 0xc28a;
	s->protocol = *(ptr + 23);
	memcpy(&s->offset, ptr + 20, 2);
	s->ttl = *(ptr + 22);
	s->checksum = 0x55aa;
	memcpy(s->addr, ptr + 26, 8);
	memcpy(s->port, ptr + 34, 4);
}

static void print_session(L4Session *s) {
	// IP
	uint32_t ip1;
	uint32_t ip2;
	memcpy(&ip1, s->addr, 4);
	ip1 = ntohl(ip1);
	memcpy(&ip2, s->addr + 4, 4);
	ip2 = ntohl(ip2);

	// TCP/UDP
	uint16_t port1;
	uint16_t port2;
	memcpy(&port1, s->port, 2);
	port1 = ntohs(port1);
	memcpy(&port2, s->port + 2, 2);
	port2 = ntohs(port2);

	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n", PRINT_IP(ip1), port1, PRINT_IP(ip2), port2);
}

static void set_new_header(uint8_t *ptr, NewHeader *h) {
	assert(h);
	memcpy(&h->id, ptr + 18, 2);
}


//*******************************************************************
// An IP connection has a packet session associated, and counts the packets
// Tracking 256 IP connections in each directions
//*******************************************************************
typedef struct l4_connection_t {
	int active;	// TODO: get rid of active
	int cnt;	// packet counter for session s
	L4Session s;
} L4Connection;
static L4Connection connection_s2c[256];
static L4Connection connection_c2s[256];

void compress_l4_init(void) {
	memset(connection_s2c, 0, sizeof(connection_s2c));
	memset(connection_c2s, 0, sizeof(connection_c2s));
}

void print_compress_l4_table(int direction) {
	L4Connection *conn = (direction == S2C)? &connection_s2c[0]: &connection_c2s[0];
	printf("Compression L4 tun tx table:\n");
	printf("   cache collision %0.2f%%, total packets %u\n",
		collision_ratio(tunnel.stats.compress_hash_total_l4, tunnel.stats.compress_hash_collision_l4),
		tunnel.stats.compress_hash_total_l4);
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
void update_compress_l4_stats(void) {
	L4Connection *conn = (arg_server)? connection_s2c: connection_c2s;
	int cnt = 0;
	int i;
	for (i = 0; i < 256; i++, conn++)
		if (conn->active)
			cnt++;

	tunnel.stats.compress_hash_cnt_l4 = cnt;
}


// ptr points at the begining of Ethernet packet
// start a new session if this is a new packet (return 0)
// for an existing session:
//          send packet uncompressed from time to time (cnt 1, 2, 3, 8, 16 etc... - return 0)
//          else send packet compressed (return 1)
// store the hash in sid if sid not null
int classify_l4(uint8_t *pkt, uint8_t *sid, int direction) {
	int rv = 0;
	L4Session s;
	set_session(pkt, &s);

	uint8_t hash = 0;
	unsigned i;
	uint8_t *ptr = (uint8_t *) &s;
	for ( i = 0; i < sizeof(s); i++, ptr++)
		hash ^= *ptr;
	if (sid) {
		*sid = hash;
		tunnel.stats.compress_hash_total_l4++;
	}

	L4Connection *conn = (direction == S2C)? &connection_s2c[hash]: &connection_c2s[hash];
	if (conn->active) {
		if (memcmp(&s, &conn->s, sizeof(L4Session)) == 0) {
			conn->cnt++;
			rv = compress_shaper(conn->cnt);
		}
		else {
			dbg_printf("replace l4 hash %d\n", hash);
			tunnel.stats.compress_hash_collision_l4++;
			memcpy(&conn->s, &s, sizeof(L4Session));
			conn->cnt = 1;
		}
	}
	else {
		memcpy(&conn->s, &s, sizeof(L4Session));
		conn->cnt = 1;
		conn->active = 1;
	}

	return rv;
}

int compress_l4(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
//uint16_t len;
//memcpy(&len, pkt + 14 + 2, 2);
//len = ntohs(len);
//printf("len %u, nbytes %d\n", len, nbytes);

//packet set to eth start
//printf("compress:\n");
//dbg_memory(pkt + 14, 20 + 8);


	(void) direction;
	(void) nbytes;
	(void) sid;
	tunnel.stats.udp_tx_compressed_pkt++;
	NewHeader h;
	set_new_header(pkt, &h);
	memcpy(pkt + FULL_HEADER_LEN - sizeof(h), &h, sizeof(h));

	return FULL_HEADER_LEN - sizeof(NewHeader);
}

int decompress_l4(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	L4Connection *conn = (direction == S2C)? &connection_s2c[sid]: &connection_c2s[sid];
	L4Session *s = &conn->s;
	NewHeader h;
	memcpy(&h, pkt, sizeof(h));

	// build the real header
	pkt += sizeof(h) - FULL_HEADER_LEN;

	memcpy(pkt, s->mac, 14);
	memcpy(pkt + 14, &s->ver_ihl_tos, 2);

	// recalculate len
	uint16_t len = nbytes + FULL_HEADER_LEN - sizeof(h) - 14;
//printf("nbytes %d, new len %d\n", nbytes, len);
	len = htons(len);
	memcpy(pkt + 16, &len, 2);

	memcpy(pkt + 18, &h.id, 2);
	memcpy(pkt + 20, &s->offset, 2);
	*(pkt + 22) = s->ttl;
	*(pkt + 23) = s->protocol;
	memcpy(pkt + 26, s->addr, 8);

	// calculate ip checksum
	memset(pkt + 24, 0, 2);
	uint16_t ipptr[10];	// we could be misaligned in memory
	memcpy(&ipptr[0], pkt + 14, 20);
	uint32_t r = 0;
	int i;
	for (i = 0; i < 10; i++)
		r += ipptr[i];
	uint16_t checksum = (uint16_t) (r & 0xffff) + (uint16_t) (r >> 16);
	checksum = ~checksum;
	memcpy(pkt + 24, &checksum, 2);

	memcpy(pkt + 34, s->port, 4);

//packet set to eth start
//printf("decompress:\n");
//dbg_memory(pkt + 14, 20 + 8);


	return FULL_HEADER_LEN - sizeof(NewHeader);
}
