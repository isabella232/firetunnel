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
// MAC and IP
typedef struct ip_session_t {	// offset
	uint8_t mac[14];	// 0 - ethernet header
	uint16_t ver_ihl_tos;	// 14 - ip
	uint16_t len;		// 16 - use a default value and recalculate in decompress()
//	uint16_t id;		// 18
	uint16_t offset;	// 20
	uint8_t ttl;		// 22
	uint8_t protocol;	// 23
	uint16_t checksum;	// 24 - use a default value and recalculate in decompress()
	uint8_t addr[8];	// 26
} __attribute__((__packed__)) IpSession;	// 34
#define FULL_HEADER_LEN 34

// fields not included in params above
typedef struct new_header_t {	// offset
	uint16_t id;		// 18
//	uint16_t offset;	// 20
//	uint8_t ttl;		// 22
} __attribute__((__packed__)) NewHeader;

int compress_l3_size(void) {
	return FULL_HEADER_LEN - sizeof(NewHeader);
}

// fill up a session structure; ptr is the start of eth packet
static void set_session(uint8_t *ptr, IpSession *s) {
	assert(s);
	memcpy(s->mac, ptr, 14);
	memcpy(&s->ver_ihl_tos, ptr + 14, 2);
	s->len = 0xc28a;
	memcpy(&s->offset, ptr + 20, 2);
	s->ttl = *(ptr + 22);
	s->protocol = *(ptr + 23);
	s->checksum = 0x55aa;
	memcpy(s->addr, ptr + 26, 8);
}

static void print_session(IpSession *s) {
	uint32_t ip1;
	uint32_t ip2;
	memcpy(&ip1, s->addr, 4);
	ip1 = ntohl(ip1);
	memcpy(&ip2, s->addr + 4, 4);
	ip2 = ntohl(ip2);
	printf("%d.%d.%d.%d -> %d.%d.%d.%d\n", PRINT_IP(ip1), PRINT_IP(ip2));
}

static void set_new_header(uint8_t *ptr, NewHeader *h) {
	assert(h);
	memcpy(&h->id, ptr + 18, 2);
//	memcpy(&h->offset, ptr + 20, 2);
//	h->ttl = *(ptr + 22);
}


//*******************************************************************
// An IP connection has a packet session associated, and counts the packets
// Tracking 256 IP connections in each directions
//*******************************************************************
typedef struct ip_connection_t {
	int active;	// TODO: get rid of active
	int cnt;	// packet counter for session s
	IpSession s;
} IpConnection;
static IpConnection connection_s2c[256];
static IpConnection connection_c2s[256];

void compress_l3_init(void) {
	memset(connection_s2c, 0, sizeof(connection_s2c));
	memset(connection_c2s, 0, sizeof(connection_c2s));
}

void print_compress_l3_table(int direction) {
	IpConnection *conn = (direction == S2C)? &connection_s2c[0]: &connection_c2s[0];
	printf("Compression L3 tun tx table:\n");
	printf("   cache collision %0.2f%%, total packets %u\n",
		collision_ratio(tunnel.stats.compress_hash_total_l3, tunnel.stats.compress_hash_collision_l3),
		tunnel.stats.compress_hash_total_l3);
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
void update_compress_l3_stats(void) {
	IpConnection *conn = (arg_server)? connection_s2c: connection_c2s;
	int cnt = 0;
	int i;
	for (i = 0; i < 256; i++, conn++)
		if (conn->active)
			cnt++;

	tunnel.stats.compress_hash_cnt_l3 = cnt;
}


// ptr points at the begining of Ethernet packet
// start a new session if this is a new packet (return 0)
// for an existing session:
//          send packet uncompressed from time to time (cnt 1, 2, 3, 8, 16 etc... - return 0)
//          else send packet compressed (return 1)
// store the hash in sid if sid not null
int classify_l3(uint8_t *pkt, uint8_t *sid, int direction) {
	int rv = 0;
	IpSession s;
	set_session(pkt, &s);

	uint8_t hash = 0;
	unsigned i;
	uint8_t *ptr = (uint8_t *) &s;
	for ( i = 0; i < sizeof(s); i++, ptr++)
		hash ^= *ptr;
	hash += s.addr[0] + s.addr[4];
	if (sid) {
		*sid = hash;
		tunnel.stats.compress_hash_total_l3++;
	}

	IpConnection *conn = (direction == S2C)? &connection_s2c[hash]: &connection_c2s[hash];
	if (conn->active) {
		if (memcmp(&s, &conn->s, sizeof(IpSession)) == 0) {
			conn->cnt++;
			rv = compress_shaper(conn->cnt);
		}
		else {
			dbg_printf("replace l3 hash %d\n", hash);
			tunnel.stats.compress_hash_collision_l3++;
			memcpy(&conn->s, &s, sizeof(IpSession));
			conn->cnt = 1;
		}
	}
	else {
		memcpy(&conn->s, &s, sizeof(IpSession));
		conn->cnt = 1;
		conn->active = 1;
	}

	return rv;
}

int compress_l3(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
//uint16_t len;
//memcpy(&len, pkt + 14 + 2, 2);
//len = ntohs(len);
//printf("len %u, nbytes %d\n", len, nbytes);
	(void) direction;
	(void) nbytes;
	(void) sid;
	tunnel.stats.udp_tx_compressed_pkt++;
	NewHeader h;
	set_new_header(pkt, &h);
	memcpy(pkt + FULL_HEADER_LEN - sizeof(h), &h, sizeof(h));

	return FULL_HEADER_LEN - sizeof(NewHeader);
}

int decompress_l3(uint8_t *pkt, int nbytes, uint8_t sid, int direction) {
	IpConnection *conn = (direction == S2C)? &connection_s2c[sid]: &connection_c2s[sid];
	IpSession *s = &conn->s;
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

	return FULL_HEADER_LEN - sizeof(NewHeader);
}
