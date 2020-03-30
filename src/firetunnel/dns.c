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

// set dns server for the tunnel
void dns_set_tunnel(const char *dns_ip) {
	if (!arg_server)
		return;

	if (tunnel.overlay.dns1 == 0) {
		if (atoip(dns_ip, &tunnel.overlay.dns1)) {
			fprintf(stderr, "Error: invalid DNS IP address %s\n", dns_ip);
			exit(1);
		}
		logmsg("Tunnel DNS %d.%d.%d.%d\n", PRINT_IP(tunnel.overlay.dns1));
		return;
	}

	if (tunnel.overlay.dns2 == 0) {
		if (atoip(dns_ip, &tunnel.overlay.dns2)) {
			fprintf(stderr, "Error: invalid DNS IP address %s\n", dns_ip);
			exit(1);
		}
		logmsg("Tunnel DNS %d.%d.%d.%d\n", PRINT_IP(tunnel.overlay.dns2));
		return;
	}

	if (tunnel.overlay.dns3 == 0) {
		if (atoip(dns_ip, &tunnel.overlay.dns3)) {
			fprintf(stderr, "Error: invalid DNS IP address %s\n", dns_ip);
			exit(1);
		}
		logmsg("Tunnel DNS %d.%d.%d.%d\n", PRINT_IP(tunnel.overlay.dns3));
		return;
	}

	fprintf(stderr, "Warning: disregarding DNS IP %s, not more than three DNS servers are allowed\n", dns_ip);
}
