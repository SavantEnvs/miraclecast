/*
 * DHCP server packet handling (src/dhcp/server.c listener_event ->
 * dhcp_recv_l3_packet, check_packet_type, dhcp_get_option, lease table,
 * send_offer/ACK/NAK/inform option building in common.c) — the code
 * miracle-dhcp runs on DHCP packets from the P2P peer.
 *
 * Reached through the public API only: g_dhcp_server_new on "lo",
 * g_dhcp_server_start, then datagrams delivered to the listener socket and
 * the glib main loop iterated.  The environment is mocked at the libc socket
 * layer (not project code): the server's UDP listener socket (port 67,
 * SO_BINDTODEVICE, both need privileges) is replaced by one end of an
 * AF_UNIX datagram socketpair, and AF_PACKET sockets used to send replies
 * fail with EPERM, as they do for an unprivileged process.
 *
 * Input format: a sequence of records, each a 2-byte big-endian length
 * followed by that many bytes of DHCP (BOOTP) payload; a short final record
 * takes the rest.  Several records let one input drive DISCOVER -> REQUEST.
 * A new server (fresh lease table) is created and destroyed per input.
 */
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <glib.h>
#include "gdhcp.h"

static int mock_listener = -1;	/* server's end of the pair */
static int mock_peer = -1;	/* our end */
static int capture_next_udp;

int socket(int domain, int type, int protocol)
{
	if (domain == AF_PACKET) {
		errno = EPERM;
		return -1;
	}
	if (capture_next_udp && domain == AF_INET &&
	    (type & 0xf) == SOCK_DGRAM) {
		int sv[2];
		capture_next_udp = 0;
		if (syscall(SYS_socketpair, AF_UNIX,
			    SOCK_DGRAM | (type & SOCK_CLOEXEC), 0, sv) < 0)
			return -1;
		mock_listener = sv[0];
		mock_peer = sv[1];
		return sv[0];
	}
	return (int)syscall(SYS_socket, domain, type, protocol);
}

int setsockopt(int fd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	if (fd >= 0 && fd == mock_listener)
		return 0;
	return (int)syscall(SYS_setsockopt, fd, level, optname, optval, optlen);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fd >= 0 && fd == mock_listener)
		return 0;
	return (int)syscall(SYS_bind, fd, addr, len);
}

static void event_fn(const char *mac, const char *lease, void *data)
{
	(void)mac; (void)lease; (void)data;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int ifindex;
	GDHCPServerError err;
	GDHCPServer *srv;
	size_t off = 0;
	int i;

	if (!ifindex)
		ifindex = (int)if_nametoindex("lo");

	srv = g_dhcp_server_new(G_DHCP_IPV4, ifindex, &err, event_fn, NULL);
	if (!srv)
		return 0;
	g_dhcp_server_set_ip_range(srv, "127.0.0.10", "127.0.0.100");
	g_dhcp_server_set_option(srv, G_DHCP_SUBNET, "255.0.0.0");
	g_dhcp_server_set_option(srv, G_DHCP_ROUTER, "127.0.0.1");
	g_dhcp_server_set_option(srv, G_DHCP_DNS_SERVER, "127.0.0.1");
	g_dhcp_server_set_lease_time(srv, 3600);

	capture_next_udp = 1;
	if (g_dhcp_server_start(srv) < 0) {
		capture_next_udp = 0;
		g_dhcp_server_unref(srv);
		return 0;
	}
	capture_next_udp = 0;

	while (off < size) {
		size_t len;
		if (size - off < 2)
			break;
		len = ((size_t)data[off] << 8) | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;
		send(mock_peer, data + off, len, MSG_DONTWAIT);
		off += len;
		/* deliver this packet before the next one */
		for (i = 0; i < 64 && g_main_context_iteration(NULL, FALSE); ++i)
			;
	}

	g_dhcp_server_unref(srv);	/* closes the listener (close-on-unref) */
	for (i = 0; i < 64 && g_main_context_iteration(NULL, FALSE); ++i)
		;
	if (mock_peer >= 0)
		close(mock_peer);
	mock_peer = mock_listener = -1;
	return 0;
}
