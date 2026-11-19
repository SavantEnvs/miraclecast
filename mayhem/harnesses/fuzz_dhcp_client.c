/*
 * DHCPv4 client packet handling (src/dhcp/client.c listener_event ->
 * dhcp_recv_l2_packet sanity/checksum checks, check_package_owner,
 * dhcp_get_option, get_lease / get_request option parsing into lists,
 * malloc_option_value_string), as miracle-dhcp's client mode runs it on
 * OFFER/ACK/NAK packets from the P2P group owner (src/dhcp/dhcp.c).
 *
 * Public API only: g_dhcp_client_new(G_DHCP_IPV4, lo) configured like
 * dhcp.c (hostname, SUBNET/DNS/ROUTER requests, lease events), then
 * g_dhcp_client_start(), packets delivered, glib main loop iterated.
 * Environment mocked at the libc socket layer: the client's AF_PACKET
 * listener (needs CAP_NET_RAW) and, after an ACK, its UDP port-68 listener
 * are replaced by AF_UNIX datagram socketpairs; other AF_PACKET sockets
 * (raw sends) fail with EPERM as for an unprivileged process;
 * SO_BINDTODEVICE / filters on mocked sockets succeed.
 *
 * In L2 mode the harness plays the kernel's packet socket: it frames each
 * fuzz record (the DHCP/BOOTP message) in an IPv4+UDP header (valid IP
 * header checksum, UDP checksum 0 = none, dest port 68), as the wire would
 * deliver it; in L3 mode the record is the UDP payload.  The client's xid
 * comes from rand(); srand(1) per input makes it a constant the seeds carry.
 *
 * Input: records of 2-byte big-endian length + DHCP message.  A new client
 * is created and destroyed per input.
 */
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <glib.h>
#include "gdhcp.h"
#include "common.h"

static int armed;		/* inside one input */
static int l2_taken;		/* the per-input AF_PACKET listener was handed out */
static int mock_fd = -1;	/* library's end of the current listener */
static int mock_peer = -1;	/* our end */
static int mock_is_l2;
static int pending_udp = -1;	/* UDP socket that may become the L3 listener */

static int new_pair(int cloexec)
{
	int sv[2];
	if (syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM | cloexec, 0, sv) < 0)
		return -1;
	if (mock_peer >= 0)
		close(mock_peer);
	mock_peer = sv[1];
	mock_fd = sv[0];
	return sv[0];
}

int socket(int domain, int type, int protocol)
{
	if (domain == AF_PACKET) {
		if (armed && !l2_taken) {
			l2_taken = 1;
			mock_is_l2 = 1;
			return new_pair(type & SOCK_CLOEXEC);
		}
		errno = EPERM;
		return -1;
	}
	int fd = (int)syscall(SYS_socket, domain, type, protocol);
	if (armed && domain == AF_INET && (type & 0xf) == SOCK_DGRAM)
		pending_udp = fd;
	return fd;
}

int setsockopt(int fd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	if (fd >= 0 && (fd == mock_fd ||
			(fd == pending_udp && optname == SO_BINDTODEVICE)))
		return 0;
	return (int)syscall(SYS_setsockopt, fd, level, optname, optval, optlen);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fd >= 0 && fd == mock_fd)
		return 0;
	if (fd >= 0 && fd == pending_udp && addr->sa_family == AF_INET &&
	    ((const struct sockaddr_in *)addr)->sin_port == htons(CLIENT_PORT)) {
		/* the client's L3 listener: swap in a socketpair end */
		int s = new_pair(SOCK_CLOEXEC);
		pending_udp = -1;
		if (s < 0)
			return -1;
		dup2(s, fd);
		close(s);
		mock_fd = fd;
		mock_is_l2 = 0;
		return 0;
	}
	return (int)syscall(SYS_bind, fd, addr, len);
}

static void on_lease(GDHCPClient *c, gpointer data)
{
	GList *l;
	char *a = g_dhcp_client_get_address(c);
	(void)data;
	g_free(a);
	for (l = g_dhcp_client_get_option(c, G_DHCP_SUBNET); l; l = l->next)
		(void)strlen(l->data);
	for (l = g_dhcp_client_get_option(c, G_DHCP_DNS_SERVER); l; l = l->next)
		(void)strlen(l->data);
	for (l = g_dhcp_client_get_option(c, G_DHCP_ROUTER); l; l = l->next)
		(void)strlen(l->data);
}

static void on_no_lease(GDHCPClient *c, gpointer data)
{
	(void)c; (void)data;
}

static void deliver(const uint8_t *p, size_t len)
{
	if (mock_peer < 0)
		return;
	if (!mock_is_l2) {
		send(mock_peer, p, len, MSG_DONTWAIT);
		return;
	}
	struct ip_udp_dhcp_packet pkt;
	size_t hdr = sizeof(pkt.ip) + sizeof(pkt.udp);
	if (len > sizeof(pkt.data))
		len = sizeof(pkt.data);	/* one frame */
	memset(&pkt, 0, sizeof(pkt));
	memcpy(&pkt.data, p, len);
	pkt.ip.version = IPVERSION;
	pkt.ip.ihl = sizeof(pkt.ip) >> 2;
	pkt.ip.ttl = 64;
	pkt.ip.protocol = IPPROTO_UDP;
	pkt.ip.saddr = htonl(INADDR_LOOPBACK);
	pkt.ip.daddr = htonl(INADDR_BROADCAST);
	pkt.ip.tot_len = htons((uint16_t)(hdr + len));
	pkt.ip.check = dhcp_checksum(&pkt.ip, sizeof(pkt.ip));
	pkt.udp.source = htons(SERVER_PORT);
	pkt.udp.dest = htons(CLIENT_PORT);
	pkt.udp.len = htons((uint16_t)(sizeof(pkt.udp) + len));
	pkt.udp.check = 0;
	send(mock_peer, &pkt, hdr + len, MSG_DONTWAIT);
}

static void pump(void)
{
	int i;
	for (i = 0; i < 64 && g_main_context_iteration(NULL, FALSE); ++i)
		;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int ifindex;
	GDHCPClientError err;
	GDHCPClient *c;
	size_t off = 0;

	if (!ifindex)
		ifindex = (int)if_nametoindex("lo");

	c = g_dhcp_client_new(G_DHCP_IPV4, ifindex, &err);
	if (!c)
		return 0;
	g_dhcp_client_set_send(c, G_DHCP_HOST_NAME, "<hostname>");
	g_dhcp_client_set_request(c, G_DHCP_SUBNET);
	g_dhcp_client_set_request(c, G_DHCP_DNS_SERVER);
	g_dhcp_client_set_request(c, G_DHCP_ROUTER);
	g_dhcp_client_register_event(c, G_DHCP_CLIENT_EVENT_LEASE_AVAILABLE,
				     on_lease, NULL);
	g_dhcp_client_register_event(c, G_DHCP_CLIENT_EVENT_NO_LEASE,
				     on_no_lease, NULL);

	armed = 1;
	l2_taken = 0;
	srand(1);
	if (g_dhcp_client_start(c, NULL) < 0)
		goto out;

	while (off + 2 <= size) {
		size_t len = ((size_t)data[off] << 8) | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;
		deliver(data + off, len);
		off += len;
		pump();
	}

out:
	g_dhcp_client_stop(c);
	g_dhcp_client_unref(c);
	pump();
	armed = 0;
	pending_udp = -1;
	if (mock_peer >= 0)
		close(mock_peer);
	mock_peer = mock_fd = -1;
	return 0;
}
