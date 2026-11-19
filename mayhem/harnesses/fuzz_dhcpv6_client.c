/*
 * DHCPv6 client packet handling (src/dhcp/client.c listener_event IPv6 path:
 * dhcpv6_recv_l3_packet, check_package_owner, dhcpv6_get_option for
 * CLIENTID/SERVERID/STATUS_CODE/RAPID_COMMIT, get_dhcpv6_request ->
 * get_dhcpv6_option_value_list -> get_addresses (IA_NA/IA_TA/IA_PD with
 * IAADDR/IA_PREFIX/STATUS_CODE sub-options via dhcpv6_get_sub_option),
 * get_domains, DNS/SNTP address lists).
 *
 * Public API only: g_dhcp_client_new(G_DHCP_IPV6, lo) with a fixed DUID,
 * an IA (NA or TA), an ORO and the event callbacks registered, then
 * g_dhcp_client_start() and the server's replies delivered on the client's
 * UDP port-546 listener, glib main loop iterated.
 *
 * Environment mocked at the libc socket layer: the AF_INET6 UDP socket the
 * client binds to port 546 is replaced by an AF_UNIX datagram socketpair;
 * the client's outgoing sendmsg() on other AF_INET6 sockets is swallowed
 * (reported as sent), and the transaction id it carried is recorded.
 *
 * Input: byte 0 selects the exchange the client starts (SOLICIT,
 * INFORMATION-REQUEST or REQUEST) and the IA type; then records of 2-byte
 * big-endian length + DHCPv6 message.  The harness writes the client's
 * current transaction id into bytes 1..3 of each record (a server echoes
 * it), everything else is fuzz data.  A new client per input.
 */
#include <errno.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>
#include <glib.h>
#include "gdhcp.h"
#include "common.h"

#define MAXFD 4096

static int armed;
static unsigned char v6fd[MAXFD];	/* AF_INET6 dgram sockets made while armed */
static int mock_fd = -1;		/* library's end of the listener */
static int mock_peer = -1;		/* our end */
static uint8_t last_xid[3];

int socket(int domain, int type, int protocol)
{
	int fd = (int)syscall(SYS_socket, domain, type, protocol);
	if (fd >= 0 && fd < MAXFD)
		v6fd[fd] = armed && domain == AF_INET6 &&
			   (type & 0xf) == SOCK_DGRAM;
	return fd;
}

/* a closed descriptor is no longer a mocked socket, whatever reuses it */
int close(int fd)
{
	if (fd >= 0 && fd < MAXFD)
		v6fd[fd] = 0;
	return (int)syscall(SYS_close, fd);
}

int setsockopt(int fd, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	if (fd >= 0 && fd < MAXFD && v6fd[fd])
		return 0;	/* SO_BINDTODEVICE etc. on mocked sockets */
	return (int)syscall(SYS_setsockopt, fd, level, optname, optval, optlen);
}

int bind(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fd >= 0 && fd < MAXFD && v6fd[fd] && addr->sa_family == AF_INET6 &&
	    ((const struct sockaddr_in6 *)addr)->sin6_port ==
		    htons(DHCPV6_CLIENT_PORT)) {
		int sv[2];
		if (syscall(SYS_socketpair, AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
			    0, sv) < 0)
			return -1;
		dup2(sv[0], fd);
		close(sv[0]);
		if (mock_peer >= 0)
			close(mock_peer);
		mock_peer = sv[1];
		mock_fd = fd;
		v6fd[fd] = 0;
		return 0;
	}
	return (int)syscall(SYS_bind, fd, addr, len);
}

ssize_t sendmsg(int fd, const struct msghdr *m, int flags)
{
	if (fd >= 0 && fd < MAXFD && v6fd[fd]) {
		size_t i, n = 0;
		for (i = 0; i < m->msg_iovlen; ++i)
			n += m->msg_iov[i].iov_len;
		if (m->msg_iovlen > 0 && m->msg_iov[0].iov_len >= 4)
			memcpy(last_xid, (uint8_t *)m->msg_iov[0].iov_base + 1, 3);
		return (ssize_t)n;
	}
	return (ssize_t)syscall(SYS_sendmsg, fd, m, flags);
}

static void walk(GDHCPClient *c, unsigned char code)
{
	GList *l;
	for (l = g_dhcp_client_get_option(c, code); l; l = l->next)
		if (code != G_DHCPV6_IA_PD)
			(void)strlen(l->data);
}

static void on_event(GDHCPClient *c, gpointer data)
{
	uint32_t t1, t2;
	time_t st, ex;
	char *a;
	(void)data;
	walk(c, G_DHCPV6_DNS_SERVERS);
	walk(c, G_DHCPV6_SNTP_SERVERS);
	walk(c, G_DHCPV6_DOMAIN_LIST);
	walk(c, G_DHCPV6_IA_PD);
	a = g_dhcp_client_get_address(c);
	g_free(a);
	g_dhcpv6_client_get_timeouts(c, &t1, &t2, &st, &ex);
	(void)g_dhcpv6_client_get_status(c);
}

static void pump(void)
{
	int i;
	for (i = 0; i < 64 && g_main_context_iteration(NULL, FALSE); ++i)
		;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static const uint8_t duid[] = { 0x00, 0x03, 0x00, 0x01,
					0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
	static int ifindex;
	uint8_t rec[MAX_DHCPV6_PKT_SIZE];
	GDHCPClientError err;
	GDHCPClient *c;
	uint32_t T1 = 0, T2 = 0;
	size_t off = 1;
	unsigned mode;

	if (size < 1)
		return 0;
	if (!ifindex)
		ifindex = (int)if_nametoindex("lo");
	mode = data[0];

	c = g_dhcp_client_new(G_DHCP_IPV6, ifindex, &err);
	if (!c)
		return 0;
	g_dhcpv6_client_set_duid(c, g_memdup2(duid, sizeof(duid)), sizeof(duid));
	g_dhcpv6_client_set_iaid(c, 1);
	g_dhcp_client_set_request(c, G_DHCPV6_CLIENTID);
	g_dhcp_client_set_request(c, G_DHCPV6_DNS_SERVERS);
	g_dhcp_client_set_request(c, G_DHCPV6_DOMAIN_LIST);
	g_dhcp_client_set_request(c, G_DHCPV6_SNTP_SERVERS);
	g_dhcpv6_client_set_oro(c, 3, G_DHCPV6_DNS_SERVERS,
				G_DHCPV6_DOMAIN_LIST, G_DHCPV6_SNTP_SERVERS);

	switch (mode % 3) {
	case 0:
		g_dhcp_client_set_request(c, G_DHCPV6_RAPID_COMMIT);
		g_dhcpv6_client_set_ia(c, ifindex,
				       (mode & 4) ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
				       &T1, &T2, false, NULL);
		g_dhcp_client_register_event(c, G_DHCP_CLIENT_EVENT_SOLICITATION,
					     on_event, NULL);
		g_dhcp_client_register_event(c, G_DHCP_CLIENT_EVENT_ADVERTISE,
					     on_event, NULL);
		break;
	case 1:
		g_dhcp_client_register_event(c,
					     G_DHCP_CLIENT_EVENT_INFORMATION_REQ,
					     on_event, NULL);
		break;
	default:
		g_dhcp_client_set_request(c, G_DHCPV6_SERVERID);
		g_dhcpv6_client_set_ia(c, ifindex,
				       (mode & 4) ? G_DHCPV6_IA_TA : G_DHCPV6_IA_NA,
				       &T1, &T2, true, "2001:db8::10");
		g_dhcp_client_register_event(c, G_DHCP_CLIENT_EVENT_REQUEST,
					     on_event, NULL);
		break;
	}

	armed = 1;
	memset(last_xid, 0, sizeof(last_xid));
	srandom(1);
	if (g_dhcp_client_start(c, NULL) < 0)
		goto out;

	while (off + 2 <= size) {
		size_t len = ((size_t)data[off] << 8) | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;
		if (len > sizeof(rec))
			len = sizeof(rec);
		memcpy(rec, data + off, len);
		off += len;
		if (len >= 4)
			memcpy(rec + 1, last_xid, 3);
		if (mock_peer >= 0)
			send(mock_peer, rec, len, MSG_DONTWAIT);
		pump();
	}

out:
	g_dhcp_client_stop(c);
	g_dhcp_client_unref(c);
	pump();
	armed = 0;
	if (mock_peer >= 0)
		close(mock_peer);
	mock_peer = mock_fd = -1;
	memset(v6fd, 0, sizeof(v6fd));
	return 0;
}
