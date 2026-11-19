/*
 * miracle-wifid's wpa_supplicant event handlers (src/wifi/wifid-supplicant.c):
 * supplicant_event() and the supplicant_event_p2p_* / ap_sta_* handlers,
 * supplicant_parse_peer() and the setup reply handlers (STATUS, P2P_PEER,
 * P2P_SET ...). They consume fields remote P2P devices control (device
 * names, WFD subelements, MACs, group/interface names) as relayed by
 * wpa_supplicant over its control socket.
 *
 * The harness plays wpa_supplicant: it binds an abstract-namespace datagram
 * socket, points the supplicant's global_ctrl at it, and calls
 * supplicant_open() (wifid's own connect path; the file is #included below
 * because that function is static). dev_ctrl points to a socket nobody
 * binds, so wifid falls back to the global interface for events, as it does
 * with real wpa_supplicant builds without a p2p-dev interface. Every fuzz
 * record is then sent as one datagram to wifid's client socket: replies
 * ("OK\n", STATUS dict, ...) answer wifid's pending requests in order, and
 * "<N>EVENT ..." / "IFNAME=x <N>EVENT ..." records are dispatched through
 * supplicant_dev_fn -> supplicant_event().
 *
 * Input: byte 0 bit 0 = link_use_dev() (also dispatch IFNAME= events from
 * the global interface); then records of 2-byte big-endian length + payload.
 * A record whose payload starts with 0x01 is instead written (minus that
 * byte) to the newest P2P group's dhcp-comm socket, as miracle-dhcp would
 * report addresses: supplicant_group_comm_fn() parses it.
 *
 * Environment mocks (libc/libsystemd only, no wifid code is replaced):
 *  - fork() returns a fake pid instead of spawning miracle-dhcp for a P2P
 *    group; kill() of that pid is a no-op and sd_event_add_child() accepts
 *    it, so groups live and P2P-GROUP-*, AP-STA-* handlers can bind peers.
 *  - socketpair(AF_UNIX, SOCK_SEQPACKET) (only the group dhcp-comm pair)
 *    keeps a dup of the child end, closed at teardown, so the comm socket
 *    does not HUP immediately.
 *  - the D-Bus hooks (link_dbus_*, peer_dbus_*; wifid-dbus.c needs a bus
 *    connection) are no-op stubs.
 * Everything (sd_event, manager, link, supplicant, sockets) is created and
 * torn down per input. Logging is set to fatal-only once, at init.
 */
#include "../../src/wifi/wifid-supplicant.c"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

#define FAKE_DHCP_PID ((pid_t)0x3ffffff0)

/* ---- cli globals normally defined in wifid.c ---- */
unsigned int wpa_loglevel = LOG_NOTICE;
bool wpa_syslog = false;

/* ---- D-Bus hooks (wifid-dbus.c) ---- */
void peer_dbus_properties_changed(struct peer *p, const char *prop, ...) { (void)p; (void)prop; }
void peer_dbus_provision_discovery(struct peer *p, const char *prov, const char *pin) { (void)p; (void)prov; (void)pin; }
void peer_dbus_go_neg_request(struct peer *p, const char *type, const char *pin) { (void)p; (void)type; (void)pin; }
void peer_dbus_formation_failure(struct peer *p, const char *reason) { (void)p; (void)reason; }
void peer_dbus_added(struct peer *p) { (void)p; }
void peer_dbus_removed(struct peer *p) { (void)p; }
void link_dbus_properties_changed(struct link *l, const char *prop, ...) { (void)l; (void)prop; }
void link_dbus_added(struct link *l) { (void)l; }
void link_dbus_removed(struct link *l) { (void)l; }

/* ---- process / fd environment mocks ---- */
static int kept_fds[64];
static unsigned int kept_cnt;

pid_t fork(void)
{
	return FAKE_DHCP_PID;
}

int kill(pid_t pid, int sig)
{
	if (pid == FAKE_DHCP_PID)
		return 0;
	return (int)syscall(SYS_kill, pid, sig);
}

int sd_event_add_child(sd_event *e, sd_event_source **s, pid_t pid,
		       int options, sd_event_child_handler_t callback,
		       void *userdata)
{
	(void)e; (void)options; (void)callback; (void)userdata;
	if (pid != FAKE_DHCP_PID)
		return -ENOSYS;
	if (s)
		*s = NULL;
	return 0;
}

int socketpair(int domain, int type, int protocol, int sv[2])
{
	int r = (int)syscall(SYS_socketpair, domain, type, protocol, sv);

	if (r == 0 && domain == AF_UNIX && type == SOCK_SEQPACKET &&
	    kept_cnt < sizeof(kept_fds) / sizeof(kept_fds[0])) {
		int d = fcntl(sv[1], F_DUPFD_CLOEXEC, 3);
		if (d >= 0)
			kept_fds[kept_cnt++] = d;
	}
	return r;
}

static void pump(sd_event *ev)
{
	int i;
	for (i = 0; i < 256; ++i)
		if (sd_event_run(ev, 0) <= 0)
			break;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	log_max_sev = LOG_FATAL;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char sname[64], gctrl[80], dctrl[96], buf[512];
	struct sockaddr_un addr, peer;
	socklen_t plen = sizeof(peer);
	struct manager m;
	struct link *l = NULL;
	struct supplicant *s;
	sd_event *ev = NULL;
	int fd = -1;
	size_t off = 1;
	unsigned int i;

	if (size < 1)
		return -1;

	snprintf(sname, sizeof(sname), "miraclecast-fuzz-wifid-%d", (int)getpid());
	snprintf(gctrl, sizeof(gctrl), "@abstract:%s", sname);
	snprintf(dctrl, sizeof(dctrl), "@abstract:%s-nodev", sname);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path[1], sname, strlen(sname));

	memset(&m, 0, sizeof(m));
	shl_htable_init_uint(&m.links);
	if (sd_event_new(&ev) < 0)
		return 0;
	m.event = ev;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		goto out;
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto out;

	if (link_new(&m, 1, "wlan0", &l) < 0)
		goto out;
	if (data[0] & 1)
		link_use_dev(l);
	s = l->s;
	s->global_ctrl = strdup(gctrl);
	s->dev_ctrl = strdup(dctrl);
	if (!s->global_ctrl || !s->dev_ctrl)
		goto out;
	/* supplicant_start() would spawn wpa_supplicant; mark it as managed
	 * by us and connect the way supplicant_timer_fn() does. */
	s->pid = 0;
	if (supplicant_open(s) < 0)
		goto out;

	/* learn wifid's client address from its ATTACH request */
	pump(ev);
	if (recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer,
		     &plen) < 0)
		goto out;

	while (off + 2 <= size && s->bus_global) {
		size_t len = ((size_t)data[off] << 8) | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;
		if (len > 0 && data[off] == 0x01) {
			/* miracle-dhcp's reply on the newest group's comm
			 * socket ("L:<ip>", "G:<ip>", "R:<mac> <ip>") */
			if (kept_cnt > 0)
				send(kept_fds[kept_cnt - 1], data + off + 1,
				     len - 1, MSG_DONTWAIT | MSG_NOSIGNAL);
		} else {
			sendto(fd, data + off, len, 0,
			       (struct sockaddr *)&peer, plen);
		}
		off += len;
		pump(ev);
		/* drain wifid's requests so the socket never fills */
		while (recv(fd, buf, sizeof(buf), MSG_DONTWAIT) > 0)
			;
	}

out:
	if (l)
		link_free(l);
	shl_htable_clear_uint(&m.links, NULL, NULL);
	if (fd >= 0)
		close(fd);
	for (i = 0; i < kept_cnt; ++i)
		close(kept_fds[i]);
	kept_cnt = 0;
	sd_event_unref(ev);
	return 0;
}
