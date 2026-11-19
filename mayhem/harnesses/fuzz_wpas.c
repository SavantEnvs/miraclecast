/*
 * wpa_supplicant control-socket protocol (src/shared/wpas.c): datagram
 * receive -> wpas__parse_message (IFNAME= prefix, <level> events, reply
 * split, shl_qstr_tokenize), match dispatch, then the reads miracle-wifid
 * does on events (wifid-supplicant.c: wpas_message_read "s", argv_read,
 * dict_read of p2p_dev_addr / device_name / wfd_subelems ...).
 *
 * Byte 0 bit 0 picks the side:
 *   0 = client (miracle-wifid's view): wpas_open() to a control socket the
 *       harness owns; the harness plays wpa_supplicant and sends the fuzz
 *       datagrams (events / replies) to the client's address.
 *   1 = server: wpas_create() and the harness sends requests to it.
 * Remaining bytes: records of 2-byte big-endian length + datagram payload.
 * Sockets are abstract-namespace (server) or the library's own /tmp client
 * socket, created and torn down per input with a fresh sd_event.
 */
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <systemd/sd-event.h>
#include "wpas.h"

static int on_message(struct wpas *w, struct wpas_message *m, void *data)
{
	const char *s = NULL;
	int32_t i32;
	uint32_t u32;
	unsigned int i;
	(void)w; (void)data;

	if (!m)
		return 0;
	(void)wpas_message_get_type(m);
	(void)wpas_message_get_level(m);
	(void)wpas_message_get_name(m);
	(void)wpas_message_get_raw(m);
	(void)wpas_message_get_ifname(m);
	(void)wpas_message_is_ok(m);
	(void)wpas_message_is_fail(m);
	(void)wpas_message_is_event(m, "P2P-DEVICE-FOUND");

	wpas_message_read(m, "s", &s);
	wpas_message_rewind(m);
	wpas_message_read(m, "ssu", &s, &s, &u32);
	wpas_message_rewind(m);
	wpas_message_read(m, "i", &i32);
	wpas_message_rewind(m);
	for (i = 0; i < 4; ++i)
		wpas_message_argv_read(m, i, 's', &s);
	wpas_message_argv_read(m, 1, 'i', &i32);
	wpas_message_argv_read(m, 1, 'u', &u32);
	wpas_message_dict_read(m, "p2p_dev_addr", 's', &s);
	wpas_message_dict_read(m, "device_name", 's', &s);
	wpas_message_dict_read(m, "name", 's', &s);
	wpas_message_dict_read(m, "wfd_subelems", 's', &s);
	wpas_message_dict_read(m, "wfd_dev_info", 's', &s);
	wpas_message_dict_read(m, "go_dev_addr", 's', &s);
	wpas_message_dict_read(m, "ssid", 's', &s);
	wpas_message_dict_read(m, "freq", 'i', &i32);
	wpas_message_dict_read(m, "dev_passwd_id", 'u', &u32);
	return 0;
}

static void pump(sd_event *ev)
{
	int i;
	for (i = 0; i < 256; ++i)
		if (sd_event_run(ev, 0) <= 0)
			break;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char ctrl[64], sname[64];
	struct sockaddr_un addr, peer;
	socklen_t plen = sizeof(peer);
	struct wpas *w = NULL;
	sd_event *ev = NULL;
	int fd = -1, server_mode;
	size_t off = 1;
	char buf[256];

	if (size < 1)
		return 0;
	server_mode = data[0] & 1;

	snprintf(sname, sizeof(sname), "miraclecast-fuzz-wpas-%d", (int)getpid());
	snprintf(ctrl, sizeof(ctrl), "@abstract:%s", sname);
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	memcpy(&addr.sun_path[1], sname, strlen(sname));

	if (sd_event_new(&ev) < 0)
		return 0;
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0)
		goto out;

	if (server_mode) {
		if (wpas_create(ctrl, &w) < 0)
			goto out;
	} else {
		struct wpas_message *req = NULL;
		/* harness = wpa_supplicant's control socket */
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
			goto out;
		if (wpas_open(ctrl, &w) < 0)
			goto out;
		if (wpas_attach_event(w, ev, 0) < 0)
			goto out;
		/* learn the client's address from a request it sends */
		if (wpas_message_new_request(w, "PING", &req) >= 0) {
			wpas_send(w, req, 0);
			wpas_message_unref(req);
		}
		pump(ev);
		if (recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&peer,
			     &plen) < 0)
			goto out;
	}
	if (server_mode && wpas_attach_event(w, ev, 0) < 0)
		goto out;
	if (wpas_add_match(w, on_message, NULL) < 0)
		goto out;

	while (off + 2 <= size && !wpas_is_dead(w)) {
		size_t len = ((size_t)data[off] << 8) | data[off + 1];
		off += 2;
		if (len > size - off)
			len = size - off;
		if (server_mode)
			sendto(fd, data + off, len, 0, (struct sockaddr *)&addr,
			       sizeof(addr));
		else
			sendto(fd, data + off, len, 0, (struct sockaddr *)&peer,
			       plen);
		off += len;
		pump(ev);
	}

out:
	if (fd >= 0)
		close(fd);
	if (w) {
		wpas_detach_event(w);
		wpas_unref(w);
	}
	sd_event_unref(ev);
	return 0;
}
