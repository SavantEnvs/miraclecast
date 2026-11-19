/*
 * Streaming RTSP parser (src/shared/rtsp.c rtsp_parse_data and the
 * parser_feed_char_* state machine, '$' interleaved data frames, dispatch).
 * The fuzz input is the byte stream a remote WFD source sends on the RTSP
 * TCP connection; it is written into one end of a socketpair whose other end
 * is owned by an rtsp bus (as in test/test_rtsp.c start_test_client), and the
 * bus's sd-event loop is run until it has consumed everything.
 * A fresh sd_event + bus is created per input, so no state survives.
 */
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <systemd/sd-event.h>
#include "rtsp.h"
#include "rtsp_common.h"

static int on_message(struct rtsp *bus, struct rtsp_message *m, void *data)
{
	(void)bus;
	(void)data;
	if (m)
		fuzz_read_message(m);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sd_event *ev = NULL;
	struct rtsp *bus = NULL;
	int fds[2];
	size_t off = 0;
	int i;

	if (sd_event_new(&ev) < 0)
		return 0;
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) < 0) {
		sd_event_unref(ev);
		return 0;
	}
	if (rtsp_open(&bus, fds[0]) < 0) {
		close(fds[0]);
		close(fds[1]);
		sd_event_unref(ev);
		return 0;
	}
	fcntl(fds[1], F_SETFL, fcntl(fds[1], F_GETFL) | O_NONBLOCK);

	if (rtsp_attach_event(bus, ev, 0) < 0 ||
	    rtsp_add_match(bus, on_message, NULL) < 0)
		goto out;

	while (off < size && !rtsp_is_dead(bus)) {
		ssize_t n = write(fds[1], data + off, size - off);
		if (n > 0)
			off += (size_t)n;
		else if (n < 0 && errno != EAGAIN && errno != EINTR)
			break;
		sd_event_run(ev, 0);
	}
	shutdown(fds[1], SHUT_WR);

	/* drain: the bus reads until EOF, then marks itself dead */
	for (i = 0; i < 4096 && !rtsp_is_dead(bus); ++i)
		if (sd_event_run(ev, 0) <= 0)
			break;

out:
	close(fds[1]);
	rtsp_unref(bus);
	sd_event_unref(ev);
	return 0;
}
