/*
 * WFD sink session logic (src/ctl/ctl-sink.c): sink_rtsp_fn and the
 * sink_handle_* handlers for OPTIONS / GET_PARAMETER / SET_PARAMETER
 * (wfd_presentation_URL, wfd_uibc_capability strtok/sscanf,
 * wfd_video_formats -> wfd.c resolution tables, wfd_trigger_method
 * SETUP/PLAY/TEARDOWN) and the replies it builds — what miracle-sinkctl does
 * with the RTSP stream a remote Miracast source sends.
 *
 * Public API: ctl_sink_new + ctl_sink_connect("127.0.0.1"); the harness is the
 * source.  The TCP connect to port 7236 is mocked at the libc layer: the
 * sink's AF_INET stream socket is an AF_UNIX stream socketpair end and its
 * connect() succeeds at once.  The fuzz input is the byte stream from the
 * source; the sink's replies are drained and discarded.  The globals and
 * ctl_fn_sink_* callbacks miracle-sinkctl (sinkctl.c) provides are defined
 * here with sinkctl's defaults, and reset per input; a fresh sd_event and
 * sink are used per input.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <systemd/sd-event.h>
#include "ctl.h"
#include "ctl-sink.h"

/* what sinkctl.c / ctl-cli.c define */
unsigned int cli_max_sev = 0;	/* quiet */
int rstp_port;
bool uibc_option;
bool uibc_enabled;
int uibc_port;
unsigned int wfd_supported_res_cea  = 0x0001ffff;
unsigned int wfd_supported_res_vesa = 0x1fffffff;
unsigned int wfd_supported_res_hh   = 0x00001fff;

void cli_printv(const char *fmt, bool prefix_time, va_list args)
{
	char buf[1024];
	(void)prefix_time;
	vsnprintf(buf, sizeof(buf), fmt, args);
}
void cli_printf_time_prefix(void) {}
void cli_printf(const char *fmt, ...)
{
	va_list a;
	va_start(a, fmt);
	cli_printv(fmt, false, a);
	va_end(a);
}
void cli_command_printf(const char *fmt, ...)
{
	va_list a;
	va_start(a, fmt);
	cli_printv(fmt, false, a);
	va_end(a);
}
void ctl_fn_sink_connected(struct ctl_sink *s) { (void)s; }
void ctl_fn_sink_disconnected(struct ctl_sink *s) { (void)s; }
void ctl_fn_sink_resolution_set(struct ctl_sink *s) { (void)s; }

static int armed, mock_fd = -1, mock_peer = -1;

int socket(int domain, int type, int protocol)
{
	if (armed && domain == AF_INET && (type & 0xf) == SOCK_STREAM) {
		int sv[2];
		armed = 0;
		if (syscall(SYS_socketpair, AF_UNIX, type, 0, sv) < 0)
			return -1;
		mock_fd = sv[0];
		mock_peer = sv[1];
		return sv[0];
	}
	return (int)syscall(SYS_socket, domain, type, protocol);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	if (fd >= 0 && fd == mock_fd)
		return 0;
	return (int)syscall(SYS_connect, fd, addr, len);
}

static void drain(void)
{
	char buf[4096];
	while (read(mock_peer, buf, sizeof(buf)) > 0)
		;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	sd_event *ev = NULL;
	struct ctl_sink *s = NULL;
	size_t off = 0;
	int i;

	rstp_port = 1991;
	uibc_option = false;
	uibc_enabled = false;
	uibc_port = 0;

	if (sd_event_new(&ev) < 0)
		return 0;
	if (ctl_sink_new(&s, ev) < 0)
		goto out;
	armed = 1;
	if (ctl_sink_connect(s, "127.0.0.1") < 0 || mock_peer < 0)
		goto out;
	armed = 0;
	fcntl(mock_peer, F_SETFL, fcntl(mock_peer, F_GETFL) | O_NONBLOCK);

	for (i = 0; i < 16 && !ctl_sink_is_connected(s); ++i)
		if (sd_event_run(ev, 0) <= 0)
			break;

	while (off < size && !ctl_sink_is_closed(s)) {
		ssize_t n = write(mock_peer, data + off, size - off);
		if (n > 0)
			off += (size_t)n;
		else if (n < 0 && errno != EAGAIN && errno != EINTR)
			break;
		sd_event_run(ev, 0);
		drain();
	}
	shutdown(mock_peer, SHUT_WR);
	for (i = 0; i < 4096 && !ctl_sink_is_closed(s); ++i) {
		int r = sd_event_run(ev, 0);
		drain();
		if (r <= 0)
			break;
	}

out:
	armed = 0;
	ctl_sink_free(s);
	sd_event_unref(ev);
	if (mock_peer >= 0)
		close(mock_peer);
	mock_peer = mock_fd = -1;
	return 0;
}
