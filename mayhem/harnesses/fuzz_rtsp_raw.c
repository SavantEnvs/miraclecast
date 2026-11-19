/*
 * One-shot RTSP message parser: rtsp_message_new_from_raw (src/shared/rtsp.c)
 * — header line splitting, rtsp_message_from_head, header tokenizing, body
 * append, seal — then the sink's rtsp_message_read formats on the result.
 * The bus is only a message factory here (it is never attached to an event
 * loop or written to), so keeping it across inputs carries no input state.
 */
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include "rtsp.h"
#include "rtsp_common.h"

static struct rtsp *bus;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct rtsp_message *m = NULL;

	if (!bus) {
		int fds[2];
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) < 0)
			return 0;
		if (rtsp_open(&bus, fds[0]) < 0)
			return 0;
	}

	if (rtsp_message_new_from_raw(bus, &m, data, size) >= 0 && m) {
		fuzz_read_message(m);
		rtsp_message_unref(m);
	}
	return 0;
}
