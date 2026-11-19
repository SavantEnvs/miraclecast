/*
 * miracle-uibcctl input parser (src/uibc/miracle-uibcctl.c): the program reads
 * UIBC event descriptions "<type>,<count>,<id>,<x>,<y>,..." line by line from
 * stdin, dispatches on the first character exactly like main(), builds the
 * UIBC packet (buildUibcMessage -> str_split + getUIBCGeneric*Packet) and sends
 * it. The fuzz input is the stdin stream; it is consumed in fgets-sized
 * chunks (at most 254 bytes, NUL-terminated, as main() does). Packets are
 * written to /dev/null instead of the TCP socket to the source.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "miracle-uibcctl.h"

static int devnull = -1;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char buffer[256];
	size_t off = 0;

	if (devnull < 0)
		devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);

	while (off < size) {
		/* fgets(buffer, 255, stdin): up to 254 chars, stopping after '\n' */
		size_t n = 0;
		memset(buffer, 0, sizeof(buffer));
		while (off < size && n < 254) {
			char c = (char)data[off++];
			buffer[n++] = c;
			if (c == '\n')
				break;
		}
		if (strlen(buffer) == 0)
			break;

		char type = buffer[0];
		UibcMessage msg;
		if (type == '0' || type == '1')
			msg = buildUibcMessage(GENERIC_TOUCH_DOWN, buffer, 1, 1);
		else if (type == '3' || type == '4')
			msg = buildUibcMessage(GENERIC_KEY_DOWN, buffer, 1, 1);
		else
			continue;

		sendUibcMessage(&msg, devnull);
		free(msg.m_PacketData);
	}
	return 0;
}
