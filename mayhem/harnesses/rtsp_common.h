/* Shared helper: read a parsed RTSP message the way the WFD sink does
 * (src/ctl/ctl-sink.c sink_handle_*), so the tokenizer/reader paths run. */
#ifndef FUZZ_RTSP_COMMON_H
#define FUZZ_RTSP_COMMON_H
#include <stdint.h>
#include "rtsp.h"

static void fuzz_read_message(struct rtsp_message *m)
{
	const char *s = NULL;
	unsigned int cea = 0, vesa = 0, hh = 0;
	int32_t i32;
	uint32_t u32;

	(void)rtsp_message_get_type(m);
	(void)rtsp_message_get_method(m);
	(void)rtsp_message_get_uri(m);
	(void)rtsp_message_get_code(m);
	(void)rtsp_message_get_phrase(m);
	(void)rtsp_message_get_channel(m);
	(void)rtsp_message_get_payload(m);
	(void)rtsp_message_get_payload_size(m);
	(void)rtsp_message_is_request(m, NULL, NULL);
	(void)rtsp_message_is_reply(m, RTSP_ANY_CODE, NULL);

	rtsp_message_read(m, "<s>", "Session", &s);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "<u>", "CSeq", &u32);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "<&>", "Public", &s);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<>}", "wfd_video_formats");
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<s>}", "wfd_presentation_URL", &s);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<&>}", "wfd_uibc_capability", &s);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<****hhh>}", "wfd_video_formats", &cea, &vesa, &hh);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<i>}", "wfd_client_rtp_ports", &i32);
	rtsp_message_rewind(m, true);
	rtsp_message_read(m, "{<s>}", "wfd_trigger_method", &s);
	rtsp_message_rewind(m, true);
	rtsp_message_skip(m, "{<*>}");
	rtsp_message_rewind(m, true);
}
#endif
