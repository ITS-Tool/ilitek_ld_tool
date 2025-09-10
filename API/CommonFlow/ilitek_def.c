// SPDX-License-Identifier: GPL-2.0
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#include "ilitek_def.h"

int tp_log_level = log_level_msg;
bool tp_print_en = true;
FILE *tp_fp = NULL;

char g_str[4096];
msg_t g_msg = NULL;

int get_time_ms(uint32_t *t_ms)
{
	static uint32_t time_ms_init = 0;
	struct timeval t;
	uint32_t time_ms;

	gettimeofday(&t, NULL);
	time_ms = t.tv_sec * 1000 + t.tv_usec / 1000;
	time_ms_init = (!time_ms_init) ? time_ms : time_ms_init;

	*t_ms = time_ms - time_ms_init;

	return 0;
}

void tp_log_arr(char *id, int level, const char *header, const char *tag,
		int type, int len, void *buf)
{
	const int num = 64;
	int i, idx = 0;
	uint32_t time_ms;
	int error;

	if (level > tp_log_level || !buf)
		return;

	error = get_time_ms(&time_ms);

	do {
		_memset(g_str, 0, sizeof(g_str));

		if (!error)
			_sprintf(g_str, 0, "[%7u.%03u]",
				time_ms / 1000, time_ms % 1000);

		if (id)
			_sprintf(g_str, _strlen(g_str),
				 PFMT_C8 "[" PFMT_C8 "] " PFMT_C8 " ",
				 header, id, tag);
		else
			_sprintf(g_str, _strlen(g_str),
				 PFMT_C8 " " PFMT_C8 " ",
				 header, tag);

		for (i = 0; i < num && idx < len; i++, idx++) {
			switch (type) {
			default:
			case TYPE_U8:
				_sprintf(g_str, _strlen(g_str), "%02x-",
					((uint8_t *)buf)[idx]);
				break;
			case TYPE_INT:
				_sprintf(g_str, _strlen(g_str), "%d-",
					((int *)buf)[idx]);
				break;
			}
		}
		_sprintf(g_str, _strlen(g_str) - 1, ", len: [%d/%d]\n",
			idx, len);

		if (tp_print_en)
			TP_PRINTF(PFMT_C8, g_str);
		if (g_msg)
			g_msg(level, g_str);
		TP_LOG(tp_fp, g_str);
	} while (idx < len);
}

void set_print_en(bool enable)
{
	tp_print_en = enable;
}

void set_log_level(int level)
{
	tp_log_level = level;
}

int set_log_fopen(WCHAR *filename)
{
	int error;

	if (tp_fp)
		return -EINVAL;

	if ((error = WFOPEN(&tp_fp, filename, "w+")) < 0) {
		tp_fp = NULL;
		return error;
	}

	return 0;
}

void set_log_fclose(void)
{
	if (!tp_fp)
		return;

	_fclose(tp_fp);
	tp_fp = NULL;
}

void set_log_fwrite(char *str)
{
	TP_LOG(tp_fp, str);
}
