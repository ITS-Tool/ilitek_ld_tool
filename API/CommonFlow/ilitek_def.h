/* SPDX-License-Identifier: GPL-2.0 */
/*
* This file is part of ILITEK CommonFlow
*
* Copyright (c) 2022 ILI Technology Corp.
* Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
* Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
*/

#ifndef __ILITEK_DEF_H__
#define __ILITEK_DEF_H__

#define COMMONFLOW_CODE_VERSION		0x00000303


#define __MAYBE_UNUSED	__attribute__((unused))
#define __DLL
#define __PACKED__	__attribute__((__packed__))
#define _sprintf(buf, idx, fmt, ...)	sprintf((buf) + (idx), (fmt), ##__VA_ARGS__)
#define _strncpy(dst, src, n, dst_size) strncpy((dst), (src), (n))
#define _strcasecmp(l, r)		strcasecmp((l), (r))
#define _strcat(dst, src, dst_size)	strcat((dst), (src))
#define _sscanf(str, fmt, ...)		sscanf(str, fmt, ##__VA_ARGS__)
#define _strlen(str)			strlen((str))
#define _strcpy(dst, src, dst_size)	strcpy((dst), (src))

#define _memset(ptr, ch, size)		memset((ptr), (ch), (size))
#define _memcpy(dst, src, size)		memcpy((dst), (src), (size))

#define WTEXT(str)			str
#define WCHAR				char
#define WSTRING				string
#define WCSCPY(dst, src, dst_size)	_strcpy((dst), (src), (dst_size))
#define WCSCASECMP(str, tag)		_strcasecmp((str), (tag))
#define WCSRCHR(str, ch)		strrchr((str), (ch))
#define SWPRINTF(buf, size, fmt, ...)	\
	sprintf((buf), (fmt), ##__VA_ARGS__)
#define WFOPEN(pfp, filename, mode)	_fopen(pfp, filename, mode)
#define WACCESS(filename, mode)		_access((filename), (mode))
#define WFPRINTF(fp, fmt, ...)		fprintf((fp), (fmt), ##__VA_ARGS__)
#define TO_WCHAR(x)			(x)

#define PFMT_C16			"%s"
#define PFMT_C8				"%s"

#define _localtime(ptm, ptime)						\
		do {							\
			struct tm *__tm__;				\
									\
			__tm__ = localtime((ptime));			\
			_memcpy((ptm), __tm__, sizeof(struct tm));	\
		} while (false)

#include <sys/time.h>
#include <unistd.h>

#define _fopen(pfp, filename, mode)	\
	((!((*(pfp)) = fopen((filename), (mode)))) ? -EFAULT : 0)
#define _fclose(pfp)			fclose((pfp))
#define _access(filename, mode)		access((filename), (mode))

#define _strtok(str, del, next_token)	strtok((str), (del))

#include <pthread.h>
#define MUTEX_T				pthread_mutex_t
#define MUTEX_INIT(x)			(pthread_mutex_init(&(x), NULL))
#define MUTEX_LOCK(x)			(pthread_mutex_lock(&(x)))
#define MUTEX_UNLOCK(x)			(pthread_mutex_unlock(&(x)))
#define MUTEX_EXIT(x)			(pthread_mutex_destroy(&(x)))

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define MALLOC(size)		malloc(size)
#define CALLOC(num, size)	calloc(num, size)
#define FREE(ptr)		\
	do {			\
		free((ptr));	\
		(ptr) = NULL;	\
	} while (0)
#define CFREE(ptr)		FREE(ptr)


#define U82U64(byte, order)	\
	((uint64_t)((uint64_t)(byte) << ((order) * 8)))

#ifndef PFMT_C16
#define PFMT_C16			"%ls"
#endif
#ifndef PFMT_C8
#define PFMT_C8				"%hs"
#endif
#ifndef PFMT_U8
#define PFMT_U8				"%hhu"
#endif
#ifndef PFMT_U16
#define PFMT_U16			"%hu"
#endif
#ifndef PFMT_X8
#define PFMT_X8				"%hhx"
#endif
#ifndef PFMT_X16
#define PFMT_X16			"%hx"
#endif

#ifndef PFMT_X64
#define PFMT_X64			"%llx"
#endif


#ifndef TP_PRINTF
#define TP_PRINTF(fmt, ...)				\
	do {						\
		printf(fmt, ##__VA_ARGS__);		\
		fflush(stdout);				\
	} while (0)
#endif

#ifndef TP_LOG
#define TP_LOG(fp, str)				\
	do {					\
		if (!fp)			\
			break;			\
		fprintf((fp), PFMT_C8, (str));	\
		fflush((fp));			\
	} while (0)
#endif

#ifndef TP_PRINT
#define TP_PRINT(_id, level, need_tag, tag, fmt, ...)			\
	do {								\
		char *__id__ = (_id);					\
		uint32_t __time_ms__;					\
									\
		if (level > tp_log_level)				\
			break;						\
									\
		g_str[0] = '\0';					\
									\
		if (need_tag) {						\
			if (!get_time_ms(&__time_ms__))			\
				_sprintf(g_str, _strlen(g_str),		\
					"[%7u.%03u]",			\
					__time_ms__ / 1000,		\
					__time_ms__ % 1000);		\
			_sprintf(g_str, _strlen(g_str), PFMT_C8, tag);	\
		}							\
									\
		if (__id__) {						\
			_sprintf(g_str, _strlen(g_str),			\
				 "[" PFMT_C8 "] " fmt,			\
				 __id__, ##__VA_ARGS__);		\
		} else {						\
			_sprintf(g_str, _strlen(g_str), " " fmt, 	\
		 		 ##__VA_ARGS__);			\
		}							\
									\
		if (tp_print_en)					\
			TP_PRINTF(PFMT_C8, g_str);			\
		if (g_msg)						\
			g_msg(level, g_str);				\
		TP_LOG(tp_fp, g_str);					\
	} while (0)
#endif

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#endif

#ifndef UNUSED
#define UNUSED(x)		(void)(x)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)		((sizeof(a) / sizeof(*(a))))
#endif

#ifndef MIN
#define MIN(l, r)		(((l) > (r)) ? (r) : (l))
#endif

#ifndef MAX
#define MAX(l, r)		(((l) > (r)) ? (l) : (r))
#endif

#define EILICOMM		200
#define EILIBUSY		201
#define EILITIME		202
#define EILIPROTO		203

enum ilitek_log_level {
	log_level_none = -1,	/* no log displayed */
	log_level_err = 0,	/* critical errors */
	log_level_warn,		/* warnings */
	log_level_tag,		/* special-required tags */
	log_level_info,		/* important/UI messages */
	log_level_msg,		/* non-important messages */
	log_level_dbg,		/* debugging messages */
	log_level_pkt,		/* tx/rx packets */

	log_level_max,		/* sentinel */
};

#define _TP_ERR(fmt, ...)	\
	TP_PRINT(NULL, log_level_err, false, "", fmt, ##__VA_ARGS__)
#define _TP_WARN(fmt, ...)	\
	TP_PRINT(NULL, log_level_warn, false, "", fmt, ##__VA_ARGS__)
#define _TP_TAG(fmt, ...)	\
	TP_PRINT(NULL, log_level_tag, false, "", fmt, ##__VA_ARGS__)
#define _TP_INFO(fmt, ...)	\
	TP_PRINT(NULL, log_level_info, false, "", fmt, ##__VA_ARGS__)
#define _TP_MSG(fmt, ...)	\
	TP_PRINT(NULL, log_level_msg, false, "", fmt, ##__VA_ARGS__)
#define _TP_DBG(fmt, ...)	\
	TP_PRINT(NULL, log_level_dbg, false, "", fmt, ##__VA_ARGS__)
#define _TP_PKT(fmt, ...)	\
	TP_PRINT(NULL, log_level_pkt, false, "", fmt, ##__VA_ARGS__)


#define TP_ERR(id, fmt, ...)	\
	TP_PRINT(id, log_level_err, true, "[ILITEK][ERR]", fmt, ##__VA_ARGS__)
#define TP_WARN(id, fmt, ...)	\
	TP_PRINT(id, log_level_warn, true, "[ILITEK][WARN]", fmt, ##__VA_ARGS__)
#define TP_TAG(id, fmt, ...)	\
	TP_PRINT(id, log_level_tag, true, "[ILITEK][TAG]", fmt, ##__VA_ARGS__)
#define TP_INFO(id, fmt, ...)	\
	TP_PRINT(id, log_level_info, true, "[ILITEK][INFO]", fmt, ##__VA_ARGS__)
#define TP_MSG(id, fmt, ...)	\
	TP_PRINT(id, log_level_msg, true, "[ILITEK][MSG]", fmt, ##__VA_ARGS__)
#define TP_DBG(id, fmt, ...)	\
	TP_PRINT(id, log_level_dbg, true, "[ILITEK][DBG]", fmt, ##__VA_ARGS__)
#define TP_PKT(id, fmt, ...)	\
	TP_PRINT(id, log_level_pkt, true, "[ILITEK][PKT]", fmt, ##__VA_ARGS__)

enum ilitek_array_type {
	TYPE_U8 = 0,
	TYPE_INT,
	TYPE_U32,
};

#define TP_ERR_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_err, "[ILITEK][ERR]", tag, type, len, buf)
#define TP_WARN_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_warn, "[ILITEK][WARN]", tag, type, len, buf)
#define TP_TAG_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_tag, "[ILITEK][TAG]", tag, type, len, buf)
#define TP_INFO_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_info, "[ILITEK][INFO]", tag, type, len, buf)
#define TP_MSG_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_msg, "[ILITEK][MSG]", tag, type, len, buf)
#define TP_DBG_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_dbg, "[ILITEK][DBG]", tag, type, len, buf)
#define TP_PKT_ARR(id, tag, type, len, buf) \
	tp_log_arr(id, log_level_pkt, "[ILITEK][PKT]", tag, type, len, buf)

extern int tp_log_level;
extern bool tp_print_en;
extern char g_str[4096];
extern FILE *tp_fp;

typedef void (*msg_t)(int, char *);
extern msg_t g_msg;

#ifdef __cplusplus
extern "C" {
#endif

void __DLL tp_log_arr(char *id, int level, const char *header,
		      const char *tag, int type, int len, void *buf);

int __DLL get_time_ms(uint32_t *t_ms);
void __DLL set_print_en(bool enable);
void __DLL set_log_level(int level);
int __DLL set_log_fopen(WCHAR *filename);
void __DLL set_log_fclose(void);
void __DLL set_log_fwrite(char *str);


#ifdef __cplusplus
}
#endif

#endif
