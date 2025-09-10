/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#ifndef __ILITEK_UPDATE_H__
#define __ILITEK_UPDATE_H__

#include "ilitek_protocol.h"

#define UPDATE_LEN			1024


#define ILITEK_FW_FILE_SIZE		(512 * 1024)
#define ILITEK_FW_BUF_SIZE		(256 * 1024)

enum fw_file_type {
	fw_hex = 0,
	fw_bin,
	fw_ili,
};

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif

struct __PACKED__ mapping_info_lego {
	uint8_t tuning_ver[4];
	uint8_t fw_ver[4];
	uint8_t core_test;
	uint8_t core_day;
	uint8_t core_month;
	uint8_t core_year;
	uint32_t core_ver;
	uint8_t vendor_ver[6];
	uint8_t _reserve_1[8];
	uint16_t customer_id;
	uint16_t fwid;
	uint16_t i2c_addr;
	uint8_t _reserve_2[2];
	char model_name[16];
	uint8_t _reserve_3[2];
	uint8_t ic_num;
	uint8_t total_tuning_num;
	uint16_t sizeof_tuning;
	uint16_t sizeof_tp_param;
	uint16_t sizeof_sys_info;
	uint16_t sizeof_sys_algo;
	uint16_t sizeof_key_info;
	uint8_t block_num;
	uint8_t support_tuning_num;
	uint8_t _reserve_4[2];

	struct __PACKED__ {
		uint8_t addr[3];
	} blocks[10];

	uint8_t _reserve_5[9];
	uint8_t end_addr[3];
	uint8_t _reserve_6[2];
};

union __PACKED__ mapping_info {
	struct __PACKED__ {
		uint8_t mapping_ver[3];
		uint8_t protocol_ver[3];
		uint8_t ic_name[6];

		struct mapping_info_lego _lego;
	};
};

/*
 * for V3, "check" is checksum, block[0] for AP and block[1] for Data Flash.
 * for V6, "check" is CRC.
 */
struct __PACKED__ ilitek_block {
	bool check_match;
	uint32_t start;
	uint32_t end;
	uint32_t check;
	uint32_t offset;
};

struct __PACKED__ ilitek_fw_file_info {
	char ic_name[8];
	uint8_t fw_ver[8];
	uint16_t fwid;

	uint8_t block_num;
	struct ilitek_block blocks[ILTIEK_MAX_BLOCK_NUM];

	uint32_t mm_addr;
	uint32_t mm_size;

	uint32_t buf_size;
	uint8_t *buf;

	/* fw file's sensor-id or fwid or other id */
	uint32_t id;
	uint8_t type;
};

#ifdef _WIN32
#pragma pack()
#endif

/* return file size in # of bytes, or negative error code */
typedef int (*read_fw_t)(WCHAR *, uint8_t *, int, void *);
/* update progress of fw updating */
typedef void (*update_progress_t)(uint8_t, void *);

struct ilitek_update_callback {
	read_fw_t read_fw;
	update_progress_t update_progress; 
};

enum fw_ver_check_policy {
	allow_fw_ver_downgrade = 1,
	allow_fw_ver_same = 2,
};

struct ilitek_fw_settings {
	int8_t retry; 
	bool force_update;

	bool fw_ver_check;
	uint8_t fw_ver_policy;
	uint8_t fw_ver[8];
};

struct ilitek_fw_handle {
	struct ilitek_ts_device *dev;
	void *_private;

	/* upgrade options */
	struct ilitek_fw_settings setting;

	/* common variable */
	int update_len;

	struct ilitek_fw_file_info file; 

	/* upgrade status */
	unsigned int progress_curr;
	unsigned int progress_max;
	uint8_t progress;

	/* callbacks */
	struct ilitek_update_callback cb;
};

#ifdef __cplusplus
extern "C" {
#endif

void __DLL *ilitek_update_init(void *_dev, bool need_update_ts_info,
			       struct ilitek_update_callback *callback,
			       void *_private);

void __DLL ilitek_update_exit(void *handle);

void __DLL ilitek_update_set_data_length(void *handle, uint16_t len);

void __DLL ilitek_update_setting(void *handle,
				 struct ilitek_fw_settings *setting);

int __DLL ilitek_update_load_fw(void *handle, WCHAR *fw_name);

int __DLL ilitek_update_start(void *handle);

#ifdef __cplusplus
}
#endif


#endif

