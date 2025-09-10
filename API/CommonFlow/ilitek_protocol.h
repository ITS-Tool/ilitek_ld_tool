/* SPDX-License-Identifier: GPL-2.0 */
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#ifndef __ILITEK_PROTOCOL_H__
#define __ILITEK_PROTOCOL_H__

#include "ilitek_def.h"


#define START_ADDR_LEGO			0x3000
#define START_ADDR_29XX			0x4000
#define END_ADDR_LEGO			0x40000

#define MM_ADDR_LEGO			0x3020
#define MM_ADDR_29XX			0x4020
#define MM_ADDR_2501X			0x4038

#define DF_START_ADDR_LEGO		0x3C000
#define DF_START_ADDR_29XX		0x2C000

#define ILITEK_TP_SYSTEM_READY		0x50

#define CRC_CALCULATE			0
#define CRC_GET				1

#define ILTIEK_MAX_BLOCK_NUM		20

#define PTL_ANY				0x00 
#define PTL_V6				0x06

#define BL_PROTOCOL_V1_8		0x10800 

#define TOUT_CF_BLOCK_0			2500
#define TOUT_CF_BLOCK_N			500
#define TOUT_F1_SHORT			1600
#define TOUT_F1_OPEN			12
#define TOUT_F1_FREQ_MC			2
#define TOUT_F1_FREQ_SC			1
#define TOUT_F1_CURVE			13
#define TOUT_F1_KEY			400
#define TOUT_F1_OTHER			27
#define TOUT_F2				7
#define TOUT_CD				27
#define TOUT_C3				100
#define TOUT_65_WRITE			135
#define TOUT_65_READ			3
#define TOUT_68				24
#define TOUT_CC_SLAVE			16000

#define TOUT_F1_SHORT_RATIO		2
#define TOUT_F1_OPEN_RATIO		3
#define TOUT_F1_FREQ_RATIO		3
#define TOUT_F1_CURVE_RATIO		3
#define TOUT_F1_OTHER_RATIO		3
#define TOUT_F2_RATIO			3
#define TOUT_CD_RATIO			3
#define TOUT_C3_RATIO			3
#define TOUT_65_WRITE_RATIO		3
#define TOUT_65_READ_RATIO		3
#define TOUT_68_RATIO			3
#define TOUT_CC_SLAVE_RATIO		2

#define AP_MODE		0x5A
#define BL_MODE		0x55

#define ILITEK_CMD_MAP							\
	X(0x40, PTL_ANY, GET_FW_VER, api_protocol_get_fw_ver)		\
	X(0x42, PTL_ANY, GET_PTL_VER, api_protocol_get_ptl_ver)		\
	X(0x60, PTL_ANY, SET_SW_RST, api_protocol_set_sw_reset)		\
	X(0x61, PTL_ANY, GET_MCU_VER, api_protocol_get_mcu_ver)		\
	X(0x80, PTL_ANY, GET_SYS_BUSY, api_protocol_get_sys_busy)	\
	X(0xC0, PTL_ANY, GET_MCU_MOD, api_protocol_get_mcu_mode)	\
	X(0xC1, PTL_ANY, SET_AP_MODE, api_protocol_set_ap_mode)		\
	X(0xC2, PTL_ANY, SET_BL_MODE, api_protocol_set_bl_mode)		\
									\
	/* v6 only cmds */						\
	X(0x27, PTL_V6, GET_SENSOR_ID, api_protocol_get_sensor_id)	\
	X(0x46, PTL_V6, GET_FWID, api_protocol_get_fwid)		\
	X(0x62, PTL_V6, GET_MCU_INFO, api_protocol_get_mcu_info)	\
	X(0xC3, PTL_V6, WRITE_DATA_V6, api_protocol_write_data_v6)	\
	X(0xC9, PTL_V6, SET_DATA_LEN, api_protocol_set_data_len)	\
	X(0xCC, PTL_V6, SET_FLASH_EN, api_protocol_set_flash_enable)	\
	X(0xCD, PTL_V6, GET_BLK_CRC_ADDR, api_protocol_get_crc_by_addr)	\
	X(0xF0, PTL_V6, SET_MOD_CTRL, api_protocol_set_mode_v6)


#define X(_cmd, _protocol, _cmd_id, _api)	_cmd_id,
enum ilitek_cmd_ids {
	ILITEK_CMD_MAP
	/* ALWAYS keep at the end */
	MAX_CMD_CNT
};
#undef X

#define X(_cmd, _protocol, _cmd_id, _api)	CMD_##_cmd_id = _cmd,
enum ilitek_cmds { ILITEK_CMD_MAP };
#undef X 

enum ilitek_fw_modes {
	mode_unknown = -1,
	mode_normal = 0,
	mode_test,
	mode_debug,
	mode_suspend,
};
 
enum ilitek_enum_type {
	enum_ap_bl = 0,
	enum_sw_reset,
};

typedef int (*write_then_read_t)(uint8_t *, int, uint8_t *, int, void *);
typedef void (*init_ack_t)(unsigned int, void *);
typedef int (*wait_ack_t)(uint8_t, unsigned int, void *);
typedef int (*hw_reset_t)(unsigned int, void *);
typedef int (*re_enum_t)(uint8_t, void *);
typedef void (*delay_ms_t)(unsigned int);
 
typedef void (*mode_switch_notify_t)(bool, bool, void *);

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif
 
struct __PACKED__ ilitek_ts_kernel_info {
	char ic_name[6];
	char mask_ver[2];
	uint32_t mm_addr;
	uint32_t min_addr;
	uint32_t max_addr;
	char module_name[32];

	char ic_full_name[16];
};

struct __PACKED__ ilitek_sensor_id {
	uint16_t header;
	uint8_t id;
};

struct __PACKED__ ilitek_ts_protocol {
	uint32_t ver;
	uint8_t flag;
};

struct __PACKED__ ilitek_ts_ic {
	uint8_t mode;
	uint32_t crc[ILTIEK_MAX_BLOCK_NUM];

	char mode_str[32];
};

struct __PACKED__ ilitek_ts_settings {
	bool no_INT_ack;
	uint8_t sensor_id_mask;
};

struct __PACKED__ ilitek_ts_callback {
	/* Please don't use "repeated start" for I2C interface */
	write_then_read_t write_then_read;
	init_ack_t init_ack;
	wait_ack_t wait_ack;
	hw_reset_t hw_reset;
	re_enum_t re_enum;
	delay_ms_t delay_ms;
	msg_t msg;

	/* notify caller after AP/BL mode switch command */
	mode_switch_notify_t mode_switch_notify;
};

struct __PACKED__ ilitek_common_info { 
	uint16_t customer_id;
	uint16_t fwid;

	uint8_t fw_ver[8]; 

	struct ilitek_ts_protocol protocol; 
	struct ilitek_sensor_id sensor;
	struct ilitek_ts_ic ic[32]; 
	struct ilitek_ts_kernel_info mcu;
};

struct __PACKED__ ilitek_ts_device {
	void *_private;
	char id[64];
	uint32_t reset_time;

	struct ilitek_ts_settings setting;
 
	uint16_t customer_id;
	uint16_t fwid;

	uint8_t fw_ver[8]; 

	struct ilitek_ts_protocol protocol; 
	struct ilitek_sensor_id sensor;
	struct ilitek_ts_ic ic[32]; 
	struct ilitek_ts_kernel_info mcu_info;

	uint8_t fw_mode; 

	uint8_t wbuf[4096];
	uint8_t rbuf[4096];
	struct ilitek_ts_callback cb;
};

#ifdef _WIN32
#pragma pack()
#endif

#ifdef __cplusplus
extern "C" {
#endif

void __DLL rectify_ic_name(char *ic_name, int size);

uint16_t __DLL le16(const uint8_t *p);
uint16_t __DLL be16(const uint8_t *p);
uint32_t __DLL le32(const uint8_t *p, int bytes);
uint32_t __DLL be32(const uint8_t *p, int bytes);

bool __DLL is_29xx(void *handle);  

uint8_t __DLL get_protocol_ver_flag(uint32_t ver);
 
uint16_t __DLL get_crc(uint32_t start, uint32_t end,
		       uint8_t *buf, uint32_t buf_size); 

bool __DLL support_sensor_id(void *handle); 
bool __DLL support_fwid(void *handle);

int __DLL reset_helper(void *handle);

int __DLL write_then_read(void *handle, uint8_t *cmd, int wlen,
			  uint8_t *buf, int rlen);
void __DLL ilitek_dev_setting(void *handle,
			      struct ilitek_ts_settings *setting);

void __DLL ilitek_dev_bind_callback(void *handle,
				    struct ilitek_ts_callback *callback);

void __DLL *ilitek_dev_init(const char *id, bool need_update_ts_info,
			    struct ilitek_ts_callback *callback,
			    void *_private);
void __DLL ilitek_dev_exit(void *handle); 

int __DLL api_update_ts_info(void *handle);

int __DLL api_protocol_set_cmd(void *handle, uint8_t idx, void *data);
int __DLL api_set_ctrl_mode(void *handle, uint8_t mode, bool eng, bool force);

uint16_t __DLL api_get_block_crc_by_addr(void *handle, uint8_t type,
					 uint32_t start, uint32_t end); 

int __DLL api_set_data_len(void *handle, uint16_t data_len);
int __DLL api_write_enable_v6(void *handle, bool in_ap, bool is_slave,
			      uint32_t start, uint32_t end);
int __DLL api_write_data_v6(void *handle, int wlen); 
int __DLL api_check_busy(void *handle, int timeout_ms, int delay_ms); 

int __DLL api_to_bl_mode(void *handle, bool bl, uint32_t start, uint32_t end); 

#ifdef __cplusplus
}
#endif

#endif
