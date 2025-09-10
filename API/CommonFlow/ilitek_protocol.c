// SPDX-License-Identifier: GPL-2.0
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#include "ilitek_protocol.h"

typedef int (*protocol_func_t)(struct ilitek_ts_device *, void *);

struct protocol_map {
	uint8_t cmd;
	uint8_t flag;
	protocol_func_t func;
	const char *desc;
};

#define X(_cmd, _protocol, _cmd_id, _api) \
	static int _api(struct ilitek_ts_device *, void *);
ILITEK_CMD_MAP
#undef X

#define X(_cmd, _protocol, _cmd_id, _api) {_cmd, _protocol, _api, #_cmd_id},
struct protocol_map protocol_maps[] = { ILITEK_CMD_MAP };
#undef X

void rectify_ic_name(char *ic_name, int size)
{
	UNUSED(size);

	if (!strcmp(ic_name, "2133"))
		_sprintf(ic_name, 0, "2132S");
	else if (!strcmp(ic_name, "2324"))
		_sprintf(ic_name, 0, "2322S");
	else if (!strcmp(ic_name, "2522"))
		_sprintf(ic_name, 0, "2521S");
}


uint16_t le16(const uint8_t *p)
{
	return p[0] | p[1] << 8;
}

uint16_t be16(const uint8_t *p)
{
	return p[1] | p[0] << 8;
}

uint32_t le32(const uint8_t *p, int bytes)
{
	uint32_t val = 0;

	while (bytes--)
		val += (p[bytes] << (8 * bytes));

	return val;
}

uint32_t be32(const uint8_t *p, int bytes)
{
	uint32_t val = 0;

	while (bytes--)
		val = (val << 8) | (*p++);

	return val;
}

static bool is_2501x(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if (!dev)
		return false;

	if (!strcmp(dev->mcu_info.ic_name, "25011") ||
	    !strcmp(dev->mcu_info.ic_name, "25012"))
		return true;

	return false;
}

bool is_29xx(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	
	if (!dev)
		return false;

	if (!strcmp(dev->mcu_info.ic_name, "2900") ||
	    !strcmp(dev->mcu_info.ic_name, "2901") ||
	    !strcmp(dev->mcu_info.ic_name, "2910") ||
	    !strcmp(dev->mcu_info.ic_name, "2911") ||
	    !strcmp(dev->mcu_info.ic_name, "2531") ||
	    !strcmp(dev->mcu_info.ic_name, "2532") ||
	    !strcmp(dev->mcu_info.ic_name, "2921") ||
	    !strcmp(dev->mcu_info.ic_name, "2901M") ||
	    is_2501x(handle))
		return true;

	return false;
}

uint8_t get_protocol_ver_flag(uint32_t ver)
{
	if (((ver >> 16) & 0xFF) == 0x6 || (ver & 0xFFFF00) == BL_PROTOCOL_V1_8)
		return PTL_V6;

	return PTL_ANY;
}

static uint16_t update_crc(uint16_t crc, uint8_t newbyte)
{
	char i;
	const uint16_t crc_poly = 0x8408;

	crc ^= newbyte;

	for (i = 0; i < 8; i++) {
		if (crc & 0x01)
			crc = (crc >> 1) ^ crc_poly;
		else
			crc = crc >> 1;
	}

	return crc;
}

uint16_t get_crc(uint32_t start, uint32_t end,
		 uint8_t *buf, uint32_t buf_size)
{
	uint16_t crc = 0;
	uint32_t i;

	if (end > buf_size || start > buf_size) {
		TP_WARN(NULL, "start/end addr: 0x%x/0x%x buf size: 0x%x OOB\n",
			start, end, buf_size);
		return 0;
	}

	for (i = start; i < end && i < buf_size; i++)
		crc = update_crc(crc, buf[i]);

	return crc;
}

bool support_mcu_info(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if ((dev->ic[0].mode == BL_MODE && dev->protocol.ver < 0x010803) ||
	    (dev->ic[0].mode == AP_MODE && dev->protocol.ver < 0x060009))
		return false;

	return true;
}

bool support_sensor_id(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if ((dev->ic[0].mode == BL_MODE && dev->protocol.ver < 0x010803) ||
		(dev->ic[0].mode == AP_MODE && dev->protocol.ver < 0x060004))
		return false;

	return true;
}

bool support_fwid(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if ((dev->ic[0].mode == BL_MODE && dev->protocol.ver < 0x010802) ||
		(dev->ic[0].mode == AP_MODE && dev->protocol.ver < 0x060007))
		return false;

	return true;
}

int reset_helper(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	bool need_re_enum = true;

	return api_protocol_set_cmd(dev, SET_SW_RST, &need_re_enum);
}

int write_then_read(void *handle, uint8_t *cmd, int wlen,
		    uint8_t *buf, int rlen)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	int error;

	if (!dev->cb.write_then_read)
		return -EINVAL;

	if (wlen > 0)
		TP_PKT_ARR(dev->id, "[wbuf]:", TYPE_U8, wlen, cmd);

	error = dev->cb.write_then_read(cmd, wlen, buf, rlen, dev->_private);

	if (rlen > 0)
		TP_PKT_ARR(dev->id, "[rbuf]:", TYPE_U8, rlen, buf);
	
	return (error < 0) ? error : 0;
}

int write_then_wait_ack(void *handle, uint8_t *cmd, int wlen, int timeout_ms)
{
	int error;
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	struct ilitek_ts_callback *cb = &dev->cb;

	uint8_t ack_cmd;

	TP_DBG(dev->id, "cmd: 0x" PFMT_X8 ", tout_ms: %d\n",
		cmd[0], timeout_ms);

	if (dev->setting.no_INT_ack) {
		if ((error = write_then_read(dev, cmd, wlen, NULL, 0)) < 0)
			return error;

		/*
		* for no-INT-ack flow, add delay to prevent
		* interrupting FW flow too soon, while FW should
		* be handling previous write command. ex. 0xcd/ 0xc3
		*/
		cb->delay_ms(5);

		goto check_busy;
	}

	if (!cb->init_ack || !cb->wait_ack)
		return -EINVAL;
	
	cb->init_ack(timeout_ms, dev->_private);
	if ((error = write_then_read(dev, cmd, wlen, NULL, 0)) < 0)
		return error;

	ack_cmd = cmd[0];
	error = cb->wait_ack(ack_cmd, timeout_ms, dev->_private);

	/* cmd[0] should be ILITEK cmd code */
	if (error < 0) {
		TP_WARN(dev->id, "wait 0x" PFMT_X8 " ack %d ms timeout, err: %d\n",
			cmd[0], timeout_ms, error);

		goto check_busy;
	}

	return 0;

check_busy:
	return api_check_busy(dev, timeout_ms, 10);
}

/* Common APIs */
static int api_protocol_get_ptl_ver(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	dev->protocol.flag = PTL_V6;
	dev->reset_time = 1000;
	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 3)) < 0)
		return error;

	dev->protocol.ver = (dev->rbuf[0] << 16) + (dev->rbuf[1] << 8) +
			     dev->rbuf[2];
	TP_MSG(dev->id, "[Protocol Version]: %x.%x.%x\n",
		(dev->protocol.ver >> 16) & 0xFF,
		(dev->protocol.ver >> 8) & 0xFF,
		dev->protocol.ver & 0xFF);

	dev->protocol.flag = get_protocol_ver_flag(dev->protocol.ver);
	switch (dev->protocol.flag) {
	case PTL_V6: dev->reset_time = 600; break;
	default:
		TP_ERR(dev->id, "unrecognized protocol ver.: 0x%x\n",
			dev->protocol.ver);
		return -EINVAL;
	}

	return 0;
}

static int api_protocol_get_fw_ver(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 8)) < 0)
		return error;

	_memcpy(dev->fw_ver, dev->rbuf, 8);

	if (dev->ic[0].mode == BL_MODE) {
		TP_MSG_ARR(dev->id, "[BL Firmware Version]", TYPE_U8,
			   8, dev->fw_ver);
	} else {
		TP_MSG_ARR(dev->id, "[FW Version]", TYPE_U8, 4, dev->fw_ver);
		TP_MSG_ARR(dev->id, "[Customer Version]", TYPE_U8,
			   4, dev->fw_ver + 4);
	}

	return 0;
}

static int api_protocol_get_mcu_mode(struct ilitek_ts_device *dev, void *data)
{
	int error;

        UNUSED(data);

	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 2)) < 0)
		return error;

	dev->ic[0].mode = dev->rbuf[0];

	if (dev->ic[0].mode == AP_MODE)
		_sprintf(dev->ic[0].mode_str, 0, "AP");
	else if (dev->ic[0].mode == BL_MODE)
		_sprintf(dev->ic[0].mode_str, 0, "BL");
	else
		_sprintf(dev->ic[0].mode_str, 0, "UNKNOWN");

	TP_MSG(dev->id, "[Current Mode] Master: 0x" PFMT_X8 " " PFMT_C8 "\n",
		dev->ic[0].mode, dev->ic[0].mode_str);

	return 0;
}

static int api_protocol_get_sensor_id(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	/* return 0 to skip error check */
	if (!support_sensor_id(dev))
		return 0;

	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 3)) < 0)
		return error;

	dev->sensor.header = be16(dev->rbuf);
	dev->sensor.id = dev->rbuf[2];

	TP_MSG(dev->id, "[Sensor ID] header: 0x" PFMT_X16 ", id: 0x" PFMT_X8 "\n",
		dev->sensor.header,
		(uint8_t)(dev->sensor.id & dev->setting.sensor_id_mask));

	return 0;
}

static int api_protocol_get_fwid(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	/* return 0 to skip error check */
	if (!support_fwid(dev))
		return 0;

	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 4)) < 0)
		return error;

	dev->customer_id = le16(dev->rbuf);
	dev->fwid = le16(dev->rbuf + 2);

	TP_MSG(dev->id, "[Customer ID] 0x%04x\n", dev->customer_id);
	TP_MSG(dev->id, "[FWID] 0x%04x\n", dev->fwid);

	return 0;
}

static bool is_special_char(char c)
{
	return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9')) ? false : true;
}

static int api_protocol_get_mcu_ver(struct ilitek_ts_device *dev, void *data)
{
	int error;
	unsigned int i;

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif
	struct __PACKED__ mcu_ver {
		uint16_t ic_name;
		uint8_t df_start_addr[3];
		uint8_t df_size;

		char module_name[26];
	} *parser;

#ifdef _WIN32
#pragma pack()
#endif

	UNUSED(data);

	/*
	 * GET_MCU_INFO (0x62) cmd support V6 and BL > v1.8.2 and AP > v6.0.7
	 * otherwise, use GET_MCU_VER (0x61) cmd
	 */
	if (dev->protocol.flag == PTL_V6 && support_mcu_info(dev)) {
		if ((error = api_protocol_set_cmd(dev, GET_MCU_INFO,
						  NULL)) < 0)
			return error;
	} else {
		if ((error = write_then_read(dev, dev->wbuf, 1,
			dev->rbuf, 32)) < 0)
			return error;

		parser = (struct mcu_ver *)dev->rbuf;

		_memset(dev->mcu_info.ic_name, 0,
			sizeof(dev->mcu_info.ic_name));
		_sprintf(dev->mcu_info.ic_name, 0, "%04x", parser->ic_name);

		_memset(dev->mcu_info.module_name, 0,
			sizeof(dev->mcu_info.module_name));
		_memcpy(dev->mcu_info.module_name, parser->module_name,
			sizeof(parser->module_name));
	}

	if (dev->protocol.flag == PTL_V6) {
		if (is_29xx(dev)) {
			/* modify reset time to 100ms for 29xx ICs */
			dev->reset_time = 100;

			/* set mm_addr for bin file update */
			dev->mcu_info.mm_addr =
				is_2501x(dev) ? MM_ADDR_2501X : MM_ADDR_29XX;
			dev->mcu_info.min_addr = START_ADDR_29XX;
			dev->mcu_info.max_addr = END_ADDR_LEGO;
		} else {
			dev->mcu_info.mm_addr = MM_ADDR_LEGO;
			dev->mcu_info.min_addr = START_ADDR_LEGO;
			dev->mcu_info.max_addr = END_ADDR_LEGO;
		}
	}

	for (i = 0; i < sizeof(dev->mcu_info.module_name); i++) {
		if (is_special_char(dev->mcu_info.module_name[i]))
			dev->mcu_info.module_name[i] = 0;
	}

	rectify_ic_name(dev->mcu_info.ic_name, sizeof(dev->mcu_info.ic_name));

	_memset(dev->mcu_info.ic_full_name, 0,
		sizeof(dev->mcu_info.ic_full_name));
	_sprintf(dev->mcu_info.ic_full_name, 0,
		"ILI" PFMT_C8, dev->mcu_info.ic_name);

	TP_MSG(dev->id, "[MCU Kernel Version] " PFMT_C8 "\n",
		dev->mcu_info.ic_full_name);
	TP_MSG(dev->id, "[Module Name]: [" PFMT_C8 "]\n",
		dev->mcu_info.module_name);

	return 0;
}

static int api_protocol_get_mcu_info(struct ilitek_ts_device *dev, void *data)
{
	int error;
	unsigned int i;

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif
	struct __PACKED__ mcu_info {
		char ic_name[5];
		char mask_ver[2];
		uint8_t mm_addr[3];
		char module_name[18];
		uint8_t reserve[4];
	} *parser;

#ifdef _WIN32
#pragma pack()
#endif

	UNUSED(data);

	/*
	 * GET_MCU_INFO (0x62) cmd only support V6 and BL > v1.8.2 and AP > v6.0.7
	 * otherwise, return 0 to skip this command.
	 */
	if (dev->protocol.flag != PTL_V6 || !support_mcu_info(dev))
		return 0;

	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 32)) < 0)
		return error;

	parser = (struct mcu_info *)dev->rbuf;

	_memset(dev->mcu_info.ic_name, 0, sizeof(dev->mcu_info.ic_name));
	_memcpy(dev->mcu_info.ic_name, parser->ic_name,
		sizeof(parser->ic_name));

	_memcpy(dev->mcu_info.module_name, parser->module_name,
		sizeof(parser->module_name));
	dev->mcu_info.mm_addr = le32(parser->mm_addr, 3);

	for (i = 0; i < sizeof(dev->mcu_info.module_name); i++) {
		if (is_special_char(dev->mcu_info.module_name[i]))
			dev->mcu_info.module_name[i] = 0;
	}

	return 0;
}

static int api_protocol_set_sw_reset(struct ilitek_ts_device *dev, void *data)
{
	int error;
	int wlen = 1;
	bool force_reset = (!data) ? true : false;

	/* make sure touch report in default I2C-HID mode after force reset */
	if (!force_reset)
		return 0;

	dev->wbuf[1] = 0;
	if ((error = write_then_read(dev, dev->wbuf, wlen, dev->rbuf, 0)) < 0)
		return error;

	dev->cb.delay_ms(dev->reset_time);

	return 0;
}

static int api_protocol_get_sys_busy(struct ilitek_ts_device *dev, void *data)
{
	int error;

	if (data)
		*(uint8_t *)data = 0;

	_memset(dev->rbuf, 0, 64);
	if ((error = write_then_read(dev, dev->wbuf, 1, dev->rbuf, 1)) < 0)
		return error;

	if (data)
		*(uint8_t *)data = dev->rbuf[0];

	return 0;
}

static int api_protocol_set_mode_v6(struct ilitek_ts_device *dev, void *data)
{
	UNUSED(data);

	return write_then_read(dev, dev->wbuf, 3, NULL, 0);
}

static int api_protocol_get_crc_by_addr(struct ilitek_ts_device *dev,
					void *data)
{
	int error;
	uint8_t type = (data) ? *(uint8_t *)data : 0;
	uint32_t start, end, t_ms;

	dev->wbuf[1] = type;

	if (type == CRC_CALCULATE) {
		start = le32(dev->wbuf + 2, 3);
		end = le32(dev->wbuf + 5, 3);
		t_ms = ((end - start) / 4096 + 1) * TOUT_CD * TOUT_CD_RATIO;

		if ((error = write_then_wait_ack(dev, dev->wbuf, 8, t_ms)) < 0)
			return error;
		type = CRC_GET;
		return api_protocol_set_cmd(dev, GET_BLK_CRC_ADDR, &type);
	}

	return write_then_read(dev, dev->wbuf, 2, dev->rbuf, 2);
}

static int api_protocol_set_data_len(struct ilitek_ts_device *dev, void *data)
{
	UNUSED(data);

	return write_then_read(dev, dev->wbuf, 3, NULL, 0);
}

static int api_protocol_set_flash_enable(struct ilitek_ts_device *dev,
					 void *data)
{
	int error;
	uint8_t type = (data) ? *(uint8_t *)data : 0;
	int wlen, rlen;
	bool in_ap = ((type & 0x1) != 0) ? true : false;

	uint32_t set_start, set_end, get_start, get_end;


	wlen = (in_ap) ? 3 : 9;
	rlen = (in_ap || dev->protocol.ver < 0x010803) ? 0 : 6;

	set_start = le32(dev->wbuf + 3, 3);
	set_end = le32(dev->wbuf + 6, 3);

	if ((error = write_then_read(dev, dev->wbuf, wlen,
				     dev->rbuf, rlen)) < 0)
		return error;

	if (in_ap || dev->protocol.ver < 0x010803)
		return 0;

	get_start = le32(dev->rbuf, 3);
	get_end = le32(dev->rbuf + 3, 3);

	if (set_start != get_start || set_end != get_end) {
		TP_ERR(dev->id, "start/end addr.: 0x%x/0x%x vs. 0x%x/0x%x not match\n",
			set_start, set_end, get_start, get_end);
		return -EINVAL;
	}
	
	return 0;
}

static int api_protocol_write_data_v6(struct ilitek_ts_device *dev, void *data)
{
	int wlen;

	if (!data)
		return -EINVAL;

	wlen = *(int *)data;

	return write_then_wait_ack(dev, dev->wbuf, wlen, TOUT_C3 * TOUT_C3_RATIO);
}

static int api_protocol_set_ap_mode(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	if (dev->cb.mode_switch_notify)
		dev->cb.mode_switch_notify(true, false, dev->_private);

	error = write_then_read(dev, dev->wbuf, 1, NULL, 0);

	if (dev->cb.mode_switch_notify)
		dev->cb.mode_switch_notify(false, false, dev->_private);

	return error;
}

static int api_protocol_set_bl_mode(struct ilitek_ts_device *dev, void *data)
{
	int error;

	UNUSED(data);

	if (dev->cb.mode_switch_notify)
		dev->cb.mode_switch_notify(true, false, dev->_private);

	error = write_then_read(dev, dev->wbuf, 1, NULL, 0);

	if (dev->cb.mode_switch_notify)
		dev->cb.mode_switch_notify(false, true, dev->_private);

	return error;
}

int api_protocol_set_cmd(void *handle, uint8_t idx, void *data)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	int error;

	if (!dev || idx >= ARRAY_SIZE(protocol_maps))
		return -EINVAL;

	if (!(dev->protocol.flag & protocol_maps[idx].flag) &&
	    protocol_maps[idx].flag != PTL_ANY) {
		TP_ERR(dev->id, "Unexpected cmd: " PFMT_C8 " for 0x" PFMT_X8 " only, now is 0x" PFMT_X8 "\n",
			protocol_maps[idx].desc, protocol_maps[idx].flag,
			dev->protocol.flag);
		return -EINVAL;
	}

	dev->wbuf[0] = protocol_maps[idx].cmd;
	if ((error = protocol_maps[idx].func(dev, data)) < 0) {
		TP_ERR(dev->id, "failed to execute cmd: 0x" PFMT_X8 " " PFMT_C8 ", err: %d\n",
			protocol_maps[idx].cmd, protocol_maps[idx].desc, error);
		return error;
	}

	return 0;
}

int api_set_ctrl_mode(void *handle, uint8_t mode, bool eng, bool force)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	int error;
	uint8_t cmd = 0;

	_memset(dev->wbuf, 0, sizeof(dev->wbuf));

	dev->wbuf[1] = mode;
	dev->wbuf[2] = (eng) ? 0x01 : 0x00;
	cmd = SET_MOD_CTRL;

	if ((error = api_protocol_set_cmd(dev, cmd, NULL)) < 0)
		return error;

        dev->fw_mode = mode;

        if (!force)
                return 0;

	dev->cb.delay_ms(30);

	return 0;
}

uint16_t api_get_block_crc_by_addr(void *handle, uint8_t type,
				   uint32_t start, uint32_t end)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	_memset(dev->wbuf, 0, 64);

	dev->wbuf[2] = start;
	dev->wbuf[3] = (start >> 8) & 0xFF;
	dev->wbuf[4] = (start >> 16) & 0xFF;
	dev->wbuf[5] = end & 0xFF;
	dev->wbuf[6] = (end >> 8) & 0xFF;
	dev->wbuf[7] = (end >> 16) & 0xFF;
	if (api_protocol_set_cmd(dev, GET_BLK_CRC_ADDR, &type) < 0)
		return 0;

	return le16(dev->rbuf);
}

int api_set_data_len(void *handle, uint16_t data_len)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	_memset(dev->wbuf, 0, 64);

	dev->wbuf[1] = data_len & 0xFF;
	dev->wbuf[2] = (data_len >> 8) & 0xFF;

	return api_protocol_set_cmd(dev, SET_DATA_LEN, NULL);
}

int api_write_enable_v6(void *handle, bool in_ap, bool is_slave,
			uint32_t start, uint32_t end)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	uint8_t type;

	_memset(dev->wbuf, 0, 64);
	dev->wbuf[1] = 0x5A;
	dev->wbuf[2] = 0xA5;
	dev->wbuf[3] = start & 0xFF;
	dev->wbuf[4] = (start >> 8) & 0xFF;
	dev->wbuf[5] = start >> 16;
	dev->wbuf[6] = end & 0xFF;
	dev->wbuf[7] = (end >> 8) & 0xFF;
	dev->wbuf[8] = end >> 16;

	type = (in_ap) ? 0x1 : 0x0;
	type |= (is_slave) ? 0x2 : 0x0;

	return api_protocol_set_cmd(dev, SET_FLASH_EN, &type);
}

int api_write_data_v6(void *handle, int wlen)
{
	return api_protocol_set_cmd(handle, WRITE_DATA_V6, &wlen);
}

int api_check_busy(void *handle, int timeout_ms, int delay_ms)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	uint8_t busy;

	/* retry 2 times at least */
	int i = MAX(DIV_ROUND_UP(timeout_ms, delay_ms), 2);

	_memset(dev->wbuf, 0, 64);

	while (i--) {
		api_protocol_set_cmd(dev, GET_SYS_BUSY, &busy);
		if (busy == ILITEK_TP_SYSTEM_READY)
			return 0;

		/* delay ms for each check busy */
		dev->cb.delay_ms(delay_ms);
	}

	TP_WARN(dev->id, "check busy timeout: %d ms, state: 0x" PFMT_X8 "\n",
		timeout_ms, busy);

	return -EILIBUSY;
}

int api_to_bl_mode(void *handle, bool to_bl,
		   uint32_t start, uint32_t end)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;
	int cnt = 0, retry = 15;
	const uint8_t target_mode = (to_bl) ? BL_MODE : AP_MODE;

	do {
		if (api_protocol_set_cmd(dev, GET_MCU_MOD, NULL) < 0)
			continue;

		if (dev->ic[0].mode == target_mode)
			goto success_change_mode;

		if (to_bl) {
			if (api_write_enable_v6(dev, true, false, 0, 0) < 0)
				continue;

			api_protocol_set_cmd(dev, SET_BL_MODE, NULL);
		} else {
			if (api_write_enable_v6(dev, false, false,
                                                start, end) < 0)
				continue;

			api_protocol_set_cmd(dev, SET_AP_MODE, NULL);
		}

		dev->cb.delay_ms(1000 + 100 * cnt);
	} while (cnt++ < retry);

	TP_ERR(dev->id, "current mode: 0x" PFMT_X8 ", change to " PFMT_C8 " mode failed\n",
		dev->ic[0].mode, (to_bl) ? "BL" : "AP");
	return -EFAULT;

success_change_mode:
	TP_MSG(dev->id, "current mode: 0x" PFMT_X8 " " PFMT_C8 " mode\n",
		dev->ic[0].mode, (to_bl) ? "BL" : "AP");

	/* update fw ver. in AP/BL mode */
	api_protocol_set_cmd(dev, GET_FW_VER, NULL);

	/* update protocol ver. in AP/BL mode */
	api_protocol_set_cmd(dev, GET_PTL_VER, NULL);

	return 0;
}

int api_update_ts_info(void *handle)
{
	int error;
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	/* set protocol default V6 initially for comms. afterwards */
	dev->protocol.flag = PTL_V6;

	if ((error = api_set_ctrl_mode(dev, mode_suspend, false, true)) < 0 ||
	    (error = api_protocol_set_cmd(dev, GET_PTL_VER, NULL)) < 0)
		goto err_set_normal;

	if ((error = api_protocol_set_cmd(dev, GET_MCU_MOD, NULL)) < 0 ||
	    (error = api_protocol_set_cmd(dev, GET_MCU_VER, NULL)) < 0 ||
	    (error = api_protocol_set_cmd(dev, GET_FW_VER, NULL)) < 0)
		goto err_set_normal;

	if ((error = api_protocol_set_cmd(dev, GET_FWID, NULL)) < 0 ||
	    (error = api_protocol_set_cmd(dev, GET_SENSOR_ID, NULL)) < 0)
		goto err_set_normal;

err_set_normal:
	api_set_ctrl_mode(dev, mode_normal, false, true);

	return error;
}

void __ilitek_get_info(void *handle, struct ilitek_common_info *info)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if (!info || !dev)
		return;

	_memcpy(info, &dev->customer_id, sizeof(struct ilitek_common_info));
}

void ilitek_dev_setting(void *handle, struct ilitek_ts_settings *setting)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if (!handle)
		return;

	_memcpy(&dev->setting, setting, sizeof(struct ilitek_ts_settings));

	TP_MSG(dev->id, "no-INT-ack: %d\n", dev->setting.no_INT_ack);
}

void ilitek_dev_bind_callback(void *handle, struct ilitek_ts_callback *callback)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if (callback) {
		_memcpy(&dev->cb, callback, sizeof(struct ilitek_ts_callback));
		if (dev->cb.msg)
			g_msg = dev->cb.msg;
	}
}

void *ilitek_dev_init(const char *id, bool need_update_ts_info,
		      struct ilitek_ts_callback *callback, void *_private)
{
	struct ilitek_ts_device *dev;

	dev = (struct ilitek_ts_device *)MALLOC(sizeof(*dev));
	if (!dev)
		return NULL;

	TP_MSG(NULL, "commonflow code version: 0x%x\n",
		COMMONFLOW_CODE_VERSION);

	TP_DBG(NULL, "sizeof(ilitek_ts_device): %u\n",
		(unsigned int)sizeof(struct ilitek_ts_device));

	/* initial all member to 0/ false/ NULL */
	_memset(dev, 0, sizeof(*dev));

	_strcpy(dev->id, id, sizeof(dev->id));
	ilitek_dev_bind_callback(dev, callback);

	dev->_private = _private;

	/* set protocol default V6 initially for comms. afterwards */
	dev->protocol.flag = PTL_V6;

	dev->fw_mode = mode_unknown;

	if (need_update_ts_info && api_update_ts_info(dev) < 0) {
		ilitek_dev_exit(dev);
		return NULL;
	}

	return dev;
}

void ilitek_dev_exit(void *handle)
{
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)handle;

	if (dev)
		FREE(dev);
}
