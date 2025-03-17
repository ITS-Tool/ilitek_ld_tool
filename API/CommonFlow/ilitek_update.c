// SPDX-License-Identifier: GPL-2.0
/*
 * This file is part of ILITEK CommonFlow
 *
 * Copyright (c) 2022 ILI Technology Corp.
 * Copyright (c) 2022 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2022 Joe Hung <joe_hung@ilitek.com>
 */

#include "ilitek_update.h"

#ifdef _WIN32
/* packed below structures by 1 byte */
#pragma pack(1)
#endif


#ifdef _WIN32
#pragma pack()
#endif

#ifndef __KERNEL__
static int hex_to_bin(uint8_t ch)
{
	uint8_t cu = ch & 0xdf;
	return -1 +
		((ch - '0' +  1) & (unsigned)((ch - '9' - 1) &
		('0' - 1 - ch)) >> 8) +
		((cu - 'A' + 11) & (unsigned)((cu - 'F' - 1) &
		('A' - 1 - cu)) >> 8);
}

static int hex2bin(uint8_t *dst, const uint8_t *src, size_t count)
{
	int hi = 0, lo = 0;

	while (count--) {
		if ((hi = hex_to_bin(*src++)) < 0 ||
		    (lo = hex_to_bin(*src++)) < 0) {
			TP_ERR(NULL, "hex_to_bin failed, hi: %d, lo: %d\n",
				hi, lo);
			return -EINVAL;
		}

		*dst++ = (hi << 4) | lo;
	}
	return 0;
}
#endif

static uint32_t get_tag_addr(uint32_t start, uint32_t end,
			     const uint8_t *buf, unsigned int buf_size,
			     const uint8_t *tag, unsigned int tag_size)
{
	unsigned int i;

	for (i = start; i <= end - tag_size && i < buf_size - tag_size; i++) {
		if (!memcmp(buf + i, tag, tag_size))
			return i + tag_size + 1;
	}

	return end;
}

static uint32_t get_endaddr(uint32_t start, uint32_t end, const uint8_t *buf,
			    unsigned int buf_size, bool is_AP)
{
	uint32_t addr;
	uint8_t tag[32];
	const uint8_t ap_tag[] = "ILITek AP CRC   ";
	const uint8_t blk_tag[] = "ILITek END TAG  ";

	_memset(tag, 0xFF, sizeof(tag));
	_memcpy(tag + 16, (is_AP) ? ap_tag : blk_tag, 16);

	addr = get_tag_addr(start, end, buf, buf_size, tag, sizeof(tag));
	TP_DBG(NULL, "find tag in start/end: 0x%x/0x%x, tag addr: 0x%x\n",
		start, end, addr);

	return addr;
}

static int decode_mm(struct ilitek_fw_handle *fw, uint32_t addr,
		      uint8_t *buf, uint32_t buf_size)
{
	uint8_t i;
	union mapping_info *mapping;

	TP_INFO(NULL, "------------Memory Mapping information------------\n");
	TP_INFO(NULL, "memory-mapping-info addr: 0x%x\n", addr);

	mapping = (union mapping_info *)(buf + addr);
	_memset(fw->file.ic_name, 0, sizeof(fw->file.ic_name));

	switch (mapping->mapping_ver[2]) {
	case 0x2:
		_memcpy(fw->file.ic_name, mapping->ic_name,
			sizeof(mapping->ic_name));
		break;
	default:
	case 0x1:
		_sprintf(fw->file.ic_name, 0, "%02x%02x",
			mapping->ic_name[1], mapping->ic_name[0]);
		break;
	}

	rectify_ic_name(fw->file.ic_name, sizeof(fw->file.ic_name));

	if (fw->dev && strcmp(fw->dev->mcu_info.ic_name, fw->file.ic_name)) {
		TP_ERR(fw->dev->id, "IC: " PFMT_C8 ", Firmware File: " PFMT_C8 " not matched\n",
			fw->dev->mcu_info.ic_name, fw->file.ic_name);
		return -EINVAL;
	}

	TP_MSG(NULL, "Hex Mapping Ver.: 0x%x\n",
		le32(mapping->mapping_ver, 3));
	TP_MSG(NULL, "Hex Protocol: 0x%x\n",
		le32(mapping->protocol_ver, 3));
	TP_MSG(NULL, "Hex MCU Ver.: " PFMT_C8 "\n", fw->file.ic_name);

	_memset(fw->file.fw_ver, 0, sizeof(fw->file.fw_ver));
	fw->file.fwid = 0xffff;

	fw->file.mm_addr = addr;
	switch (addr) {
	case 0x4038:
	case 0x4020:
		fw->file.mm_size = 128;
		fw->file.fw_ver[0] = mapping->_lego.fw_ver[3];
		fw->file.fw_ver[1] = mapping->_lego.fw_ver[2];
		fw->file.fw_ver[2] = mapping->_lego.fw_ver[1];
		fw->file.fw_ver[3] = mapping->_lego.fw_ver[0];
		fw->file.fw_ver[4] = buf[0x2C007];
		fw->file.fw_ver[5] = buf[0x2C006];
		fw->file.fw_ver[6] = buf[0x2C005];
		fw->file.fw_ver[7] = buf[0x2C004];

		fw->file.fwid = mapping->_lego.fwid;
		break;
	case 0x3020:
		fw->file.mm_size = 128;
		fw->file.fw_ver[0] = mapping->_lego.fw_ver[3];
		fw->file.fw_ver[1] = mapping->_lego.fw_ver[2];
		fw->file.fw_ver[2] = mapping->_lego.fw_ver[1];
		fw->file.fw_ver[3] = mapping->_lego.fw_ver[0];
		fw->file.fw_ver[4] = buf[0x3C007];
		fw->file.fw_ver[5] = buf[0x3C006];
		fw->file.fw_ver[6] = buf[0x3C005];
		fw->file.fw_ver[7] = buf[0x3C004];

		fw->file.fwid = mapping->_lego.fwid;
		break; 
	default:
		fw->file.mm_size = 0;
		break;
	}

	TP_MSG(NULL, "file fwid: 0x%04x\n", fw->file.fwid);

	TP_INFO(NULL, "File FW Version: %02x-%02x-%02x-%02x\n",
		fw->file.fw_ver[0], fw->file.fw_ver[1],
		fw->file.fw_ver[2], fw->file.fw_ver[3]);
	TP_INFO(NULL, "File Customer Version: %02x-%02x-%02x-%02x\n",
		fw->file.fw_ver[4], fw->file.fw_ver[5],
		fw->file.fw_ver[6], fw->file.fw_ver[7]);

	if (le32(mapping->mapping_ver, 3) < 0x10000)
		goto memory_mapping_end;

	TP_INFO(NULL, "File Tuning Version: %02x-%02x-%02x-%02x\n",
		mapping->_lego.tuning_ver[3], mapping->_lego.tuning_ver[2],
		mapping->_lego.tuning_ver[1], mapping->_lego.tuning_ver[0]);

	if (mapping->_lego.block_num > ARRAY_SIZE(fw->file.blocks)) {
		TP_ERR(NULL, "Unexpected block num: " PFMT_U8 " > %u\n",
			mapping->_lego.block_num,
			(unsigned int)ARRAY_SIZE(fw->file.blocks));
		goto memory_mapping_end;
	}

	fw->file.block_num = mapping->_lego.block_num;

	TP_MSG(NULL, "Total " PFMT_U8 " blocks\n", fw->file.block_num);
	for (i = 0; i < fw->file.block_num; i++) {
		fw->file.blocks[i].start =
			le32(mapping->_lego.blocks[i].addr, 3);
		fw->file.blocks[i].end = (i == fw->file.block_num - 1) ?
			le32(mapping->_lego.end_addr, 3) :
			le32(mapping->_lego.blocks[i + 1].addr, 3);

		/*
		 * get end addr. of block,
		 * i.e. address of block's final byte of crc.
		 */
		fw->file.blocks[i].end = get_endaddr(
			fw->file.blocks[i].start, fw->file.blocks[i].end,
			buf, buf_size, i == 0);

		fw->file.blocks[i].check = get_crc(fw->file.blocks[i].start,
			fw->file.blocks[i].end - 1,
			buf, buf_size);

		TP_MSG(NULL, "Block[%u], start:0x%x end:0x%x, crc:0x%x\n",
			i, fw->file.blocks[i].start, fw->file.blocks[i].end,
			fw->file.blocks[i].check);
	}

memory_mapping_end:
	TP_INFO(NULL, "--------------------------------------------------\n");

	return 0;
}

static int decode_hex(struct ilitek_fw_handle *fw, uint8_t *hex,
		      uint32_t start, uint32_t end,
		      uint8_t *buf, uint32_t buf_size)
{
	int error;
	uint8_t info[4], data[16];
	unsigned int i, len, addr, type, exaddr = 0;
	uint32_t mapping_info_addr = 0;

	fw->file.blocks[0].start = (~0U);
	fw->file.blocks[0].end = 0x0;
	fw->file.blocks[0].check = 0x0;
	fw->file.blocks[1].start = (~0U);
	fw->file.blocks[1].end = 0x0;
	fw->file.blocks[1].check = 0x0;

	for (i = start; i < end; i++) {
		/* filter out non-hexadecimal characters */
		if (hex_to_bin(hex[i]) < 0)
			continue;

		if ((error = hex2bin(info, hex + i, sizeof(info))) < 0)
			return error;

		len = info[0];
		addr = be32(info + 1, 2);
		type = info[3];

		if ((error = hex2bin(data, hex + i + 8, len)) < 0)
			return error;

		switch (type) {
		case 0xAC:
			mapping_info_addr = be32(data, len);
			break;

		case 0x01:
			goto success_return;

		case 0x02:
			exaddr = be32(data, len) << 4;
			break;

		case 0x04:
			exaddr = be32(data, len) << 16;
			break;

		case 0x05:
			TP_MSG(NULL, "hex data type: 0x%x, start linear address: 0x%x\n",
				type, be32(data, len));
			break;

		case 0x00:
			addr += exaddr;

			if (addr + len > buf_size) {
				TP_ERR(NULL, "hex addr: 0x%x, buf size: 0x%x OOB\n",
					addr + len, buf_size);
				return -ENOBUFS;
			}
			_memcpy(buf + addr, data, len);

			break;
		default:
			TP_ERR(NULL, "unexpected type:0x%x in hex, len:%u, addr:0x%x\n",
				type, len, addr);
			return -EINVAL;
		}

		i = i + 10 + len * 2;
	}

success_return:
	return decode_mm(fw, mapping_info_addr, fw->file.buf, buf_size);
}

static int decode_bin(struct ilitek_fw_handle *fw,
		      uint8_t *bin, uint32_t bin_size,
		      uint8_t *buf, uint32_t buf_size)
{
	int error;
	struct ilitek_ts_device *dev = fw->dev;
	uint32_t mapping_info_addr;

	if (!dev) {
		TP_ERR(NULL, "offline decode bin file is not supported\n");
		return -EINVAL;
	}

	if (bin_size > buf_size) {
		TP_ERR(dev->id, "bin file size: 0x%x, buf size: 0x%x OOB\n",
			bin_size, buf_size);
		return -ENOBUFS;
	}
	_memcpy(buf, bin, bin_size);

	if ((error = api_protocol_set_cmd(dev, GET_PTL_VER, NULL)) < 0 ||
	    (error = api_protocol_set_cmd(dev, GET_MCU_VER, NULL)) < 0)
		return error;

	switch (dev->protocol.flag) {
	case PTL_V6:
		mapping_info_addr = dev->mcu_info.mm_addr;
		break; 

	default:
		return -EINVAL;
	}

	/*
	 * take the whole "buf" into decode_mm, "buf" should be
	 * properly initialized, and the size should be
	 * larger than "bin", which reduce OOB issue.
	 */
	return decode_mm(fw, mapping_info_addr, buf, buf_size);
} 
 
static int decode_firmware(struct ilitek_fw_handle *fw, WCHAR *filename)
{
	int error;
	int size = 0;
	uint8_t *buf;
	WCHAR *file_ext;

	/* initialization */
	_memset(fw->file.buf, 0xFF, fw->file.buf_size); 
	/*
	 * set block num 2 for V3 AP and Data Flash as default,
	 * for V6, block num would be updated after decoding memory mapping.
	 */
	fw->file.block_num = 2;
	fw->file.blocks[0].start = (~0U);
	fw->file.blocks[0].end = 0x0;
	fw->file.blocks[0].check = 0x0;
	fw->file.blocks[1].start = (~0U);
	fw->file.blocks[1].end = 0x0;
	fw->file.blocks[1].check = 0x0;

	TP_MSG(NULL, "start to read fw file: " PFMT_C16 "\n", filename);

        if (!(file_ext = WCSRCHR(filename, '.')))
		return -ENOENT;

	buf = (uint8_t *)CALLOC(ILITEK_FW_FILE_SIZE, 1);
	if (!buf)
		return -ENOMEM;

	/* no need to read .ili file */
	if (!fw->cb.read_fw) {
		error = -EFAULT;
		TP_ERR(NULL, "read fw callback not registered\n");
		goto err_free;
	}

	size = fw->cb.read_fw(filename, buf, ILITEK_FW_FILE_SIZE,
			      fw->_private);

	if ((error = size) < 0) {
		TP_ERR(NULL, "read fw file: " PFMT_C16 " failed, err: %d\n",
			filename, error);
		goto err_free;
	}

	if (!WCSCASECMP(file_ext, ".hex")) {
		fw->file.type = fw_hex;
		error = decode_hex(fw, buf, 0, size, fw->file.buf,
				   fw->file.buf_size);
	} else if (!WCSCASECMP(file_ext, ".bin")) {
		fw->file.type = fw_bin;
		error = decode_bin(fw, buf, size, fw->file.buf,
				   fw->file.buf_size);
	} else {
		error = -EINVAL;
	}

err_free:
	CFREE(buf);

	return error;
} 

static bool need_fw_update_v6(struct ilitek_fw_handle *fw)
{
	struct ilitek_ts_device *dev = fw->dev;
	uint8_t i;
	bool need = false;

	TP_INFO(dev->id, "------------Lego Block Info.------------\n");

	for (i = 0; i < fw->file.block_num; i++) {
		dev->ic[0].crc[i] = api_get_block_crc_by_addr(dev,
			CRC_CALCULATE, fw->file.blocks[i].start,
			fw->file.blocks[i].end);
	}

	for (i = 0; i < fw->file.block_num; i++) {
		fw->file.blocks[i].check_match = (fw->setting.force_update) ?
			false : (dev->ic[0].crc[i] == fw->file.blocks[i].check);

		need = (!fw->file.blocks[i].check_match) ? true : need;

		TP_INFO(dev->id, "Block[" PFMT_U8 "]: Start/End Addr.: 0x%x/0x%x, IC/File CRC: 0x%x/0x%x " PFMT_C8 "\n",
			i, fw->file.blocks[i].start, fw->file.blocks[i].end,
			dev->ic[0].crc[i], fw->file.blocks[i].check,
			(fw->file.blocks[i].check_match) ?
			"matched" : "not matched");
	}

	/* check BL mode firstly before AP-cmd related varaible, ex: ic_num */
	if (dev->ic[0].mode == BL_MODE)
		need = true;
 
	TP_INFO(dev->id, "----------------------------------------\n");

	return need;
}

static bool need_fw_update(struct ilitek_fw_handle *fw)
{
	struct ilitek_ts_device *dev = fw->dev;
	bool need = false;

	struct ilitek_fw_settings *set = &fw->setting;
	uint64_t dev_fw_ver, file_fw_ver;

	 need = need_fw_update_v6(fw);
 
	if (set->force_update)
		return true; 

	if (set->fw_ver_check && dev->ic[0].mode == AP_MODE) {
		TP_INFO(dev->id, "IC FW version: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
			dev->fw_ver[0], dev->fw_ver[1], dev->fw_ver[2],
			dev->fw_ver[3], dev->fw_ver[4], dev->fw_ver[5],
			dev->fw_ver[6], dev->fw_ver[7]);
		TP_INFO(dev->id, "File FW version: %02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x\n",
			set->fw_ver[0], set->fw_ver[1],
			set->fw_ver[2], set->fw_ver[3],
			set->fw_ver[4], set->fw_ver[5],
			set->fw_ver[6], set->fw_ver[7]);

		dev_fw_ver =
			U82U64(dev->fw_ver[0], 7) + U82U64(dev->fw_ver[1], 6) +
			U82U64(dev->fw_ver[2], 5) + U82U64(dev->fw_ver[3], 4) +
			U82U64(dev->fw_ver[4], 3) + U82U64(dev->fw_ver[5], 2) +
			U82U64(dev->fw_ver[6], 1) + U82U64(dev->fw_ver[7], 0);
		file_fw_ver =
			U82U64(set->fw_ver[0], 7) + U82U64(set->fw_ver[1], 6) +
			U82U64(set->fw_ver[2], 5) + U82U64(set->fw_ver[3], 4) +
			U82U64(set->fw_ver[4], 3) + U82U64(set->fw_ver[5], 2) +
			U82U64(set->fw_ver[6], 1) + U82U64(set->fw_ver[7], 0);

		TP_MSG(dev->id, "IC fw ver: 0x" PFMT_X64 ", File fw ver: 0x" PFMT_X64 "\n",
			(long long unsigned int)dev_fw_ver,
			(long long unsigned int)file_fw_ver);

		if (file_fw_ver > dev_fw_ver) {
			TP_INFO(dev->id, "IC FW version is older than File FW version\n");
			return true;
		} else if (file_fw_ver == dev_fw_ver) {
			TP_INFO(dev->id, "File FW version is the same, " PFMT_C8 " to update\n",
				(set->fw_ver_policy & allow_fw_ver_same) ?
				"still need" : "no need");
			return (set->fw_ver_policy & allow_fw_ver_same) ?
				need : false;
		} else {
			TP_INFO(dev->id, "File FW version is older, " PFMT_C8 " to update\n",
				(set->fw_ver_policy & allow_fw_ver_downgrade) ?
				"still need" : "no need");
			return (set->fw_ver_policy & allow_fw_ver_downgrade) ?
				need : false;
		}
	}

	return need;
}

static int update_master(struct ilitek_fw_handle *fw, int idx, uint32_t len)
{
	int error = 0;
	struct ilitek_ts_device *dev = fw->dev;
	unsigned int i;
	uint16_t file_crc;
	int retry = 3;

	TP_MSG(dev->id, "updating block[%d], data len: %u, start/end addr: 0x%x/0x%x\n",
		idx, len, fw->file.blocks[idx].start, fw->file.blocks[idx].end);

err_retry:
	if (retry-- < 0)
		return (error < 0) ? error : -EINVAL;

	if ((error = api_write_enable_v6(dev, false, false,
					 fw->file.blocks[idx].start,
					 fw->file.blocks[idx].end)) < 0)
		return error;

	_memset(dev->wbuf, 0xff, sizeof(dev->wbuf));
	for (i = fw->file.blocks[idx].start;
	     i < fw->file.blocks[idx].end; i += len) {
		/*
		 * check end addr. of data write buffer is within valid range.
		 */
		if (i + len > END_ADDR_LEGO) {
			TP_ERR(dev->id, "block[%d] write addr. 0x%x + 0x%x > 0x%x OOB\n",
				idx, i, len, END_ADDR_LEGO);
			return -EINVAL;
		}

		_memcpy(dev->wbuf + 1, fw->file.buf + i, len);
		error = api_write_data_v6(dev, len + 1);

		if (error < 0)
			goto err_retry;

		fw->progress_curr = MIN(i + len - fw->file.blocks[idx].offset,
					fw->progress_max);
		fw->progress = (100 * fw->progress_curr) / fw->progress_max;
		TP_DBG(dev->id, "block[%d] update progress: " PFMT_U8 "%%\n",
			idx, fw->progress);

		if (fw->cb.update_progress)
			fw->cb.update_progress(fw->progress, fw->_private);
	}

	file_crc = get_crc(fw->file.blocks[idx].start,
			   fw->file.blocks[idx].end - 1,
			   fw->file.buf, fw->file.buf_size);
	dev->ic[0].crc[idx] =
		api_get_block_crc_by_addr(dev, CRC_GET,
					  fw->file.blocks[idx].start,
					  fw->file.blocks[idx].end);

	TP_INFO(dev->id, "block[%d]: start/end addr.: 0x%x/0x%x, ic/file crc: 0x%x/0x%x " PFMT_C8 "\n",
		idx, fw->file.blocks[idx].start, fw->file.blocks[idx].end,
		dev->ic[0].crc[idx], file_crc,
		(file_crc == dev->ic[0].crc[idx]) ? "matched" : "not matched");

	if (file_crc != dev->ic[0].crc[idx]) {
		error = -EINVAL;
		goto err_retry;
	}

	return 0;
}
 
static int ilitek_update_BL_v1_8(struct ilitek_fw_handle *fw)
{
	int error;
	struct ilitek_ts_device *dev = fw->dev;
	uint8_t i;

	if ((error = api_set_data_len(dev, fw->update_len)) < 0)
		return error;

	for (i = 0; i < fw->file.block_num; i++) {
		if (fw->file.blocks[i].check_match)
			continue;

		if ((error = update_master(fw, i, fw->update_len)) < 0) {
			TP_ERR(dev->id, "Upgrade Block:" PFMT_U8 " failed, err: %d\n",
				i, error);
			return error;
		}
	}

	if ((error = api_to_bl_mode(dev, false, fw->file.blocks[0].start,
		fw->file.blocks[0].end)) < 0)
		return error;

	return 0;
} 

static void update_progress(struct ilitek_fw_handle *fw)
{
	struct ilitek_ts_device *dev = fw->dev;
	uint8_t i;
	unsigned int last_end = 0, last_offset = 0;

	fw->progress = 0;
	fw->progress_max = 0;
	fw->progress_curr = 0;

	switch (dev->protocol.flag) { 
	case PTL_V6:
		for (i = 0; i < fw->file.block_num; i++) {
			if (fw->file.blocks[i].check_match)
				continue;

			fw->progress_max +=
				fw->file.blocks[i].end -
				fw->file.blocks[i].start;
			last_offset += fw->file.blocks[i].start - last_end;
			fw->file.blocks[i].offset = last_offset;

			last_end = fw->file.blocks[i].end;
		} 

		break;
	}
}

void *ilitek_update_init(void *_dev, bool need_update_ts_info,
			 struct ilitek_update_callback *cb, void *_private)
{
	struct ilitek_fw_handle *fw;
	struct ilitek_ts_device *dev = (struct ilitek_ts_device *)_dev;

	if (need_update_ts_info && dev && api_update_ts_info(dev) < 0)
		return NULL;

	fw = (struct ilitek_fw_handle *)MALLOC(sizeof(*fw));
	if (!fw)
		return NULL;

	/* initial all member to 0/ false/ NULL */
	_memset(fw, 0, sizeof(*fw));
	fw->dev = (dev) ? dev : NULL;

	/* initial update-len to default UPDATE_LEN */
	fw->update_len = UPDATE_LEN;

	fw->dev = dev;
	fw->_private = _private;
	fw->file.buf_size = ILITEK_FW_BUF_SIZE;
	fw->file.buf = (uint8_t *)CALLOC(fw->file.buf_size, 1);
	if (!fw->file.buf)
		goto err_free_fw; 

	if (cb)
		_memcpy(&fw->cb, cb, sizeof(*cb));

	return fw;
 
err_free_fw:
	FREE(fw);

	return NULL;
}

void ilitek_update_exit(void *handle)
{
	struct ilitek_fw_handle *fw = (struct ilitek_fw_handle *)handle;

	if (!handle)
		return;

	if (fw->file.buf)
		CFREE(fw->file.buf); 

	if (fw)
		FREE(fw);
}

void ilitek_update_set_data_length(void *handle, uint16_t len)
{
	struct ilitek_fw_handle *fw = (struct ilitek_fw_handle *)handle;

	if (!fw)
		return;

	fw->update_len = len;
}

int ilitek_update_load_fw(void *handle, WCHAR *fw_name)
{
	int error;
	struct ilitek_fw_handle *fw = (struct ilitek_fw_handle *)handle;

	uint32_t i;

	if (!handle)
		return -EINVAL;

	if ((error = decode_firmware(fw, fw_name)) < 0)
		return error; 

	/* for Lego and V6 IC, check block's start/end address validity */ 
	for (i = 0; i < fw->file.block_num; i++) {
		if (fw->dev->mcu_info.min_addr <=
			fw->file.blocks[i].start &&
		    fw->dev->mcu_info.max_addr >
			fw->file.blocks[i].end)
			continue;

		if (!(fw->file.blocks[i].start % 0x1000))
			continue;

		TP_ERR(fw->dev->id, "Block[%u] addr. OOB (0x%x <= 0x%x/0x%x < 0x%x) or invalid start addr\n",
			i, fw->dev->mcu_info.min_addr,
			fw->file.blocks[i].start,
			fw->file.blocks[i].end,
			fw->dev->mcu_info.max_addr);
		return -EINVAL;
	}
 
	TP_MSG(fw->dev->id, "IC: " PFMT_C8 ", Firmware File: " PFMT_C8 " matched\n",
		fw->dev->mcu_info.ic_name, fw->file.ic_name);

	return 0;
}

int ilitek_update_start(void *handle)
{
	int error;
	int8_t retry = 0;
	struct ilitek_fw_handle *fw = (struct ilitek_fw_handle *)handle;
	struct ilitek_ts_device *dev;

	if (!handle)
		return -EINVAL;
	dev = fw->dev;

	/*
	 * Some platform (ITS-Bridge) might change touch controller
	 * after loading fw file, get panel info. forcely and
	 * re-check the ic/file are matched.
	 */
	if ((error = api_update_ts_info(dev)) < 0 ||
	    strcmp(dev->mcu_info.ic_name, fw->file.ic_name)) {
		TP_ERR(fw->dev->id, "get ic info failed, err: %d or ic/file (" PFMT_C8 "/" PFMT_C8 ") not matched\n",
			error, fw->dev->mcu_info.ic_name, fw->file.ic_name);
		return -EPERM;
	}

	TP_INFO(dev->id, "[ilitek_update_start] start\n");

	do {
		TP_DBG(dev->id, "retry: %hhd, retry_limit: %hhd\n",
			retry, fw->setting.retry);
		if (retry)
			reset_helper(dev);

		if ((error = api_set_ctrl_mode(dev, mode_suspend, false, true)) < 0)
			continue;

		if (!need_fw_update(fw)) 
			goto success_return; 

		update_progress(fw);
		if (fw->cb.update_progress)
			fw->cb.update_progress(0, fw->_private);

		if ((error = api_to_bl_mode(dev, true, 0, 0)) < 0)
			continue;

		TP_INFO_ARR(dev->id, "[BL Firmware Version]",
			    TYPE_U8, 8, dev->fw_ver);
		TP_INFO(dev->id, "[ilitek_update_start] start to program\n");

		switch (dev->protocol.ver & 0xFFFF00) {
		case BL_PROTOCOL_V1_8:
			error = ilitek_update_BL_v1_8(fw);
			break; 
		default:
			TP_ERR(dev->id, "BL protocol ver: 0x%x not supported\n",
				dev->protocol.ver);
			continue;
		}
		if (error < 0)
			continue;

		if ((error = api_to_bl_mode(dev, false,
					    fw->file.blocks[0].start,
					    fw->file.blocks[0].end)) < 0)
			continue; 

success_return:
		if ((error = api_update_ts_info(dev)) < 0)
			continue;

		if ((error = api_set_ctrl_mode(dev, mode_normal, false, true)) < 0)
			continue; 

		if (fw->cb.update_progress)
			fw->cb.update_progress(100, fw->_private); 

		TP_INFO(dev->id, "[ilitek_update_start] success\n");

		return 0;
	} while (++retry < fw->setting.retry);

	TP_ERR(dev->id, "[ilitek_update_start] fw update failed, err: %d\n",
		error);

	return (error < 0) ? error : -EFAULT;
}

void ilitek_update_setting(void *handle, struct ilitek_fw_settings *setting)
{
	struct ilitek_fw_handle *fw = (struct ilitek_fw_handle *)handle;

	if (!handle)
		return;

	_memcpy(&fw->setting, setting, sizeof(struct ilitek_fw_settings));
}

