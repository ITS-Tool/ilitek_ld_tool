/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#ifndef INC_ILITEK_MAIN_H_
#define INC_ILITEK_MAIN_H_
#include <stdint.h>
#include <stdbool.h>

#define COMMAND_LIST							\
	X(Chrome, 	1,  "(CHROMEOS-ONLY) Get FW ver. only")		\
	X(PanelInfor,	4,  "Get all ILITEK TP Info.")			\
	X(FWUpgrade,	7,  "FW Update to specific fw file")

#define COMMON_OPTIONS											\
	X(version,		version,		no, 0, 'v',					\
	  "Show tool version", "")									\
	X(edid,			edid,			no, 0, enum_edid,				\
	  "Show EDID info.", "")									\
	X(help,			help,			no, 0, 'h',					\
	  "Show help message", "")									\
	X(log,			log,			no, 0, enum_log,				\
	  "Enable saving daemon execution log", "")							\
	X(err,			err,			no, 0, enum_err,				\
	  "Change log level to error level", "")							\
	X(dbg,			dbg,			no, 0, enum_dbg,				\
	  "Change log level to debug level", "")							\
	X(pkt,			pkt,			no, 0, enum_pkt,				\
	  "Change log level to the lowest-level", "")							\
	X(none,			none,			no, 0, enum_none,				\
	  "Stop showing any log", "")									\
	X(input-file,		input_file,		required, 0, 'i',				\
	  "Set input file path of FW or Profile", "=%s")						\
	X(output-dir,		output_dir,		required, 0, 'o',				\
	  "Save log to specific folder", "=%s")								\
	X(check-vendor-define,	check_vendor_define,	no, &cmd_opt.check_vendor_define, 1,		\
	  "(HIDRAW-ONLY) Focus on specific vendor-defined hidraw", "")					\
	X(hidraw,		hidraw,			optional, 0, enum_hidraw,			\
	  "(HID-ONLY) Use hidraw [w/ specific hidraw number]", "[=%d]")					\
	X(vid,			vid,			required, 0, enum_vid,				\
	  "(HID-ONLY) Add specific VID (default 0x222A)", "=%x")					\
	X(INT-ack,		INT_ack,		required, 0, enum_INT_ack,			\
	  "(I2C-ONLY) Enable/Disable INT ack check (default enabled)", "=n/y")				\
	X(sensor-id-mask,	sensor_id_mask,		required, 0, enum_sensor_id_mask,		\
	  "Set sensor-id-mask", "=%hhx")								\
	X(update-len,		update_len,		required, 0, enum_update_len,			\
	  "Set FW update packet length", "=%hu")							\
	X(progress,		progress,		required, 0, enum_progress,			\
	  "Set type of progress display (default \"bar\")", "=bar/text")

#define UPGRADE_OPTIONS							\
	X(force-upgrade, force_upgrade, no,	  0, enum_force_upgrade,\
	  "Enable force upgrade option", "")				\
	X(fw-ver,	 fw_ver,	required, 0, enum_fw_ver,	\
	  "Compare FW version before upgrade", "=%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx")

#define TOOL_OPTIONS		\
	COMMON_OPTIONS		\
	UPGRADE_OPTIONS

#endif
