/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#ifndef _ILITEK_MAIN_C_
#define _ILITEK_MAIN_C_

#include "ILITek_Device.h"
#include "ILITek_Main.h"
#include "API/ILITek_Upgrade.h"
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <sys/file.h>
#include <sys/shm.h>
#include <sys/ipc.h>

#include <getopt.h>

struct cmd_option cmd_opt;

int Func_Chrome()
{
	int error;

	dev->protocol.flag = PTL_V6;
	if ((error = api_set_ctrl_mode(dev, mode_suspend, false, false)) < 0 ||
            (error = api_protocol_set_cmd(dev, GET_FW_VER, NULL)) < 0 ||
            (error = api_set_ctrl_mode(dev, mode_normal, false, false)) < 0)
		return error;

	/*
	 * Chromebook script used, please don't modify string format.
	 */
	TP_MSG(NULL, "fw-version-tag: [%02X%02X.%02X%02X.%02X%02X.%02X%02X]\n",
		dev->fw_ver[0], dev->fw_ver[1], dev->fw_ver[2], dev->fw_ver[3],
		dev->fw_ver[4], dev->fw_ver[5], dev->fw_ver[6], dev->fw_ver[7]);

	return 0;
}

int get_fwid_by_lookup(char *fwid_map_file, uint16_t *fwid)
{
	int error;
	FILE *fp;
	char line[1024], *line_ptr;
	struct edid_block edid;
	char tag[64];
	bool skip_first_line = false;

	char *file_edid = NULL;
	char *file_fwid = NULL;
	char *file_sensor_id = NULL;

        uint8_t sensor_id, sensor_id_mask;

	memset(&edid, 0, sizeof(struct edid_block));
	if ((error = get_edid(&edid)) < 0)
		return error;

	memset(tag, 0, sizeof(tag));
	sprintf(tag, "%04x-%04x", edid.manufacturerCode, edid.productCode);

	TP_DBG(NULL, "find %s in fwid map file: %s\n", tag, fwid_map_file);

	if (!(fp = fopen(fwid_map_file, "r"))) {
		TP_ERR(NULL, "Invalid fwid map file: %s\n", fwid_map_file);
		return -EINVAL;
	}

	while (!feof(fp)) {
		if (!fgets(line, sizeof(line), fp))
			continue;
		line_ptr = line;

		/* skip the first line */
		if (!skip_first_line) {
			skip_first_line = true;
			continue;
		}

		/* fetch edid string */
		file_edid = strsep(&line_ptr, ",");
                file_fwid = strsep(&line_ptr, ",");
                file_sensor_id = strsep(&line_ptr, ",");

                if (!file_fwid)
                        continue;

		/* lookup table by edid */
		if (file_edid && strcmp(file_edid, tag))
			continue;

                if (file_sensor_id) {
                        sscanf(file_sensor_id, "%02hhx-%02hhx",
                                &sensor_id, &sensor_id_mask);

                        if (sensor_id != (dev->sensor.id & sensor_id_mask))
                                continue;
                }

                TP_DBG(NULL, "fwid: %s was found\n", file_fwid);
                sscanf(file_fwid, "%04hx", fwid);

		fclose(fp);

                return 0;
	}
	fclose(fp);
	TP_ERR(NULL, "No matched fwid found\n");

	return -EFAULT;
}

int Func_PanelInfo()
{
        int error;
	uint16_t fwid;
	char fwid_str[8];

	memset(fwid_str, 0, sizeof(fwid_str));

	if ((error = api_update_ts_info(dev)) < 0)
		return error;

        /*
	 * Get FWID from EDID lookup table first.
	 * If no matched edid string in the table, get FWID from FW secondly.
	 * get FWID from FW should be accessible for both AP and BL mode.
	 */
	do {
		if (!get_fwid_by_lookup(cmd_opt.input_file, &fwid)) {
			sprintf(fwid_str, "%04hx", fwid);
			break;
		}

		if (!is_29xx(dev)) {
			/* return ic name for Lego series */
			strcpy(fwid_str, dev->mcu_info.ic_name);
			break;
		}

		/* return fwid for 29XX series */
		sprintf(fwid_str, "%04hx", dev->fwid);
		break;
	} while (false);

	/*
	 * Chromebook script used, please don't modify string format.
	 */
	TP_MSG(NULL, "fw-version-tag: [%02X%02X.%02X%02X.%02X%02X.%02X%02X]\n",
		dev->fw_ver[0], dev->fw_ver[1], dev->fw_ver[2], dev->fw_ver[3],
		dev->fw_ver[4], dev->fw_ver[5], dev->fw_ver[6], dev->fw_ver[7]);
	TP_MSG(NULL, "protocol-version-tag: [%02X.%02X]\n",
		(dev->protocol.ver >> 16) & 0xFF,
		(dev->protocol.ver >> 8) & 0xFF);
	TP_MSG(NULL, "fw-mode-tag: [%s]\n", dev->ic[0].mode_str);
	TP_MSG(NULL, "ic-type-tag: [%s]\n", dev->mcu_info.ic_name);
	TP_MSG(NULL, "module-name-tag: [%s]\n", dev->mcu_info.module_name);
        TP_MSG(NULL, "fwid-tag: [%s]\n", fwid_str);

	return 0;
}

int Func_FWUpgrade()
{
	TP_MSG(NULL, "FW filename:%s\n", cmd_opt.input_file);

	return Firmware_Upgrade_Main(cmd_opt.input_file);
}

#define X(_name, _val, _desc) enum_cmd_##_name = _val,
enum cmds_enum {
	enum_cmd_unknown = 0,
	COMMAND_LIST
};
#undef X

#define X(_name, _enum, _arg, _flag, _val, _desc, _opt) enum_##_enum,
enum options_enum {
	enum_sentinel_base = 0xff,
	TOOL_OPTIONS
};
#undef X

void help_message()
{
	uint32_t size;
	struct option_desc *arr;
	uint32_t i;

	struct option_desc {
		const char *tag;
		const char *opt;
		const char *desc;
	};

#define X(_name, _id, _desc)	{ #_name, "", _desc, },
	struct option_desc cmds[] = {
		COMMAND_LIST
	};
#undef X

#define X(_name, _enum, _arg, _flag, _val, _desc, _opt)	\
		{ "--" #_name, _opt, _desc, },
	struct option_desc common_descs[] = {
		COMMON_OPTIONS
	};

	struct option_desc upgrade_descs[] = { UPGRADE_OPTIONS };
#undef X

	switch (cmd_opt.cmd) {
	case enum_cmd_FWUpgrade:
		size = ARRAY_SIZE(upgrade_descs);
		arr = (struct option_desc *)upgrade_descs;
		_TP_MSG("FW Upgrade command options:\n");
		_TP_MSG("\t--input-file=<fw file path %%s>\tAssign fw (.bin or .hex) file path\n");
		break;
	case enum_cmd_PanelInfor:
		_TP_MSG("PanelInfor command options:\n");
		_TP_MSG("\t--input-file=<fwid lookup .csv filepath %%s>\n\n");
		return;
	default:
		size = ARRAY_SIZE(common_descs);
		arr = (struct option_desc *)common_descs;

		_TP_MSG("Command list:\n");
		for (i = 0; i < ARRAY_SIZE(cmds); i++)
			_TP_MSG("\t%-20s%s\n", cmds[i].tag, cmds[i].desc);
		_TP_MSG("\nCommand options:\n");

		break;
	}

	for (i = 0; i < size; i++)
		_TP_MSG("\t%s%s\t%s\n", arr[i].tag, arr[i].opt, arr[i].desc);
}

void check_args(int argc, char *argv[])
{
	time_t now;
	char tm_str[64], filename[2048];
	struct edid_block edid;
	int c, idx;
	uint32_t i;

#define X(_name, _id, _desc)	{ #_name, _id, },
	struct {
		const char *tag;
		int id;
	} cmds[] = {
		COMMAND_LIST
	};
#undef X

#define X(_name, _enum, _arg, _flag, _val, _desc, _opt)		\
 		{ #_name, _arg##_argument, _flag, _val },

	struct option opts[] = {
		TOOL_OPTIONS

		/* sentinel */
		{0, 0, 0, 0}
	};
#undef X

	memset(&cmd_opt, 0, sizeof(cmd_opt));
	memset(&fw.setting, 0, sizeof(fw.setting));

	/* set hidraw id to invalid value as default disabled */
	cmd_opt.hidraw_id = -1;

	cmd_opt.sensor_id_mask = 0xff;
	cmd_opt.update_len = UPDATE_LEN;

	/* parse cmd first */
	for (i = 0; argc > 1 && i < ARRAY_SIZE(cmds); i++) {
		if (strcmp(argv[1], cmds[i].tag))
			continue;
		cmd_opt.cmd = cmds[i].id;
		break;
	}

	/* set optind to 1 to reset getopt() */
	optind = 1;

	while ((c = getopt_long(argc, argv, "vhi:o:", opts, &idx)) != -1) {
		switch (c) {
		case enum_edid: get_edid(&edid); exit(0);

		case enum_log:
			time(&now);
			strftime(tm_str, sizeof(tm_str),
				"%Y%m%d_%I%M%S", localtime(&now));

			sprintf(filename, "%s/ld_log_%s.txt",
				(strlen(cmd_opt.output_dir) ?
				cmd_opt.output_dir : "."), tm_str);

			set_log_fopen(filename);
			break;

		case enum_err: set_log_level(log_level_err); break;
		case enum_dbg: set_log_level(log_level_dbg); break;
		case enum_pkt: set_log_level(log_level_pkt); break;
		case enum_none: set_log_level(log_level_none); break;

		/* Interface-related options */
		case enum_hidraw:
			if (optarg)
				sscanf(optarg, "%d", &cmd_opt.hidraw_id);
			break;
		case enum_vid: sscanf(optarg, "%x", &OTHER_VID); break;
		case enum_INT_ack:
			cmd_opt.no_INT_ack = (!strcmp(optarg, "n")) ?
				true : false;
			break;

		/* Miscs */
		case enum_sensor_id_mask:
			sscanf(optarg, "%hhx", &cmd_opt.sensor_id_mask); break;
		case enum_update_len:
			sscanf(optarg, "%hu", &cmd_opt.update_len); break;
		case enum_progress:
			if (!strcmp(optarg, "text"))
				cmd_opt.progress_type = 1;
			break;

		/* Upgrade */
		case enum_force_upgrade: fw.setting.force_update = true; break; 
		case enum_fw_ver:
			fw.setting.fw_ver_check = true;
			sscanf(optarg,
				"%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx.%hhx",
				fw.setting.fw_ver, fw.setting.fw_ver + 1,
				fw.setting.fw_ver + 2, fw.setting.fw_ver + 3,
				fw.setting.fw_ver + 4, fw.setting.fw_ver + 5,
				fw.setting.fw_ver + 6, fw.setting.fw_ver + 7);
			break;

                /* Miscs */
		case 'v': TP_MSG(NULL, "%s\n", TOOL_VERSION); exit(0);
		case 'i': sscanf(optarg, "%[^\n]s", cmd_opt.input_file); break;
		case 'o':
			sscanf(optarg, "%[^\n]s", cmd_opt.output_dir);
			if (access(cmd_opt.output_dir, 0) < 0 &&
			    mkdir(cmd_opt.output_dir, 0777)) {
				TP_WARN(NULL, "create folder %s failed\n",
					cmd_opt.output_dir);
				memset(cmd_opt.output_dir, 0,
					sizeof(cmd_opt.output_dir));
			}
			break;
		case 'h': help_message(); exit(0);

		case '?':
			if (cmd_opt.cmd)
				break;

			help_message();
			exit(0);
		}
	}
}

int DealWithFunctions()
{
	int error;

	switch (cmd_opt.cmd) {
	case enum_cmd_Chrome: error = Func_Chrome(); break;
	case enum_cmd_PanelInfor: error = Func_PanelInfo(); break;
	case enum_cmd_FWUpgrade: error = Func_FWUpgrade(); break;
	default: return -EINVAL;
	}

	return (error < 0) ? error : 0;
}

int main(int argc, char *argv[])
{
	int error;

	check_args(argc, argv);

	TP_MSG(NULL, "%s\n", TOOL_VERSION);

	if ((error = InitDevice()) < 0)
		goto err_return;

	dev = (struct ilitek_ts_device *)
		ilitek_dev_init((char *)"0", false, &dev_cb, NULL);

	memset(&dev_set, 0, sizeof(dev_set));
	dev_set.no_INT_ack = cmd_opt.no_INT_ack;
	dev_set.sensor_id_mask = cmd_opt.sensor_id_mask;
	ilitek_dev_setting(dev, &dev_set);

	error = DealWithFunctions();

	ilitek_dev_exit(dev);

	CloseDevice();

err_return:
	TP_MSG(NULL, "main ret = %d\n", error);
	set_log_fclose();

	return (error < 0) ? error : 0;
}

#endif
