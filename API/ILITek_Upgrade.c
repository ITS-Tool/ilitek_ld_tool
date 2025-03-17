/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#ifndef _ILITEK_UPGRADE_C_
#define _ILITEK_UPGRADE_C_

/* Includes of headers ------------------------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "../ILITek_Device.h"
#include "ILITek_Upgrade.h"
#include "../ILITek_Main.h"

struct ilitek_fw_struct fw;

static unsigned int get_file_size(char *filename)
{
	unsigned int size;
	FILE *file = fopen(filename, "r");

	fseek(file, 0, SEEK_END);
	size = ftell(file);
	fclose(file);
	return size;
}

static int read_fw(char *filename, unsigned char *buf, int size, void *data)
{
	int fd, error;
	int file_size;

	UNUSED(data);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		TP_ERR(NULL, "[%s] cannot open %s file\n", __func__, filename);
		return -EFAULT;
	}

	file_size = (int)get_file_size(filename);
	TP_MSG(NULL, "%s file size: %u bytes\n", filename, file_size);

	if (file_size > size) {
		file_size = -EFBIG;
		goto close_file;
	}

	error = read(fd, buf, file_size);
	if (error != (int)file_size) {
		TP_ERR(NULL, "read %s failed, err: %d\n", filename, error);
		file_size = -EFAULT;
		goto close_file;
	}

close_file:
	close(fd);

	return file_size;
}

static void update_progress(unsigned char progress, void *data)
{
	UNUSED(data);

	fw.progress = progress;

	progress_bar(progress);
}

struct ilitek_update_callback update_cb = {
	/* .read_fw = */ read_fw,
	/* .update_progress = */ update_progress,
};

int Firmware_Upgrade_Main(char *filename)
{
	int error;
	struct ilitek_fw_handle *handle;
	uint32_t start_ms, timespan_ms;

	get_time_ms(&start_ms);

	fw.setting.retry = 1;
	handle = (struct ilitek_fw_handle *)ilitek_update_init(dev, true,
							       &update_cb,
							       NULL);
	ilitek_update_set_data_length(handle, cmd_opt.update_len);

	ilitek_update_setting(handle, &fw.setting);

	if ((error = ilitek_update_load_fw(handle, filename)) < 0 ||
	    (error = ilitek_update_start(handle)) < 0)
		goto err_exit;

err_exit:
	ilitek_update_exit(handle);

	get_time_ms(&timespan_ms);
	timespan_ms -= start_ms;

	TP_MSG(NULL, "FW upgrade finished, err: %d, time span: %u ms\n",
		error, timespan_ms);

	return error;
}

#endif

