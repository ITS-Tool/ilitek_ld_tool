/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#ifndef _ILITEK_UPGRADE_H_
#define _ILITEK_UPGRADE_H_

#include "CommonFlow/ilitek_update.h"

struct ilitek_fw_struct {
	struct ilitek_fw_settings setting;
	uint8_t progress;
};

extern struct ilitek_fw_struct fw;

int Firmware_Upgrade_Main(char *filename);


#endif

