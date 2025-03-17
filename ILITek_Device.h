/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#ifndef INC_ILITEK_DEVICE_H_
#define INC_ILITEK_DEVICE_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include <dirent.h>
#include <malloc.h>

#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <math.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <libgen.h>

#include <linux/ioctl.h>
#include <linux/input.h>
#include <linux/hid.h>
#include <linux/hiddev.h>
#include <linux/hidraw.h>

#include "API/CommonFlow/ilitek_protocol.h"

#define DAEMON_VERSION	"4.0.0.1"
#define TOOL_VERSION "ILITEK LINUX DAEMON V" DAEMON_VERSION

/*
 * Ugly hack to work around failing compilation on systems that don't
 * yet populate new version of hidraw.h to userspace.
 */
#ifndef HIDIOCSFEATURE
#warning Please have your distro update the userspace kernel headers
#define HIDIOCSFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
#define HIDIOCGFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
#endif

#define ILITEK_VENDOR_ID	0x222A
#define OTHER_VENDOR_ID		0x04E7

#define BYTE_64			64
#define BYTE_256		256
#define BYTE_1K			1024
#define BYTE_2K			2048
#define BYTE_4K			4096

#define REPORT_ID_64_BYTE	0x0203
#define REPORT_ID_256_BYTE	0x0307
#define REPORT_ID_1024_BYTE	0x0308
#define REPORT_ID_2048_BYTE	0x0309
#define REPORT_ID_4096_BYTE	0x030A

#define EDID_SYS_PATH		"/sys/class/drm"
#define EDID_LENGTH		0x80

extern int OTHER_VID;

struct cmd_option {
	int cmd;

	int check_vendor_define;

	bool no_INT_ack;

	int hidraw_id;

	char input_file[1024];
	char output_dir[1024];

	uint16_t update_len;
	uint8_t sensor_id_mask;

	/* FWUpgrade */
	uint8_t progress_type;
};

extern struct cmd_option cmd_opt;

struct edid_block {
	uint8_t  header[8];               // EDID header "00 FF FF FF FF FF FF 00"
	uint16_t manufacturerCode;        // EISA 3-character ID
	uint16_t productCode;             // Vendor assigned code
	uint32_t serialNumber;            // Serial number
	uint8_t  manufacturedWeek;        // Week number
	uint8_t  manufacturedYear;        // Year number + 1990
	uint8_t  version;                 // EDID version
	uint8_t  revision;                // EDID revision
	uint8_t  videoInputDefinition;
	uint8_t  maxHorizontalImageSize;  // in cm
	uint8_t  maxVerticalImageSize;    // in cm
	uint8_t  displayGamma;            // gamma
	uint8_t  dpmSupport;              // DPMS
	uint8_t  redGreenLowBits;         // Rx1 Rx0 Ry1 Ry0 Gx1 Gx0 Gy1Gy0
	uint8_t  blueWhiteLowBits;        // Bx1 Bx0 By1 By0 Wx1 Wx0 Wy1 Wy0
	uint8_t  redX;                    // Red-x Bits 9 - 2
	uint8_t  redY;                    // Red-y Bits 9 - 2
	uint8_t  greenX;                  // Green-x Bits 9 - 2
	uint8_t  greenY;                  // Green-y Bits 9 - 2
	uint8_t  blueX;                   // Blue-x Bits 9 - 2
	uint8_t  blueY;                   // Blue-y Bits 9 - 2
	uint8_t  whiteX;                  // White-x Bits 9 - 2
	uint8_t  whiteY;                  // White-x Bits 9 - 2
	uint8_t  establishedTimings[3];
	uint8_t  standardTimings[16];
	uint8_t  descriptionBlock1[18];
	uint8_t  descriptionBlock2[18];
	uint8_t  descriptionBlock3[18];
	uint8_t  descriptionBlock4[18];
	uint8_t  extensions;              // Number of (optional) 128-byte EDID extension blocks
	uint8_t  checksum;
} __attribute__((packed));

extern struct ilitek_ts_callback dev_cb;
extern struct ilitek_ts_device *dev;
extern struct ilitek_ts_settings dev_set;

extern int TransferData_HID(uint8_t *OutBuff, int writelen, uint8_t *InBuff, int readlen, int timeout_ms);
extern int TransferData(uint8_t *OutBuff, int writelen, uint8_t *InBuff, int readlen, int timeout_ms);
//----------------------------------------------------------------

extern int InitDevice();
extern void CloseDevice();

extern int viWaitAck(uint8_t cmd, uint8_t *buf, int timeout_ms,
		     bool check_validity);
extern int hidraw_read(int fd, uint8_t *buf, int len, int timeout_ms,
		       uint8_t cmd, bool check_validity, bool check_ack);
extern void init_INT();
extern int wait_INT(uint32_t timeout_ms);

extern FILE *log_openfile(char *log_dirname, char *prefix);
extern void log_closefile(FILE *file);

extern int get_edid(struct edid_block *edid);

extern void progress_bar(uint8_t percentage);

#endif
