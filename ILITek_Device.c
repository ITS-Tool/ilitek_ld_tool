/*
 * Copyright (c) 2019 ILI Technology Corp.
 *
 * This file is part of ILITEK Linux Daemon Tool
 *
 * Copyright (c) 2021 Luca Hsu <luca_hsu@ilitek.com>
 * Copyright (c) 2021 Joe Hung <joe_hung@ilitek.com>
 */
#include "ILITek_Device.h"
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>

struct ilitek_ts_device *dev;
struct ilitek_ts_settings dev_set;


int ILITEK_PID = 0x0,ILITEK_VID = 0x0, OTHER_VID =0x0;

int fd;

bool has_vendor_define(uint8_t *src, unsigned int src_size,
			 uint8_t *tag, unsigned int tag_size)
{
	unsigned int i = 0, j = 0;

	for (i = 0; i < src_size - tag_size; i++) {
		if (src[i] == tag[j]) {
			if (++j == tag_size) {
				TP_MSG(NULL, "vendor define is found...\n");
				return true;
			}
			continue;
		}

		j = 0;
	}

	return false;
}

int open_hidraw_device(uint32_t bus_type, unsigned long timeout_ms)
{
	struct hidraw_devinfo dev_info;
	DIR *dir = NULL;
	struct dirent *ptr;
	char hidraw_path[512];
	int hidraw_id;
	int desc_size;
	struct hidraw_report_descriptor report_desc;

	uint8_t vendor_define[] = {0x9, 0x1, 0x85, 0x3};

	uint32_t t_init, t_diff;

	get_time_ms(&t_init);

	do {

		dir = opendir("/dev");
		if (!dir) {
			TP_ERR(NULL, "can't open \"/dev\" directory\n");
			return -ENOENT;
		}

		while ((ptr = readdir(dir))) {
			/* filter out non-character device */
			if (ptr->d_type != DT_CHR ||
			    strncmp(ptr->d_name, "hidraw", 6))
				continue;

			sscanf(ptr->d_name, "hidraw%d", &hidraw_id);
			if (cmd_opt.hidraw_id >= 0 &&
			    cmd_opt.hidraw_id != hidraw_id)
				continue;

			memset(hidraw_path, 0, sizeof(hidraw_path));
			snprintf(hidraw_path, sizeof(hidraw_path),
				 "/dev/%s", ptr->d_name);

			fd = open(hidraw_path, O_RDWR | O_NONBLOCK);
			if (fd < 0) {
				TP_ERR(NULL, "can't open %s, fd: %d, err: %d\n",
					hidraw_path, fd, errno);
				continue;
			}

			if (cmd_opt.check_vendor_define) {
				ioctl(fd, HIDIOCGRDESCSIZE, &desc_size);
				TP_DBG(NULL, "[%s] fd: %d, desc size: %d\n",
					ptr->d_name, fd, desc_size);

				memset(&report_desc, 0, sizeof(report_desc));
				report_desc.size = desc_size;

				ioctl(fd, HIDIOCGRDESC, &report_desc);
				TP_MSG_ARR(NULL, "[rpt_desc]:", TYPE_U8,
					   report_desc.size, report_desc.value);

				if (!has_vendor_define(report_desc.value, report_desc.size,
						       vendor_define, sizeof(vendor_define)))
					goto err_continue;
			}

			ioctl(fd, HIDIOCGRAWINFO, &dev_info);
			if ((dev_info.vendor != ILITEK_VENDOR_ID &&
			     dev_info.vendor != OTHER_VID)) {
				TP_DBG(NULL, "Invalid vendor id: %x, should be %x or %x\n",
					dev_info.vendor, ILITEK_VENDOR_ID, OTHER_VID);
				goto err_continue;
			}

			if (dev_info.bustype != bus_type) {
				TP_DBG(NULL, "invalid bus type: %u, should be %u\n",
					dev_info.bustype, bus_type);
				goto err_continue;
			}

			TP_MSG(NULL, "bustype: %u, path: %s, vid: %#x, pid: %#x\n",
				dev_info.bustype, hidraw_path,
				dev_info.vendor, dev_info.product);

			/*
			 * hidraw may be changed after FW reset or re-enumerate
			 */
			cmd_opt.hidraw_id = -1;

			closedir(dir);
			return 0;

err_continue:
			close(fd);
		}

		closedir(dir);

		get_time_ms(&t_diff);
		t_diff = t_diff - t_init;

	} while ((!timeout_ms || t_diff < timeout_ms));


	TP_WARN(NULL, "No ilitek hidraw file node found!\n");

	return -ENODEV;
}

int InitDevice()
{
	return open_hidraw_device(BUS_I2C, 5000);
}

int hidraw_read(int fd, uint8_t *buf, int len, int timeout_ms,
		uint8_t cmd, bool check_validity, bool check_ack)
{
	int ret = 0, t_ms = 0;

	if (!buf)
		return -EINVAL;

	do {
		ret = read(fd, buf, len);

		if ((!check_validity && ret > 0) || (ret == len &&
		     ((buf[0] == 0x03 && buf[1] == 0xA3 && buf[2] == cmd) ||
		      buf[0] == 0xAA))) {
		      if ((check_ack && buf[4] == 0xAC) || !check_ack)
				return ret;
		}

		usleep(1000);
		t_ms += 1;
	} while (t_ms < timeout_ms);

	return -ETIME;
}

unsigned int getLength(unsigned int len, unsigned int *reportID)
{
	if (len <= BYTE_64) {
		*reportID = REPORT_ID_64_BYTE;
		return BYTE_64;
	} else if (len <= BYTE_256) {
		*reportID = REPORT_ID_256_BYTE;
		return BYTE_256 + 1 + 6;
	} else if (len <= BYTE_1K + 1) {
		*reportID = REPORT_ID_1024_BYTE;
		return BYTE_1K + 1 + 6;
	} else if (len <= BYTE_2K + 1) {
		*reportID = REPORT_ID_2048_BYTE;
		return BYTE_2K + 1 + 6;
	}

	*reportID = REPORT_ID_4096_BYTE;

	return BYTE_4K + 1 + 6;
}

/*
 * TransferData_HID will return HID format packet,
 * no matter which interface is selected.
 *
 * Write/Read length will be modified to aligned power of 2.
 * will return write/read length on success.
 */
int TransferData_HID(uint8_t *OutBuff, int writelen,
		     uint8_t *InBuff, int readlen, int timeout_ms)
{
	int ret = 0;
	unsigned int wlen, rlen;
	unsigned int w_report, r_report;
	uint8_t cmd;
	int __attribute__((unused)) retry = 50;

	wlen = getLength(writelen, &w_report);
	rlen = getLength(readlen, &r_report);

	if (!OutBuff)
		cmd = 0;
	else if (OutBuff[0] == 0x03)
		cmd = OutBuff[4];
	else
		cmd = OutBuff[6];

	if (writelen > 0) {
                TP_PKT_ARR(NULL, "[OutBuff]:", TYPE_U8, wlen, OutBuff);
		ret = ioctl(fd, HIDIOCSFEATURE(wlen), OutBuff);

		if (ret < 0) {
			if (cmd != 0x60) {
				TP_ERR(NULL, "[%s] hidraw write fail, cmd: %#x, ret:%d, wlen:%d\n",
					__func__, cmd, ret, wlen);
			}
			return ret;
		}
	}

	if (readlen > 0) {
		if (r_report == REPORT_ID_64_BYTE) {
			ret = hidraw_read(fd, InBuff, rlen,
					  timeout_ms + 100,
					  cmd, true, false);
		} else {
			/* Must set report id before IOCTL */
			InBuff[0] = r_report & 0xFF;
			ret = ioctl(fd, HIDIOCGFEATURE(rlen), InBuff);
		}

		if (ret < 0) {
			TP_ERR(NULL, "[%s] hidraw Read fail, cmd: %#x, ret:%d\n",
				__func__, cmd, ret);
			return ret;
		}

                TP_PKT_ARR(NULL, "[InBuff]:", TYPE_U8, rlen, InBuff);
	}

	return 0;
}

/*
 * TransferData will make sure write buffer is HID format
 * before enter _TransferData.
 */
int TransferData(uint8_t *OutBuff, int writelen, uint8_t *InBuff,
		 int readlen, int timeout_ms)
{
	int error;
	uint8_t WriteBuff[8192], ReadBuff[8192];
	uint32_t w_report = 0, wlen = 0;
	uint32_t r_report = 0, rlen = 0;

	wlen = getLength(writelen, &w_report);
	rlen = getLength(readlen, &r_report);

	if (writelen > 0 && w_report == REPORT_ID_64_BYTE &&
	    readlen > 0 && r_report != REPORT_ID_64_BYTE) {
		error = TransferData(OutBuff, writelen, NULL, 0, timeout_ms);
		if (error < 0)
			return error;
		return TransferData(NULL, 0, InBuff, readlen, timeout_ms);
	}

	memset(WriteBuff, 0, wlen);
	memset(ReadBuff, 0, rlen);

	if (w_report == REPORT_ID_64_BYTE) {
		WriteBuff[0] = w_report & 0xFF;
		WriteBuff[1] = 0xA3;
		WriteBuff[2] = writelen;
		WriteBuff[3] = readlen;
		memcpy(WriteBuff + 4, OutBuff, writelen);
	} else {
		WriteBuff[0] = w_report & 0xFF;
		WriteBuff[1] = 0xA3;
		WriteBuff[2] = writelen & 0xFF;
		WriteBuff[3] = (writelen >> 8) & 0xFF;
		WriteBuff[4] = readlen & 0xFF;
		WriteBuff[5] = (readlen >> 8) & 0xFF;
		memcpy(WriteBuff + 6, OutBuff, writelen);
	}

	error = TransferData_HID(WriteBuff, writelen,
				 ReadBuff, readlen, timeout_ms);

	if (r_report == REPORT_ID_64_BYTE)
		memcpy(InBuff, ReadBuff + 4, readlen);
	else
		memcpy(InBuff, ReadBuff, rlen);

	if (error < 0) {
		if (!OutBuff || OutBuff[0] != 0x60)
			return error;
	}

	return 0;
}

void CloseDevice()
{
	close(fd);
}

/* Default wait ack timeout should be 1500000 us */
int viWaitAck(uint8_t cmd, uint8_t *buf, int timeout_ms, bool check_validity)
{
	int error;

	error = hidraw_read(fd, buf, 64, timeout_ms, cmd, check_validity, true);
	if (error < 0) {
		TP_ERR(NULL, "timeout_ms: %d, cmd: %x, err: %d\n",
			timeout_ms, cmd, error);
		return error;
	}

	return 0;
}

FILE *log_openfile(char *log_dir, char *prefix)
{
	FILE *file;

	time_t rawtime;
	struct tm *timeinfo;
	char timebuf[60], filename[512];

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 60, "%Y%m%d_%I%M%S", timeinfo);

	if (strlen(log_dir) && access(log_dir, 0) < 0) {
		if (mkdir(log_dir, 0777)) {
			TP_ERR(NULL, "create directory %s failed!\n", log_dir);
			return NULL;
		}
	}

	if (strlen(log_dir))
		sprintf(filename, "%s/%s_%s.txt", log_dir, prefix, timebuf);
	else
		sprintf(filename, "./%s_%s.txt", prefix, timebuf);

	file = fopen(filename, "w");

	TP_MSG(NULL, "*******************************************\n");
	TP_MSG(NULL, "************** Start Logging **************\n");
	TP_MSG(NULL, "*******************************************\n\n");

	return file;
}

void log_closefile(FILE *file)
{
	if (!file)
		return;

	TP_MSG(NULL, "\n");
	TP_MSG(NULL, "*******************************************\n");
	TP_MSG(NULL, "************** End of Logging *************\n");
	TP_MSG(NULL, "*******************************************\n");
	fclose(file);
}

bool check_edid(const char *dirpath)
{
	int fd;
	char filename[512];
	char buf[128];

	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s/%s", dirpath, "status");

	if (access(filename, F_OK))
		return false;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return false;

	if (read(fd, buf, sizeof(buf) - 1) < 0) {
		close(fd);
		return false;
	}

	close(fd);

	return !strncmp("connected", buf, 9) ? true : false;
}

int read_edid(const char *dirpath, struct edid_block *edid)
{
	FILE *file;
	char filename[512];
	int error;

	memset(filename, 0, sizeof(filename));
	sprintf(filename, "%s/%s", dirpath, "edid");

	file = fopen(filename, "rb");
	if (!file)
		return -ENOENT;

	error = fread(edid, sizeof(uint8_t), EDID_LENGTH, file);
	if (error != EDID_LENGTH) {
		TP_WARN(NULL, "unexpected edid len, get: %d, expected: %d\n",
			error, EDID_LENGTH);
		fclose(file);
		return -EINVAL;
	}

	fclose(file);

	TP_DBG_ARR(NULL, "[EDID]:", TYPE_U8, EDID_LENGTH, edid);
	TP_MSG(NULL, "Manufacturer: %#x\n", edid->manufacturerCode);
	TP_MSG(NULL, "Product Code: %#x\n", edid->productCode);
	TP_MSG(NULL, "Serial Number: %#x\n", edid->serialNumber);
	TP_MSG(NULL, "Week Number: %d\n", edid->manufacturedWeek);
	TP_MSG(NULL, "Year Number: %d\n", edid->manufacturedYear + 1990);
	TP_MSG(NULL, "EDID Ver.: %#x\n", edid->version);
	TP_MSG(NULL, "EDID Rev.: %#x\n", edid->revision);
	TP_MSG(NULL, "Horizon Screen Size: %d cm\n",
		edid->maxHorizontalImageSize);
	TP_MSG(NULL, "Vertical Screen Size: %d cm\n",
		edid->maxVerticalImageSize);

	TP_MSG(NULL, "edid-tag: [%04x-%04x]\n",
		edid->manufacturerCode, edid->productCode);

	return 0;
}

int get_edid(struct edid_block *edid)
{
	char fpath[512];
	DIR *dir;
	struct dirent *entry;

	if (!(dir = opendir(EDID_SYS_PATH)))
		return -ENOENT;

	while ((entry = readdir(dir))) {
		memset(fpath, 0, sizeof(fpath));
		sprintf(fpath, "%s/%s", EDID_SYS_PATH, entry->d_name);

		if (!check_edid(fpath))
			continue;

		TP_DBG(NULL, "path: %s edid connected\n", fpath);

		if (read_edid(fpath, edid) < 0)
			continue;

		return 0;
	}

	return -ENOENT;
}

static int _write_then_read(uint8_t *wbuf, int wlen, uint8_t *rbuf, int rlen, void *data)
{
	UNUSED(data);

	return TransferData(wbuf, wlen, rbuf, rlen, 1000);
}

static void init_ack(unsigned int tout_ms, void *data)
{
	UNUSED(tout_ms);
	UNUSED(data);
}

static int wait_ack(uint8_t cmd, unsigned int tout_ms, void *data)
{
	uint8_t buf[64];

        UNUSED(data);

	return viWaitAck(cmd, buf, tout_ms, true);
}

static void delay_ms(unsigned int time_ms)
{
	usleep(time_ms * 1000);
}

struct ilitek_ts_callback dev_cb = {
	/* .write_then_read = */ _write_then_read,
	/* .init_ack = */ init_ack,
	/* .wait_ack = */ wait_ack,
	/* .hw_reset = */ NULL,
	/* .re_enum = */ NULL,
	/* .delay_ms = */ delay_ms,
	/* .msg = */ NULL,

	/* .mode_switch_notify = */ NULL,
};

void progress_bar(uint8_t percentage)
{
	uint8_t i, max = 50;

	if (cmd_opt.progress_type) {
		TP_MSG(NULL, "progress: %hhu%%\n", percentage);
		return;
	}

	printf("\033[s\033[H\033[K\033[1;33m%3d%% [", percentage);
	for (i = 0; i < percentage / 2; i++)
		printf("#");
	for (; i < max; i++)
		printf(".");
	printf("]\033[m\033[u");

	fflush(stdout);
}

