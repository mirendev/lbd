/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LBD_H
#define _LBD_H

#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/crc32.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/ioctl.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include "lbd_qcow2.h"

#define LBD_NAME		"lbd"
#define LBD_CTL_NAME		"lbd-control"
#define LBD_VERSION		"0.1.0"

#define LBD_BLOCK_SIZE		4096
#define LBD_QUEUE_DEPTH		128

/* Log format constants */
#define LBD_LOG_VERSION		2
#define LBD_LOG_PATH_MAX	256
#define LBD_LOG_MAX_SIZE_DEFAULT  (64ULL * 1024 * 1024)  /* 64 MiB */
#define LBD_LOG_MAX_AGE_DEFAULT   60                      /* seconds */
#define LBD_LOG_BUF_SIZE          (5ULL * 1024 * 1024)    /* 5 MiB */

/* Device states */
enum lbd_state {
	LBD_STATE_UNBOUND = 0,
	LBD_STATE_BOUND,
	LBD_STATE_REMOVING,
};

/* ioctl interface */
#define LBD_CTL_MAGIC		'L'
#define LBD_CTL_ADD		_IOWR(LBD_CTL_MAGIC, 0, struct lbd_ctl_add)
#define LBD_CTL_REMOVE		_IOW(LBD_CTL_MAGIC, 1, struct lbd_ctl_remove)
#define LBD_CTL_INFO		_IOWR(LBD_CTL_MAGIC, 2, struct lbd_ctl_info)

struct lbd_ctl_add {
	char path[LBD_LOG_PATH_MAX];
	char log_dir[LBD_LOG_PATH_MAX];
	char base_path[LBD_LOG_PATH_MAX];  /* empty string = no base */
	__s32 index;		/* out: assigned device index */
	__u64 log_max_size;	/* 0 = default */
	__u32 log_max_age_secs;	/* 0 = default */
};

struct lbd_ctl_remove {
	__s32 index;
};

struct lbd_ctl_info {
	__s32 index;
	__u32 state;
	__u64 size;
	char path[LBD_LOG_PATH_MAX];
};

/*
 * CBOR log key constants (numeric map keys for compactness).
 *
 * Header map(5):  { 1:version, 2:block_size, 3:segment_label,
 *                   4:device_size, 5:backing_path }
 * Write  map(7):  { 1:"W", 2:timestamp_ns, 3:sequence, 4:block,
 *                   5:length, 6:crc32, 7:data_bytes }
 * Trim   map(5):  { 1:"T", 2:timestamp_ns, 3:sequence, 4:block,
 *                   5:length }
 */
#define LBD_CBOR_KEY_HDR_VERSION	1
#define LBD_CBOR_KEY_HDR_BLOCK_SIZE	2
#define LBD_CBOR_KEY_HDR_SEGMENT_LABEL	3
#define LBD_CBOR_KEY_HDR_DEVICE_SIZE	4
#define LBD_CBOR_KEY_HDR_BACKING_PATH	5

#define LBD_CBOR_KEY_OP			1
#define LBD_CBOR_KEY_TIMESTAMP		2
#define LBD_CBOR_KEY_SEQUENCE		3
#define LBD_CBOR_KEY_BLOCK		4
#define LBD_CBOR_KEY_LENGTH		5
#define LBD_CBOR_KEY_CHECKSUM		6
#define LBD_CBOR_KEY_DATA		7

/* Per-request data (embedded in blk-mq PDU) */
struct lbd_cmd {
	struct list_head list_entry;
	int ret;
};

/* Per-device state */
struct lbd_device {
	int index;
	enum lbd_state state;

	struct gendisk *gd;
	struct blk_mq_tag_set tag_set;

	struct file *backing_file;
	struct file *log_file;
	char backing_path[LBD_LOG_PATH_MAX];
	char log_dir[LBD_LOG_PATH_MAX];
	struct path log_dir_path;
	loff_t size;		/* device size in bytes */

	struct workqueue_struct *wq;
	struct work_struct work;
	struct list_head cmd_list;
	spinlock_t cmd_lock;

	/* Log segmentation — all protected by log_mutex */
	struct mutex log_mutex;
	bool log_has_entries;		/* current segment has data entries */
	u64 log_seq;			/* global, never resets */
	char log_segment_label[25];	/* current segment TAI64N label */
	u64 log_max_size;		/* rotation size threshold */
	u32 log_max_age_secs;		/* rotation age threshold */
	struct delayed_work log_rotate_dwork;	/* age timer */
	void *log_buf;			/* write buffer, allocated once */
	size_t log_buf_used;		/* bytes currently in buffer */

	void *lz4_state;		/* LZ4 compression state, allocated once */

	/* qcow2-lz4 backing store */
	bool is_qcow2;
	struct lbd_qcow2 qcow2;

	/* Thin snapshot base layer */
	struct lbd_qcow2_base *base;	/* NULL when no base configured */
	char base_path[LBD_LOG_PATH_MAX];

	/* I/O stats (atomic for lock-free sysfs reads) */
	atomic64_t stat_reads;
	atomic64_t stat_writes;
	atomic64_t stat_trims;
	atomic64_t stat_read_bytes;
	atomic64_t stat_write_bytes;
	atomic64_t stat_trim_bytes;

	/* Allocation stats (qcow2 space reuse) */
	atomic64_t stat_alloc_reused;	/* clusters written in-place or via free list */
	atomic64_t stat_alloc_new;	/* clusters allocated by appending */
	atomic64_t stat_alloc_freed;	/* extents added to the free list */
	atomic64_t stat_compressed;	/* clusters stored compressed */
	atomic64_t stat_uncompressed;	/* clusters stored uncompressed */

	/* Log stats */
	atomic64_t stat_log_rotations;
	ktime_t segment_start_time;
};

/* Kernel version compatibility */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#define LBD_HAS_BLK_MQ_ALLOC_DISK 1
#else
#define LBD_HAS_BLK_MQ_ALLOC_DISK 0
#endif

/*
 * blk_mode_t was introduced in 6.5, replacing fmode_t for block open.
 * Both are unsigned integers so we just use unsigned int directly.
 */

#endif /* _LBD_H */
