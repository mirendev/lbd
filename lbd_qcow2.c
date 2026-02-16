// SPDX-License-Identifier: GPL-2.0
/*
 * LBD qcow2-lz4 backing store
 *
 * Implements a qcow2-inspired format with LZ4-compressed clusters
 * as the backing store for LBD block devices. Data is organized in
 * 64 KiB clusters with two-level (L1/L2) address translation.
 */

#include <linux/blkdev.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/byteorder/generic.h>

#include "lbd.h"
#include "lbd_qcow2.h"
#include "lz4_kcompat.h"

/* Forward declaration for base layer read (used by lbd_qcow2_cl_load) */
static int lbd_qcow2_base_read_cluster(struct lbd_device *dev,
					u64 cluster_index, void *buf);

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static inline u64 lbd_qcow2_lru_tick(struct lbd_qcow2 *q)
{
	return q->lru_tick++;
}

/* Write header's alloc_offset field to disk */
static int lbd_qcow2_write_alloc_offset(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[8];
	loff_t pos = LBD_QCOW2_OFF_ALLOC_OFFSET;
	ssize_t ret;

	_qcow2_put64(buf, 0, q->alloc_offset);
	ret = kernel_write(dev->backing_file, buf, 8, &pos);
	if (ret != 8)
		return ret < 0 ? ret : -EIO;
	return 0;
}

/* Write header's free_list_head field to disk */
static int lbd_qcow2_write_free_list_head(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[8];
	loff_t pos = LBD_QCOW2_OFF_FREE_LIST;
	ssize_t ret;

	_qcow2_put64(buf, 0, q->free_list_head);
	ret = kernel_write(dev->backing_file, buf, 8, &pos);
	if (ret != 8)
		return ret < 0 ? ret : -EIO;
	return 0;
}

/*
 * Compute the on-disk allocation size for an existing L2 entry.
 * Returns 0 on error.
 */
static u64 lbd_qcow2_read_old_alloc_size(struct lbd_device *dev, u64 l2_entry)
{
	struct lbd_qcow2 *q = &dev->qcow2;

	if (l2_entry == 0)
		return 0;

	if (l2_entry & LBD_QCOW2_L2_COMPRESSED) {
		u64 phys = l2_entry & LBD_QCOW2_L2_OFFSET_MASK;
		__be32 comp_size_be;
		u32 comp_size;
		loff_t pos = phys;
		ssize_t ret;

		ret = kernel_read(dev->backing_file, &comp_size_be,
				  sizeof(comp_size_be), &pos);
		if (ret != sizeof(comp_size_be))
			return 0;

		comp_size = be32_to_cpu(comp_size_be);
		return ALIGN(sizeof(__be32) + comp_size, 4096);
	}

	return q->cluster_size;
}

/*
 * Write a tombstone at a physical offset, prepending to the free list.
 * extent_size is the total usable space at that location.
 */
static int lbd_qcow2_free_extent(struct lbd_device *dev, loff_t phys_offset,
				  u64 extent_size)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[16];
	loff_t pos = phys_offset;
	ssize_t ret;

	/* Tombstone marker */
	_qcow2_put32(buf, 0, LBD_QCOW2_FREE_TOMBSTONE);
	/* Extent size */
	_qcow2_put32(buf, 4, (u32)extent_size);
	/* Next free pointer */
	_qcow2_put64(buf, 8, q->free_list_head);

	ret = kernel_write(dev->backing_file, buf, 16, &pos);
	if (ret != 16)
		return ret < 0 ? ret : -EIO;

	q->free_list_head = phys_offset;
	atomic64_inc(&dev->stat_alloc_freed);
	return lbd_qcow2_write_free_list_head(dev);
}

/* ----------------------------------------------------------------
 * Header persistence helpers for new fields
 * ---------------------------------------------------------------- */

static int lbd_qcow2_write_incompat_features(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[8];
	loff_t pos = LBD_QCOW2_OFF_INCOMPAT_FEAT;
	ssize_t ret;

	_qcow2_put64(buf, 0, q->incompatible_features);
	ret = kernel_write(dev->backing_file, buf, 8, &pos);
	if (ret != 8)
		return ret < 0 ? ret : -EIO;
	return 0;
}

static int lbd_qcow2_write_snapshot_header(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[16];
	loff_t pos;
	ssize_t ret;

	/* Write snapshot_table_offset (8 bytes at offset 76) */
	pos = LBD_QCOW2_OFF_SNAPSHOT_TABLE;
	_qcow2_put64(buf, 0, q->snapshot_table_offset);
	ret = kernel_write(dev->backing_file, buf, 8, &pos);
	if (ret != 8)
		return ret < 0 ? ret : -EIO;

	/* Write snapshot_count (4 bytes at offset 84) */
	pos = LBD_QCOW2_OFF_SNAPSHOT_COUNT;
	_qcow2_put32(buf, 0, q->snapshot_count);
	ret = kernel_write(dev->backing_file, buf, 4, &pos);
	if (ret != 4)
		return ret < 0 ? ret : -EIO;

	return 0;
}

static int lbd_qcow2_write_refcount_header(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 buf[8];
	loff_t pos;
	ssize_t ret;

	/* Write refcount_table_offset (8 bytes at offset 64) */
	pos = LBD_QCOW2_OFF_REFCOUNT_TABLE;
	_qcow2_put64(buf, 0, q->refcount_table_offset);
	ret = kernel_write(dev->backing_file, buf, 8, &pos);
	if (ret != 8)
		return ret < 0 ? ret : -EIO;

	/* Write refcount_table_clusters (4 bytes at offset 72) */
	pos = LBD_QCOW2_OFF_REFCOUNT_CLUSTERS;
	_qcow2_put32(buf, 0, q->refcount_table_clusters);
	ret = kernel_write(dev->backing_file, buf, 4, &pos);
	if (ret != 4)
		return ret < 0 ? ret : -EIO;

	return 0;
}

/* ----------------------------------------------------------------
 * Refcount block cache
 * ---------------------------------------------------------------- */

static inline u64 lbd_qcow2_refcount_lru_tick(struct lbd_qcow2 *q)
{
	return q->lru_tick++;  /* shared with L2/cl cache, that's fine */
}

/* Flush a dirty refcount block to disk */
static int lbd_qcow2_refcount_block_flush(struct lbd_device *dev,
					   struct lbd_refcount_cache_entry *e)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u64 block_phys;
	__be16 *disk_block;
	loff_t pos;
	ssize_t ret;
	u32 i;

	if (!e->valid || !e->dirty)
		return 0;

	if (e->block_index >= q->refcount_table_clusters)
		return -EIO;

	block_phys = q->refcount_table[e->block_index];
	if (!block_phys)
		return -EIO;

	disk_block = kvmalloc(q->cluster_size, GFP_NOIO);
	if (!disk_block)
		return -ENOMEM;

	for (i = 0; i < q->refcount_entries_per_block; i++)
		disk_block[i] = cpu_to_be16(e->entries[i]);

	pos = block_phys;
	ret = kernel_write(dev->backing_file, disk_block, q->cluster_size, &pos);
	kvfree(disk_block);

	if (ret != q->cluster_size)
		return ret < 0 ? ret : -EIO;

	e->dirty = false;
	return 0;
}

/* Get a refcount block into cache */
static struct lbd_refcount_cache_entry *
lbd_qcow2_refcount_block_get(struct lbd_device *dev, u32 block_index)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct lbd_refcount_cache_entry *best = NULL;
	u64 oldest = U64_MAX;
	int i;

	/* Check cache for hit */
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
		struct lbd_refcount_cache_entry *e = &q->refcount_cache[i];
		if (e->valid && e->block_index == block_index) {
			e->lru = lbd_qcow2_refcount_lru_tick(q);
			return e;
		}
	}

	/* Cache miss: find LRU entry to evict */
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
		struct lbd_refcount_cache_entry *e = &q->refcount_cache[i];
		if (!e->valid) {
			best = e;
			break;
		}
		if (e->lru < oldest) {
			oldest = e->lru;
			best = e;
		}
	}

	/* Flush dirty before eviction */
	if (best->valid && best->dirty)
		lbd_qcow2_refcount_block_flush(dev, best);

	best->block_index = block_index;
	best->dirty = false;
	best->lru = lbd_qcow2_refcount_lru_tick(q);

	if (block_index < q->refcount_table_clusters &&
	    q->refcount_table[block_index] != 0) {
		loff_t pos = q->refcount_table[block_index];
		__be16 *disk_block;
		ssize_t ret;

		disk_block = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!disk_block) {
			best->valid = false;
			return NULL;
		}

		ret = kernel_read(dev->backing_file, disk_block,
				  q->cluster_size, &pos);
		if (ret != q->cluster_size) {
			kvfree(disk_block);
			best->valid = false;
			return NULL;
		}

		for (i = 0; i < q->refcount_entries_per_block; i++)
			best->entries[i] = be16_to_cpu(disk_block[i]);

		kvfree(disk_block);
	} else {
		memset(best->entries, 0, q->cluster_size);
	}

	best->valid = true;
	return best;
}

/* Get the refcount for a host cluster */
static u16 lbd_qcow2_get_refcount(struct lbd_device *dev, u64 host_cluster)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u32 block_index = host_cluster / q->refcount_entries_per_block;
	u32 entry_index = host_cluster % q->refcount_entries_per_block;
	struct lbd_refcount_cache_entry *e;

	if (!q->refcount_table)
		return 0;

	if (block_index >= q->refcount_table_clusters)
		return 0;

	e = lbd_qcow2_refcount_block_get(dev, block_index);
	if (!e)
		return 0;

	return e->entries[entry_index];
}

/* Set the refcount for a host cluster */
static int lbd_qcow2_set_refcount(struct lbd_device *dev, u64 host_cluster,
				   u16 value)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u32 block_index = host_cluster / q->refcount_entries_per_block;
	u32 entry_index = host_cluster % q->refcount_entries_per_block;
	struct lbd_refcount_cache_entry *e;

	if (!q->refcount_table)
		return -EINVAL;

	/* Grow refcount table if needed */
	if (block_index >= q->refcount_table_clusters) {
		u32 new_size = block_index + 1;
		u64 *new_table;
		u32 i;

		new_table = kvmalloc_array(new_size, sizeof(u64), GFP_NOIO);
		if (!new_table)
			return -ENOMEM;

		if (q->refcount_table) {
			memcpy(new_table, q->refcount_table,
			       q->refcount_table_clusters * sizeof(u64));
		}
		for (i = q->refcount_table_clusters; i < new_size; i++)
			new_table[i] = 0;

		kvfree(q->refcount_table);
		q->refcount_table = new_table;
		q->refcount_table_clusters = new_size;
	}

	/* Allocate refcount block if needed */
	if (q->refcount_table[block_index] == 0) {
		loff_t block_phys = q->alloc_offset;
		void *zeros;
		loff_t pos;
		ssize_t ret;

		q->alloc_offset += q->cluster_size;

		/* Write zeroed block to disk */
		zeros = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!zeros)
			return -ENOMEM;
		memset(zeros, 0, q->cluster_size);
		pos = block_phys;
		ret = kernel_write(dev->backing_file, zeros,
				   q->cluster_size, &pos);
		kvfree(zeros);
		if (ret != q->cluster_size)
			return ret < 0 ? ret : -EIO;

		q->refcount_table[block_index] = block_phys;

		/* Invalidate any cached entry for this block */
		{
			int i;
			for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
				struct lbd_refcount_cache_entry *ce =
					&q->refcount_cache[i];
				if (ce->valid && ce->block_index == block_index)
					ce->valid = false;
			}
		}
	}

	e = lbd_qcow2_refcount_block_get(dev, block_index);
	if (!e)
		return -EIO;

	e->entries[entry_index] = value;
	e->dirty = true;
	return 0;
}

/* Increment refcount for a host cluster, returns new value */
static int lbd_qcow2_increment_refcount(struct lbd_device *dev,
					 u64 host_cluster)
{
	u16 rc = lbd_qcow2_get_refcount(dev, host_cluster);

	if (rc == 0xFFFF)
		return -EOVERFLOW;

	return lbd_qcow2_set_refcount(dev, host_cluster, rc + 1);
}

/* Decrement refcount for a host cluster, returns new value via *out */
static int lbd_qcow2_decrement_refcount(struct lbd_device *dev,
					 u64 host_cluster, u16 *out)
{
	u16 rc = lbd_qcow2_get_refcount(dev, host_cluster);
	int err;

	if (rc == 0) {
		if (out) *out = 0;
		return 0;
	}

	err = lbd_qcow2_set_refcount(dev, host_cluster, rc - 1);
	if (err)
		return err;

	if (out)
		*out = rc - 1;
	return 0;
}

/* Flush all dirty refcount cache entries */
static void lbd_qcow2_refcount_cache_flush(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	int i;

	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
		struct lbd_refcount_cache_entry *e = &q->refcount_cache[i];
		if (e->valid && e->dirty)
			lbd_qcow2_refcount_block_flush(dev, e);
	}
}

/* Write refcount table (array of u64 pointers) to disk */
static int lbd_qcow2_write_refcount_table(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	__be64 *disk_table;
	loff_t pos;
	ssize_t ret;
	u32 i;
	u32 table_bytes;

	if (!q->refcount_table || q->refcount_table_clusters == 0)
		return 0;

	table_bytes = q->refcount_table_clusters * sizeof(u64);

	disk_table = kvmalloc(table_bytes, GFP_NOIO);
	if (!disk_table)
		return -ENOMEM;

	for (i = 0; i < q->refcount_table_clusters; i++)
		disk_table[i] = cpu_to_be64(q->refcount_table[i]);

	pos = q->refcount_table_offset;
	ret = kernel_write(dev->backing_file, disk_table, table_bytes, &pos);
	kvfree(disk_table);

	if (ret != table_bytes)
		return ret < 0 ? ret : -EIO;

	return 0;
}

/* Forward declaration — defined later, needed by refcount init scan */
static struct lbd_l2_cache_entry *
lbd_qcow2_l2_get(struct lbd_device *dev, u32 l1_index);

/*
 * Initialize refcount table from scratch by scanning all L1/L2 tables.
 * Called during first snapshot creation.
 */
static int lbd_qcow2_refcount_init_from_scan(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u32 i, j;
	int err;

	q->refcount_entries_per_block = q->cluster_size / sizeof(u16);

	/* Allocate initial refcount table (empty, will grow as needed) */
	q->refcount_table = kvmalloc_array(1, sizeof(u64), GFP_NOIO);
	if (!q->refcount_table)
		return -ENOMEM;
	q->refcount_table[0] = 0;
	q->refcount_table_clusters = 1;

	/* Allocate space for refcount table on disk */
	q->refcount_table_offset = q->alloc_offset;
	q->alloc_offset += q->cluster_size; /* reserve at least one cluster */

	/* Allocate refcount cache entries */
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
		struct lbd_refcount_cache_entry *e = &q->refcount_cache[i];
		if (!e->entries) {
			e->entries = kvmalloc(q->cluster_size, GFP_NOIO);
			if (!e->entries)
				return -ENOMEM;
		}
		e->valid = false;
		e->dirty = false;
	}

	/* Walk active L1/L2: increment refcount for each allocation */
	for (i = 0; i < q->l1_size; i++) {
		u64 l2_phys = q->l1_table[i];
		struct lbd_l2_cache_entry *l2e;
		u64 l2_host_cluster;

		if (l2_phys == 0)
			continue;

		/* Increment refcount for the L2 table's host cluster */
		l2_host_cluster = l2_phys / q->cluster_size;
		err = lbd_qcow2_increment_refcount(dev, l2_host_cluster);
		if (err)
			return err;

		/* Load L2 table and walk entries */
		l2e = lbd_qcow2_l2_get(dev, i);
		if (!l2e)
			return -EIO;

		for (j = 0; j < q->l2_entries; j++) {
			u64 entry = l2e->table[j];
			u64 phys, host_cluster;

			if (entry == 0)
				continue;

			phys = entry & LBD_QCOW2_L2_OFFSET_MASK;
			host_cluster = phys / q->cluster_size;
			err = lbd_qcow2_increment_refcount(dev,
							    host_cluster);
			if (err)
				return err;
		}
	}

	/* Flush all refcount blocks to disk */
	lbd_qcow2_refcount_cache_flush(dev);

	/* Write refcount table to disk */
	err = lbd_qcow2_write_refcount_table(dev);
	if (err)
		return err;

	/* Write refcount header fields */
	err = lbd_qcow2_write_refcount_header(dev);
	if (err)
		return err;

	return 0;
}

/* Maximum number of free list entries to scan when allocating */
#define LBD_QCOW2_FREE_SCAN_LIMIT	8

/* Minimum free entry size (tombstone header) */
#define LBD_QCOW2_FREE_ENTRY_MIN	16

/*
 * Try to allocate space from the free list or append.
 * needed: bytes required for the new on-disk data.
 * Returns the physical offset to write at via *out_phys.
 */
static int lbd_qcow2_alloc_space(struct lbd_device *dev, u64 needed,
				  loff_t *out_phys)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	loff_t prev_phys = 0;
	loff_t cur = q->free_list_head;
	int scanned = 0;
	int is_first = 1;

	while (cur != 0 && scanned < LBD_QCOW2_FREE_SCAN_LIMIT) {
		u8 buf[16];
		loff_t pos = cur;
		ssize_t ret;
		u32 tombstone, extent_size;
		u64 next_free;

		ret = kernel_read(dev->backing_file, buf, 16, &pos);
		if (ret != 16)
			break;

		tombstone = _qcow2_get32(buf, 0);
		if (tombstone != LBD_QCOW2_FREE_TOMBSTONE)
			break;

		extent_size = _qcow2_get32(buf, 4);
		next_free = _qcow2_get64(buf, 8);

		if (extent_size >= needed) {
			u64 remainder = extent_size - needed;

			/* Unlink this entry from the free list */
			if (is_first) {
				q->free_list_head = next_free;
			} else {
				/* Update previous entry's next pointer */
				u8 nbuf[8];
				loff_t npos = prev_phys + 8;

				_qcow2_put64(nbuf, 0, next_free);
				ret = kernel_write(dev->backing_file, nbuf, 8,
						   &npos);
				if (ret != 8)
					goto append;
			}

			/* Split if remainder is large enough */
			if (remainder >= LBD_QCOW2_FREE_ENTRY_MIN) {
				loff_t split_phys = cur + needed;
				int err;

				/*
				 * Add the remainder back as a new free entry
				 * at the head of the free list.
				 */
				err = lbd_qcow2_free_extent(dev, split_phys,
							    remainder);
				if (err) {
					/*
					 * Non-fatal: we waste the remainder
					 * but the allocation itself is fine.
					 */
					lbd_qcow2_write_free_list_head(dev);
				}
			} else {
				lbd_qcow2_write_free_list_head(dev);
			}

			*out_phys = cur;
			atomic64_inc(&dev->stat_alloc_reused);
			return 0;
		}

		prev_phys = cur;
		cur = next_free;
		is_first = 0;
		scanned++;
	}

append:
	*out_phys = q->alloc_offset;
	q->alloc_offset += needed;
	atomic64_inc(&dev->stat_alloc_new);
	return 0;
}

/* ----------------------------------------------------------------
 * L2 cache
 * ---------------------------------------------------------------- */

/* Find or load an L2 table into cache, return pointer to cache entry */
static struct lbd_l2_cache_entry *
lbd_qcow2_l2_get(struct lbd_device *dev, u32 l1_index)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct lbd_l2_cache_entry *best = NULL;
	u64 oldest = U64_MAX;
	int i;

	/* Check cache for hit */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &q->l2_cache[i];

		if (e->valid && e->l1_index == l1_index) {
			e->lru = lbd_qcow2_lru_tick(q);
			return e;
		}
	}

	/* Cache miss: find LRU entry to evict */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &q->l2_cache[i];

		if (!e->valid) {
			best = e;
			break;
		}
		if (e->lru < oldest) {
			oldest = e->lru;
			best = e;
		}
	}

	/* Flush dirty entry before evicting */
	if (best->valid && best->dirty) {
		u64 l2_phys = q->l1_table[best->l1_index];
		if (l2_phys) {
			loff_t pos = l2_phys;
			__be64 *disk_l2;
			int j;
			ssize_t ret;

			disk_l2 = kvmalloc(q->cluster_size, GFP_NOIO);
			if (disk_l2) {
				for (j = 0; j < q->l2_entries; j++)
					disk_l2[j] = cpu_to_be64(best->table[j]);
				ret = kernel_write(dev->backing_file, disk_l2,
						   q->cluster_size, &pos);
				if (ret != q->cluster_size)
					pr_warn("lbd%d: L2 flush failed\n",
						dev->index);
				kvfree(disk_l2);
			}
		}
		best->dirty = false;
	}

	/* Load L2 table from disk */
	best->l1_index = l1_index;
	best->dirty = false;
	best->lru = lbd_qcow2_lru_tick(q);

	if (l1_index < q->l1_size && q->l1_table[l1_index] != 0) {
		loff_t pos = q->l1_table[l1_index];
		__be64 *disk_l2;
		ssize_t ret;
		int j;

		disk_l2 = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!disk_l2) {
			best->valid = false;
			return NULL;
		}

		ret = kernel_read(dev->backing_file, disk_l2,
				  q->cluster_size, &pos);
		if (ret != q->cluster_size) {
			pr_warn("lbd%d: L2 read failed for l1[%u]\n",
				dev->index, l1_index);
			kvfree(disk_l2);
			best->valid = false;
			return NULL;
		}

		for (j = 0; j < q->l2_entries; j++)
			best->table[j] = be64_to_cpu(disk_l2[j]);

		kvfree(disk_l2);
	} else {
		/* Unallocated L2: all zeros */
		memset(best->table, 0, q->cluster_size);
	}

	best->valid = true;
	return best;
}

/* Flush a specific dirty L2 entry to disk */
static int lbd_qcow2_l2_flush(struct lbd_device *dev,
			       struct lbd_l2_cache_entry *e)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u64 l2_phys;
	__be64 *disk_l2;
	loff_t pos;
	ssize_t ret;
	int j;

	if (!e->valid || !e->dirty)
		return 0;

	l2_phys = q->l1_table[e->l1_index];
	if (!l2_phys)
		return -EIO; /* should not happen */

	disk_l2 = kvmalloc(q->cluster_size, GFP_NOIO);
	if (!disk_l2)
		return -ENOMEM;

	for (j = 0; j < q->l2_entries; j++)
		disk_l2[j] = cpu_to_be64(e->table[j]);

	pos = l2_phys;
	ret = kernel_write(dev->backing_file, disk_l2, q->cluster_size, &pos);
	kvfree(disk_l2);

	if (ret != q->cluster_size)
		return ret < 0 ? ret : -EIO;

	e->dirty = false;
	return 0;
}

/*
 * COW an L2 table if it is shared with a snapshot (refcount > 1).
 * Must be called before modifying any L2 entry (write, discard).
 */
static int lbd_qcow2_l2_cow_if_needed(struct lbd_device *dev, u32 l1_index)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u64 l2_phys, old_host, new_phys;
	u16 rc;
	struct lbd_l2_cache_entry *l2e;
	__be64 *disk_l2;
	loff_t pos;
	ssize_t ret;
	__be64 val;
	int j, err;

	if (!q->refcount_table || l1_index >= q->l1_size)
		return 0;

	l2_phys = q->l1_table[l1_index];
	if (l2_phys == 0)
		return 0;

	old_host = l2_phys / q->cluster_size;
	rc = lbd_qcow2_get_refcount(dev, old_host);
	if (rc <= 1)
		return 0;  /* not shared */

	/* COW the L2 table: allocate new cluster */
	new_phys = q->alloc_offset;
	q->alloc_offset += q->cluster_size;

	/* Load current L2 data */
	l2e = lbd_qcow2_l2_get(dev, l1_index);
	if (!l2e)
		return -EIO;

	/* Write L2 data to new location */
	disk_l2 = kvmalloc(q->cluster_size, GFP_NOIO);
	if (!disk_l2)
		return -ENOMEM;

	for (j = 0; j < q->l2_entries; j++)
		disk_l2[j] = cpu_to_be64(l2e->table[j]);

	pos = new_phys;
	ret = kernel_write(dev->backing_file, disk_l2, q->cluster_size, &pos);
	kvfree(disk_l2);
	if (ret != q->cluster_size)
		return ret < 0 ? ret : -EIO;

	/* Update L1 entry to point to new location */
	q->l1_table[l1_index] = new_phys;
	val = cpu_to_be64(new_phys);
	pos = q->l1_offset + (loff_t)l1_index * sizeof(__be64);
	ret = kernel_write(dev->backing_file, &val, sizeof(val), &pos);
	if (ret != sizeof(val))
		return ret < 0 ? ret : -EIO;

	/* Update cache entry to reflect new location */
	/* (l2e is still the same cache entry, just update metadata) */

	/* Update refcounts */
	err = lbd_qcow2_decrement_refcount(dev, old_host, NULL);
	if (err)
		return err;

	new_phys /= q->cluster_size;
	err = lbd_qcow2_increment_refcount(dev, new_phys);
	if (err)
		return err;

	return 0;
}

/* Allocate a new L2 table on disk if needed */
static int lbd_qcow2_l2_alloc(struct lbd_device *dev, u32 l1_index)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	loff_t pos;
	__be64 val;
	ssize_t ret;

	if (l1_index >= q->l1_size)
		return -ENOSPC;

	if (q->l1_table[l1_index] != 0)
		return 0; /* already allocated */

	/* Allocate cluster for L2 table at append point */
	q->l1_table[l1_index] = q->alloc_offset;
	q->alloc_offset += q->cluster_size;

	/* Write zeroed L2 table to disk */
	{
		void *zeros = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!zeros)
			return -ENOMEM;
		memset(zeros, 0, q->cluster_size);
		pos = q->l1_table[l1_index];
		ret = kernel_write(dev->backing_file, zeros,
				   q->cluster_size, &pos);
		kvfree(zeros);
		if (ret != q->cluster_size)
			return ret < 0 ? ret : -EIO;
	}

	/* Write L1 entry to disk */
	val = cpu_to_be64(q->l1_table[l1_index]);
	pos = q->l1_offset + (loff_t)l1_index * sizeof(__be64);
	ret = kernel_write(dev->backing_file, &val, sizeof(val), &pos);
	if (ret != sizeof(val))
		return ret < 0 ? ret : -EIO;

	return 0;
}

/* ----------------------------------------------------------------
 * Cluster cache
 * ---------------------------------------------------------------- */

static struct lbd_cl_cache_entry *
lbd_qcow2_cl_find(struct lbd_qcow2 *q, u64 cluster_index)
{
	int i;

	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++) {
		struct lbd_cl_cache_entry *e = &q->cl_cache[i];

		if (e->valid && e->cluster_index == cluster_index) {
			e->lru = lbd_qcow2_lru_tick(q);
			return e;
		}
	}
	return NULL;
}

static void lbd_qcow2_cl_invalidate(struct lbd_qcow2 *q, u64 cluster_index)
{
	int i;

	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++) {
		struct lbd_cl_cache_entry *e = &q->cl_cache[i];

		if (e->valid && e->cluster_index == cluster_index) {
			e->valid = false;
			return;
		}
	}
}

static struct lbd_cl_cache_entry *
lbd_qcow2_cl_alloc_entry(struct lbd_qcow2 *q)
{
	struct lbd_cl_cache_entry *best = NULL;
	u64 oldest = U64_MAX;
	int i;

	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++) {
		struct lbd_cl_cache_entry *e = &q->cl_cache[i];

		if (!e->valid) {
			best = e;
			break;
		}
		if (e->lru < oldest) {
			oldest = e->lru;
			best = e;
		}
	}

	/* Evict LRU (cluster cache is read-only cache, no flush needed) */
	best->valid = false;
	return best;
}

/* Load a cluster into cache from disk via L2 lookup */
static struct lbd_cl_cache_entry *
lbd_qcow2_cl_load(struct lbd_device *dev, u64 cluster_index)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct lbd_cl_cache_entry *ce;
	struct lbd_l2_cache_entry *l2e;
	u32 l1_idx, l2_idx;
	u64 l2_entry, phys_offset;
	ssize_t ret;

	/* Check cache first */
	ce = lbd_qcow2_cl_find(q, cluster_index);
	if (ce)
		return ce;

	/* L2 lookup */
	l1_idx = cluster_index / q->l2_entries;
	l2_idx = cluster_index % q->l2_entries;

	l2e = lbd_qcow2_l2_get(dev, l1_idx);
	if (!l2e)
		return NULL;

	l2_entry = l2e->table[l2_idx];

	/* Get a cache entry */
	ce = lbd_qcow2_cl_alloc_entry(q);
	ce->cluster_index = cluster_index;
	ce->lru = lbd_qcow2_lru_tick(q);
	ce->dirty = false;

	if (l2_entry == 0) {
		if (dev->base) {
			int err = lbd_qcow2_base_read_cluster(dev,
					cluster_index, ce->data);
			if (err)
				return NULL;
		} else {
			memset(ce->data, 0, q->cluster_size);
		}
		ce->valid = true;
		return ce;
	}

	phys_offset = l2_entry & LBD_QCOW2_L2_OFFSET_MASK;

	if (l2_entry & LBD_QCOW2_L2_COMPRESSED) {
		/* Compressed cluster: read size header + compressed data */
		__be32 comp_size_be;
		u32 comp_size;
		int dec_len;
		loff_t pos = phys_offset;

		ret = kernel_read(dev->backing_file, &comp_size_be,
				  sizeof(comp_size_be), &pos);
		if (ret != sizeof(comp_size_be)) {
			pr_warn("lbd%d: failed to read compressed size\n",
				dev->index);
			return NULL;
		}

		comp_size = be32_to_cpu(comp_size_be);
		if (comp_size > LZ4_compressBound(q->cluster_size)) {
			pr_warn("lbd%d: invalid compressed size %u\n",
				dev->index, comp_size);
			return NULL;
		}

		ret = kernel_read(dev->backing_file, q->read_buf,
				  comp_size, &pos);
		if (ret != comp_size) {
			pr_warn("lbd%d: failed to read compressed data\n",
				dev->index);
			return NULL;
		}

		dec_len = LZ4_decompress_safe(q->read_buf, ce->data,
					      comp_size, q->cluster_size);
		if (dec_len != q->cluster_size) {
			pr_warn("lbd%d: LZ4 decompress failed (%d)\n",
				dev->index, dec_len);
			return NULL;
		}
	} else {
		/* Uncompressed cluster */
		loff_t pos = phys_offset;

		ret = kernel_read(dev->backing_file, ce->data,
				  q->cluster_size, &pos);
		if (ret != q->cluster_size) {
			pr_warn("lbd%d: failed to read cluster\n",
				dev->index);
			return NULL;
		}
	}

	ce->valid = true;
	return ce;
}

/* ----------------------------------------------------------------
 * Snapshot create / delete
 * ---------------------------------------------------------------- */

/*
 * Flush all dirty L2 cache entries to disk.
 */
static void lbd_qcow2_flush_all_l2(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	int i;

	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &q->l2_cache[i];
		if (e->valid && e->dirty)
			lbd_qcow2_l2_flush(dev, e);
	}
}

/*
 * Set COW flag on all non-zero L2 entries in all allocated L2 tables.
 */
static int lbd_qcow2_set_cow_flags(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u32 i, j;

	for (i = 0; i < q->l1_size; i++) {
		struct lbd_l2_cache_entry *l2e;

		if (q->l1_table[i] == 0)
			continue;

		l2e = lbd_qcow2_l2_get(dev, i);
		if (!l2e)
			return -EIO;

		for (j = 0; j < q->l2_entries; j++) {
			if (l2e->table[j] != 0) {
				l2e->table[j] |= LBD_QCOW2_L2_COW;
				l2e->dirty = true;
			}
		}

		lbd_qcow2_l2_flush(dev, l2e);
	}
	return 0;
}

/*
 * Clear COW flag on all L2 entries in all allocated L2 tables.
 */
static int lbd_qcow2_clear_cow_flags(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u32 i, j;

	for (i = 0; i < q->l1_size; i++) {
		struct lbd_l2_cache_entry *l2e;

		if (q->l1_table[i] == 0)
			continue;

		l2e = lbd_qcow2_l2_get(dev, i);
		if (!l2e)
			return -EIO;

		for (j = 0; j < q->l2_entries; j++) {
			if (l2e->table[j] & LBD_QCOW2_L2_COW) {
				l2e->table[j] &= ~LBD_QCOW2_L2_COW;
				l2e->dirty = true;
			}
		}

		lbd_qcow2_l2_flush(dev, l2e);
	}
	return 0;
}

/*
 * Write a snapshot table entry to disk at the given offset.
 * Returns the total bytes written (including alignment padding).
 */
static int lbd_qcow2_write_snap_entry(struct lbd_device *dev, loff_t offset,
				       u32 snap_id, u64 l1_off, u32 l1_sz,
				       u32 date_sec, u32 date_nsec,
				       const char *name, u16 name_len)
{
	u8 buf[LBD_QCOW2_SNAP_FIXED_SIZE];
	loff_t pos = offset;
	ssize_t ret;
	u32 padded_name_len;

	_qcow2_put32(buf, 0, snap_id);
	_qcow2_put64(buf, 4, l1_off);
	_qcow2_put32(buf, 12, l1_sz);
	_qcow2_put32(buf, 16, date_sec);
	_qcow2_put32(buf, 20, date_nsec);
	_qcow2_put16(buf, 24, name_len);

	ret = kernel_write(dev->backing_file, buf, LBD_QCOW2_SNAP_FIXED_SIZE,
			   &pos);
	if (ret != LBD_QCOW2_SNAP_FIXED_SIZE)
		return ret < 0 ? ret : -EIO;

	/* Write name */
	if (name_len > 0) {
		ret = kernel_write(dev->backing_file, name, name_len, &pos);
		if (ret != name_len)
			return ret < 0 ? ret : -EIO;
	}

	/* Pad to 8-byte alignment */
	padded_name_len = ALIGN(name_len, 8);
	if (padded_name_len > name_len) {
		u8 zeros[8] = {0};
		u32 pad = padded_name_len - name_len;

		ret = kernel_write(dev->backing_file, zeros, pad, &pos);
		if (ret != pad)
			return ret < 0 ? ret : -EIO;
	}

	return 0;
}

int lbd_qcow2_snapshot_create(struct lbd_device *dev, const char *name)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u16 name_len;
	u32 snap_id;
	u64 l1_copy_offset;
	u32 l1_bytes;
	__be64 *disk_l1;
	loff_t pos;
	ssize_t ret;
	struct timespec64 ts;
	int err, i;

	name_len = strlen(name);
	if (name_len > LBD_QCOW2_SNAP_NAME_MAX)
		return -ENAMETOOLONG;

	down_write(&q->rwsem);

	/* Step 1: Flush all dirty L2 cache entries */
	lbd_qcow2_flush_all_l2(dev);

	/* Step 2: Allocate space for L1 table copy */
	l1_bytes = q->l1_size * sizeof(u64);
	l1_copy_offset = q->alloc_offset;
	q->alloc_offset += ALIGN(l1_bytes, q->cluster_size);

	/* Step 3: Write current L1 table to copy location */
	disk_l1 = kvmalloc_array(q->l1_size, sizeof(__be64), GFP_NOIO);
	if (!disk_l1) {
		up_write(&q->rwsem);
		return -ENOMEM;
	}

	for (i = 0; i < q->l1_size; i++)
		disk_l1[i] = cpu_to_be64(q->l1_table[i]);

	pos = l1_copy_offset;
	ret = kernel_write(dev->backing_file, disk_l1, l1_bytes, &pos);
	kvfree(disk_l1);
	if (ret != l1_bytes) {
		up_write(&q->rwsem);
		return ret < 0 ? ret : -EIO;
	}

	/* Step 4: Initialize refcount table if first snapshot */
	if (!q->refcount_table) {
		err = lbd_qcow2_refcount_init_from_scan(dev);
		if (err) {
			up_write(&q->rwsem);
			return err;
		}
		q->incompatible_features |= LBD_QCOW2_FEAT_REFCOUNTS |
					     LBD_QCOW2_FEAT_SNAPSHOTS;
		lbd_qcow2_write_incompat_features(dev);
	} else {
		/* Step 5: Subsequent snapshot - bump refcounts for active data */
		for (i = 0; i < q->l1_size; i++) {
			struct lbd_l2_cache_entry *l2e;
			u64 l2_phys = q->l1_table[i];
			u32 j;

			if (l2_phys == 0)
				continue;

			/* Increment refcount for L2 table's host cluster */
			err = lbd_qcow2_increment_refcount(dev,
				l2_phys / q->cluster_size);
			if (err) {
				up_write(&q->rwsem);
				return err;
			}

			l2e = lbd_qcow2_l2_get(dev, i);
			if (!l2e) {
				up_write(&q->rwsem);
				return -EIO;
			}

			for (j = 0; j < q->l2_entries; j++) {
				u64 entry = l2e->table[j];
				u64 phys;

				if (entry == 0)
					continue;

				phys = entry & LBD_QCOW2_L2_OFFSET_MASK;
				err = lbd_qcow2_increment_refcount(dev,
					phys / q->cluster_size);
				if (err) {
					up_write(&q->rwsem);
					return err;
				}
			}
		}
	}

	/* Step 6: Set COW flag on all non-zero active L2 entries */
	err = lbd_qcow2_set_cow_flags(dev);
	if (err) {
		up_write(&q->rwsem);
		return err;
	}

	/* Step 7: Append snapshot entry to snapshot table */
	snap_id = q->next_snapshot_id++;
	ktime_get_real_ts64(&ts);

	if (q->snapshot_table_offset == 0) {
		q->snapshot_table_offset = q->alloc_offset;
		q->alloc_offset += q->cluster_size;
	}

	{
		/* Calculate position: walk existing entries to find end */
		u32 entry_size = LBD_QCOW2_SNAP_FIXED_SIZE + ALIGN(name_len, 8);
		loff_t snap_pos = q->snapshot_table_offset;
		u32 s;

		/* Skip existing snapshot entries */
		for (s = 0; s < q->snapshot_count; s++) {
			u8 hdr_buf[LBD_QCOW2_SNAP_FIXED_SIZE];
			u16 existing_name_len;

			pos = snap_pos;
			ret = kernel_read(dev->backing_file, hdr_buf,
					  LBD_QCOW2_SNAP_FIXED_SIZE, &pos);
			if (ret != LBD_QCOW2_SNAP_FIXED_SIZE) {
				up_write(&q->rwsem);
				return -EIO;
			}
			existing_name_len = _qcow2_get16(hdr_buf, 24);
			snap_pos += LBD_QCOW2_SNAP_FIXED_SIZE +
				    ALIGN(existing_name_len, 8);
		}

		err = lbd_qcow2_write_snap_entry(dev, snap_pos, snap_id,
						  l1_copy_offset, q->l1_size,
						  (u32)ts.tv_sec,
						  (u32)ts.tv_nsec,
						  name, name_len);
		if (err) {
			up_write(&q->rwsem);
			return err;
		}

		(void)entry_size;
	}

	/* Step 8: Update snapshot count and header */
	q->snapshot_count++;

	/* Flush refcount cache */
	lbd_qcow2_refcount_cache_flush(dev);
	lbd_qcow2_write_refcount_table(dev);
	lbd_qcow2_write_refcount_header(dev);

	lbd_qcow2_write_snapshot_header(dev);
	lbd_qcow2_write_alloc_offset(dev);

	pr_info("lbd%d: snapshot '%s' created (id=%u)\n",
		dev->index, name, snap_id);

	up_write(&q->rwsem);
	return 0;
}

int lbd_qcow2_snapshot_delete(struct lbd_device *dev, u32 snapshot_id)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	loff_t snap_pos;
	u32 s, found_idx = U32_MAX;
	u64 snap_l1_offset = 0;
	u32 snap_l1_size = 0;
	u64 *snap_l1 = NULL;
	__be64 *disk_l1 = NULL;
	int err = 0;
	u32 i, j;

	down_write(&q->rwsem);

	if (q->snapshot_count == 0) {
		up_write(&q->rwsem);
		return -ENOENT;
	}

	/* Find the snapshot entry */
	snap_pos = q->snapshot_table_offset;
	for (s = 0; s < q->snapshot_count; s++) {
		u8 hdr_buf[LBD_QCOW2_SNAP_FIXED_SIZE];
		u32 sid;
		u16 nlen;
		loff_t pos = snap_pos;
		ssize_t ret;

		ret = kernel_read(dev->backing_file, hdr_buf,
				  LBD_QCOW2_SNAP_FIXED_SIZE, &pos);
		if (ret != LBD_QCOW2_SNAP_FIXED_SIZE) {
			err = -EIO;
			goto out;
		}

		sid = _qcow2_get32(hdr_buf, 0);
		nlen = _qcow2_get16(hdr_buf, 24);

		if (sid == snapshot_id) {
			found_idx = s;
			snap_l1_offset = _qcow2_get64(hdr_buf, 4);
			snap_l1_size = _qcow2_get32(hdr_buf, 12);
			break;
		}

		snap_pos += LBD_QCOW2_SNAP_FIXED_SIZE + ALIGN(nlen, 8);
	}

	if (found_idx == U32_MAX) {
		err = -ENOENT;
		goto out;
	}

	/* Load the snapshot's L1 table */
	snap_l1 = kvmalloc_array(snap_l1_size, sizeof(u64), GFP_NOIO);
	if (!snap_l1) {
		err = -ENOMEM;
		goto out;
	}

	disk_l1 = kvmalloc_array(snap_l1_size, sizeof(__be64), GFP_NOIO);
	if (!disk_l1) {
		err = -ENOMEM;
		goto out;
	}

	{
		loff_t pos = snap_l1_offset;
		ssize_t ret = kernel_read(dev->backing_file, disk_l1,
					  snap_l1_size * sizeof(__be64), &pos);
		if (ret != snap_l1_size * sizeof(__be64)) {
			err = ret < 0 ? ret : -EIO;
			goto out;
		}
	}

	for (i = 0; i < snap_l1_size; i++)
		snap_l1[i] = be64_to_cpu(disk_l1[i]);
	kvfree(disk_l1);
	disk_l1 = NULL;

	/* Walk snapshot's L2 tables and decrement refcounts */
	for (i = 0; i < snap_l1_size; i++) {
		u64 l2_phys = snap_l1[i];
		__be64 *snap_l2_disk;
		u64 *snap_l2;
		u16 new_rc;
		loff_t pos;
		ssize_t ret;

		if (l2_phys == 0)
			continue;

		/* Read the snapshot's L2 table from disk */
		snap_l2_disk = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!snap_l2_disk) {
			err = -ENOMEM;
			goto out;
		}
		snap_l2 = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!snap_l2) {
			kvfree(snap_l2_disk);
			err = -ENOMEM;
			goto out;
		}

		pos = l2_phys;
		ret = kernel_read(dev->backing_file, snap_l2_disk,
				  q->cluster_size, &pos);
		if (ret != q->cluster_size) {
			kvfree(snap_l2);
			kvfree(snap_l2_disk);
			err = ret < 0 ? ret : -EIO;
			goto out;
		}

		for (j = 0; j < q->l2_entries; j++)
			snap_l2[j] = be64_to_cpu(snap_l2_disk[j]);
		kvfree(snap_l2_disk);

		/* Decrement refcount for each data cluster */
		for (j = 0; j < q->l2_entries; j++) {
			u64 entry = snap_l2[j];
			u64 phys;

			if (entry == 0)
				continue;

			phys = entry & LBD_QCOW2_L2_OFFSET_MASK;
			err = lbd_qcow2_decrement_refcount(dev,
				phys / q->cluster_size, &new_rc);
			if (err) {
				kvfree(snap_l2);
				goto out;
			}

			if (new_rc == 0) {
				/* Host cluster is now free */
				u64 old_sz = lbd_qcow2_read_old_alloc_size(
						dev, entry);
				if (old_sz > 0)
					lbd_qcow2_free_extent(dev, phys,
							      old_sz);
			}
		}

		kvfree(snap_l2);

		/* Decrement refcount for the L2 table itself */
		err = lbd_qcow2_decrement_refcount(dev,
			l2_phys / q->cluster_size, &new_rc);
		if (err)
			goto out;

		if (new_rc == 0) {
			lbd_qcow2_free_extent(dev, l2_phys, q->cluster_size);
		}
	}

	/* Free the snapshot's L1 table cluster(s) */
	{
		u64 l1_bytes = ALIGN((u64)snap_l1_size * sizeof(u64),
				     q->cluster_size);
		lbd_qcow2_free_extent(dev, snap_l1_offset, l1_bytes);
	}

	/* Remove snapshot entry from table by compacting */
	{
		/* Re-read all snapshot entries, skip the deleted one, rewrite */
		u8 *snap_table_buf;
		loff_t read_pos, write_pos;
		u32 total_entries = q->snapshot_count;

		snap_table_buf = kvmalloc(q->cluster_size, GFP_NOIO);
		if (!snap_table_buf) {
			err = -ENOMEM;
			goto out;
		}

		read_pos = q->snapshot_table_offset;
		write_pos = q->snapshot_table_offset;

		for (s = 0; s < total_entries; s++) {
			u8 hdr_buf[LBD_QCOW2_SNAP_FIXED_SIZE];
			u16 nlen;
			u32 entry_total;
			loff_t rp = read_pos;
			ssize_t ret;

			ret = kernel_read(dev->backing_file, hdr_buf,
					  LBD_QCOW2_SNAP_FIXED_SIZE, &rp);
			if (ret != LBD_QCOW2_SNAP_FIXED_SIZE) {
				kvfree(snap_table_buf);
				err = -EIO;
				goto out;
			}

			nlen = _qcow2_get16(hdr_buf, 24);
			entry_total = LBD_QCOW2_SNAP_FIXED_SIZE +
				      ALIGN(nlen, 8);

			if (s == found_idx) {
				/* Skip this entry */
				read_pos += entry_total;
				continue;
			}

			if (write_pos != read_pos) {
				/* Read entire entry and write to new position */
				u8 *entry_buf = kvmalloc(entry_total, GFP_NOIO);
				if (!entry_buf) {
					kvfree(snap_table_buf);
					err = -ENOMEM;
					goto out;
				}

				rp = read_pos;
				ret = kernel_read(dev->backing_file, entry_buf,
						  entry_total, &rp);
				if (ret != entry_total) {
					kvfree(entry_buf);
					kvfree(snap_table_buf);
					err = -EIO;
					goto out;
				}

				rp = write_pos;
				ret = kernel_write(dev->backing_file, entry_buf,
						   entry_total, &rp);
				kvfree(entry_buf);
				if (ret != entry_total) {
					kvfree(snap_table_buf);
					err = ret < 0 ? ret : -EIO;
					goto out;
				}
			}

			write_pos += entry_total;
			read_pos += entry_total;
		}

		kvfree(snap_table_buf);
	}

	q->snapshot_count--;

	/* If no more snapshots, clear COW flags */
	if (q->snapshot_count == 0) {
		lbd_qcow2_clear_cow_flags(dev);
	}

	/* Flush and persist metadata */
	lbd_qcow2_refcount_cache_flush(dev);
	lbd_qcow2_write_refcount_table(dev);
	lbd_qcow2_write_snapshot_header(dev);
	lbd_qcow2_write_alloc_offset(dev);

	pr_info("lbd%d: snapshot id=%u deleted (%u remaining)\n",
		dev->index, snapshot_id, q->snapshot_count);

out:
	kvfree(snap_l1);
	kvfree(disk_l1);
	up_write(&q->rwsem);
	return err;
}

int lbd_qcow2_snapshot_list(struct lbd_device *dev, void __user *buf,
			    u32 buf_size, u32 *count_out)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	loff_t snap_pos;
	u32 s;

	down_read(&q->rwsem);

	*count_out = q->snapshot_count;

	if (buf && buf_size > 0) {
		snap_pos = q->snapshot_table_offset;
		for (s = 0; s < q->snapshot_count && buf_size > 0; s++) {
			u8 hdr_buf[LBD_QCOW2_SNAP_FIXED_SIZE];
			u16 nlen;
			u32 entry_total;
			loff_t pos = snap_pos;
			ssize_t ret;
			u32 to_copy;

			ret = kernel_read(dev->backing_file, hdr_buf,
					  LBD_QCOW2_SNAP_FIXED_SIZE, &pos);
			if (ret != LBD_QCOW2_SNAP_FIXED_SIZE) {
				up_read(&q->rwsem);
				return -EIO;
			}

			nlen = _qcow2_get16(hdr_buf, 24);
			entry_total = LBD_QCOW2_SNAP_FIXED_SIZE +
				      ALIGN(nlen, 8);

			to_copy = min_t(u32, entry_total, buf_size);
			/* Read entire entry and copy to user */
			{
				u8 *entry_buf = kvmalloc(entry_total, GFP_NOIO);
				if (!entry_buf) {
					up_read(&q->rwsem);
					return -ENOMEM;
				}

				pos = snap_pos;
				ret = kernel_read(dev->backing_file, entry_buf,
						  entry_total, &pos);
				if (ret != entry_total) {
					kvfree(entry_buf);
					up_read(&q->rwsem);
					return -EIO;
				}

				if (copy_to_user(buf, entry_buf, to_copy)) {
					kvfree(entry_buf);
					up_read(&q->rwsem);
					return -EFAULT;
				}
				kvfree(entry_buf);
			}

			buf += to_copy;
			buf_size -= to_copy;
			snap_pos += entry_total;
		}
	}

	up_read(&q->rwsem);
	return 0;
}

/* ----------------------------------------------------------------
 * Init / Destroy
 * ---------------------------------------------------------------- */

int lbd_qcow2_init(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	u8 *hdr;
	loff_t pos = 0;
	ssize_t ret;
	__be64 *disk_l1;
	int i;

	hdr = kvmalloc(LBD_QCOW2_HEADER_SIZE, GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	/* Read header */
	ret = kernel_read(dev->backing_file, hdr, LBD_QCOW2_HEADER_SIZE, &pos);
	if (ret != LBD_QCOW2_HEADER_SIZE) {
		pr_err("lbd%d: qcow2 header read failed\n", dev->index);
		kvfree(hdr);
		return ret < 0 ? ret : -EIO;
	}

	if (lbd_qcow2_hdr_magic(hdr) != LBD_QCOW2_MAGIC) {
		pr_err("lbd%d: invalid qcow2 magic\n", dev->index);
		kvfree(hdr);
		return -EINVAL;
	}

	if (lbd_qcow2_hdr_version(hdr) != LBD_QCOW2_VERSION) {
		pr_err("lbd%d: unsupported qcow2 version %u\n",
		       dev->index, lbd_qcow2_hdr_version(hdr));
		kvfree(hdr);
		return -EINVAL;
	}

	q->cluster_bits = lbd_qcow2_hdr_cluster_bits(hdr);
	if (q->cluster_bits < 12 || q->cluster_bits > 24) {
		pr_err("lbd%d: invalid cluster_bits %u\n",
		       dev->index, q->cluster_bits);
		kvfree(hdr);
		return -EINVAL;
	}

	q->cluster_size = 1U << q->cluster_bits;
	q->l2_entries = q->cluster_size / sizeof(u64);
	q->virtual_size = lbd_qcow2_hdr_virtual_size(hdr);
	q->l1_offset = lbd_qcow2_hdr_l1_table_offset(hdr);
	q->l1_size = lbd_qcow2_hdr_l1_size(hdr);
	q->alloc_offset = lbd_qcow2_hdr_alloc_offset(hdr);
	q->free_list_head = lbd_qcow2_hdr_free_list(hdr);
	q->incompatible_features = lbd_qcow2_hdr_incompat_feat(hdr);
	q->refcount_table_offset = lbd_qcow2_hdr_refcount_table(hdr);
	q->refcount_table_clusters = lbd_qcow2_hdr_refcount_clusters(hdr);
	q->snapshot_table_offset = lbd_qcow2_hdr_snapshot_table(hdr);
	q->snapshot_count = lbd_qcow2_hdr_snapshot_count(hdr);
	q->refcount_entries_per_block = q->cluster_size / sizeof(u16);
	q->lru_tick = 0;

	kvfree(hdr);

	init_rwsem(&q->rwsem);

	/* Allocate and read L1 table */
	q->l1_table = kvmalloc_array(q->l1_size, sizeof(u64), GFP_KERNEL);
	if (!q->l1_table)
		return -ENOMEM;

	disk_l1 = kvmalloc_array(q->l1_size, sizeof(__be64), GFP_KERNEL);
	if (!disk_l1) {
		kvfree(q->l1_table);
		q->l1_table = NULL;
		return -ENOMEM;
	}

	pos = q->l1_offset;
	ret = kernel_read(dev->backing_file, disk_l1,
			  q->l1_size * sizeof(__be64), &pos);
	if (ret != q->l1_size * sizeof(__be64)) {
		pr_err("lbd%d: L1 table read failed\n", dev->index);
		kvfree(disk_l1);
		kvfree(q->l1_table);
		q->l1_table = NULL;
		return ret < 0 ? ret : -EIO;
	}

	for (i = 0; i < q->l1_size; i++)
		q->l1_table[i] = be64_to_cpu(disk_l1[i]);
	kvfree(disk_l1);

	/* Allocate L2 cache entries */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &q->l2_cache[i];

		e->table = kvmalloc(q->cluster_size, GFP_KERNEL);
		if (!e->table)
			goto err_l2_cache;
		e->valid = false;
		e->dirty = false;
	}

	/* Allocate cluster cache entries */
	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++) {
		struct lbd_cl_cache_entry *e = &q->cl_cache[i];

		e->data = kvmalloc(q->cluster_size, GFP_KERNEL);
		if (!e->data)
			goto err_cl_cache;
		e->valid = false;
		e->dirty = false;
	}

	/* Allocate compression buffer */
	q->comp_buf = kvmalloc(LZ4_compressBound(q->cluster_size), GFP_KERNEL);
	if (!q->comp_buf)
		goto err_cl_cache;

	/* Allocate read buffer for compressed data */
	q->read_buf = kvmalloc(LZ4_compressBound(q->cluster_size), GFP_KERNEL);
	if (!q->read_buf) {
		kvfree(q->comp_buf);
		q->comp_buf = NULL;
		goto err_cl_cache;
	}

	/* Allocate refcount cache entries */
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++) {
		struct lbd_refcount_cache_entry *e = &q->refcount_cache[i];

		e->entries = kvmalloc(q->cluster_size, GFP_KERNEL);
		if (!e->entries)
			goto err_refcount_cache;
		e->valid = false;
		e->dirty = false;
	}

	/* Load refcount table from disk if present */
	if (q->incompatible_features & LBD_QCOW2_FEAT_REFCOUNTS) {
		size_t rt_bytes = (size_t)q->refcount_table_clusters * sizeof(u64);
		__be64 *disk_rt;

		q->refcount_table = kvmalloc_array(q->refcount_table_clusters,
						   sizeof(u64), GFP_KERNEL);
		if (!q->refcount_table)
			goto err_refcount_cache;

		disk_rt = kvmalloc(rt_bytes, GFP_KERNEL);
		if (!disk_rt) {
			kvfree(q->refcount_table);
			q->refcount_table = NULL;
			goto err_refcount_cache;
		}

		pos = q->refcount_table_offset;
		ret = kernel_read(dev->backing_file, disk_rt, rt_bytes, &pos);
		if (ret != (ssize_t)rt_bytes) {
			pr_err("lbd%d: refcount table read failed\n",
			       dev->index);
			kvfree(disk_rt);
			kvfree(q->refcount_table);
			q->refcount_table = NULL;
			goto err_refcount_cache;
		}

		for (i = 0; i < (int)q->refcount_table_clusters; i++)
			q->refcount_table[i] = be64_to_cpu(disk_rt[i]);
		kvfree(disk_rt);
	}

	/* Determine next_snapshot_id from existing snapshots */
	if (q->snapshot_count > 0) {
		loff_t snap_pos = q->snapshot_table_offset;
		u8 entry_hdr[LBD_QCOW2_SNAP_FIXED_SIZE];
		u32 max_id = 0;

		for (i = 0; i < (int)q->snapshot_count; i++) {
			u32 snap_id;
			u16 name_len;
			u32 total_entry;

			pos = snap_pos;
			ret = kernel_read(dev->backing_file, entry_hdr,
					  LBD_QCOW2_SNAP_FIXED_SIZE, &pos);
			if (ret != LBD_QCOW2_SNAP_FIXED_SIZE)
				break;

			snap_id = _qcow2_get32(entry_hdr, 0);
			name_len = _qcow2_get16(entry_hdr, 24);
			if (snap_id > max_id)
				max_id = snap_id;

			total_entry = LBD_QCOW2_SNAP_FIXED_SIZE + name_len;
			total_entry = (total_entry + 7) & ~7U;
			snap_pos += total_entry;
		}
		q->next_snapshot_id = max_id + 1;
	} else {
		q->next_snapshot_id = 1;
	}

	pr_info("lbd%d: qcow2-lz4 format detected, virtual_size=%llu, "
		"cluster_size=%u, l1_size=%u\n",
		dev->index, q->virtual_size, q->cluster_size, q->l1_size);

	return 0;

err_refcount_cache:
	kvfree(q->refcount_table);
	q->refcount_table = NULL;
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++)
		kvfree(q->refcount_cache[i].entries);
	kvfree(q->read_buf);
	kvfree(q->comp_buf);
err_cl_cache:
	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++)
		kvfree(q->cl_cache[i].data);
err_l2_cache:
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++)
		kvfree(q->l2_cache[i].table);
	kvfree(q->l1_table);
	q->l1_table = NULL;
	return -ENOMEM;
}

void lbd_qcow2_destroy(struct lbd_device *dev)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	int i;

	/* Flush any dirty L2 entries */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &q->l2_cache[i];

		if (e->valid && e->dirty)
			lbd_qcow2_l2_flush(dev, e);
	}

	/* Flush refcount cache and write refcount table */
	if (q->refcount_table) {
		lbd_qcow2_refcount_cache_flush(dev);
		lbd_qcow2_write_refcount_table(dev);
	}

	/* Write final alloc_offset and free_list_head */
	lbd_qcow2_write_alloc_offset(dev);
	lbd_qcow2_write_free_list_head(dev);

	/* Free refcount resources */
	for (i = 0; i < LBD_QCOW2_REFCOUNT_CACHE_SIZE; i++)
		kvfree(q->refcount_cache[i].entries);
	kvfree(q->refcount_table);
	q->refcount_table = NULL;

	kvfree(q->read_buf);
	kvfree(q->comp_buf);

	for (i = 0; i < LBD_QCOW2_CL_CACHE_SIZE; i++)
		kvfree(q->cl_cache[i].data);
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++)
		kvfree(q->l2_cache[i].table);

	kvfree(q->l1_table);
	q->l1_table = NULL;
}

/* ----------------------------------------------------------------
 * Read path
 * ---------------------------------------------------------------- */

int lbd_qcow2_read(struct lbd_device *dev, struct request *rq)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct req_iterator iter;
	struct bio_vec bvec;
	loff_t guest_offset = (loff_t)blk_rq_pos(rq) << SECTOR_SHIFT;

	rq_for_each_segment(bvec, rq, iter) {
		void *mapped;
		unsigned int remaining = bvec.bv_len;
		unsigned int bv_off = bvec.bv_offset;

		mapped = kmap_local_page(bvec.bv_page);

		while (remaining > 0) {
			u64 cluster_idx = guest_offset >> q->cluster_bits;
			u32 off_in_cluster = guest_offset & (q->cluster_size - 1);
			u32 bytes = min_t(u32, remaining,
					  q->cluster_size - off_in_cluster);
			struct lbd_cl_cache_entry *ce;

			down_read(&q->rwsem);

			ce = lbd_qcow2_cl_load(dev, cluster_idx);
			if (!ce) {
				up_read(&q->rwsem);
				kunmap_local(mapped);
				return -EIO;
			}

			memcpy(mapped + bv_off, ce->data + off_in_cluster,
			       bytes);

			up_read(&q->rwsem);

			bv_off += bytes;
			guest_offset += bytes;
			remaining -= bytes;
		}

		kunmap_local(mapped);
	}

	atomic64_inc(&dev->stat_reads);
	atomic64_add(blk_rq_bytes(rq), &dev->stat_read_bytes);
	return 0;
}

/* ----------------------------------------------------------------
 * Write path
 * ---------------------------------------------------------------- */

int lbd_qcow2_write(struct lbd_device *dev, struct request *rq)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct req_iterator iter;
	struct bio_vec bvec;
	loff_t guest_offset = (loff_t)blk_rq_pos(rq) << SECTOR_SHIFT;
	u32 total_len = blk_rq_bytes(rq);
	void *write_data;
	size_t offset = 0;

	/* Gather all write data into contiguous buffer */
	write_data = kvmalloc(total_len, GFP_NOIO);
	if (!write_data)
		return -ENOMEM;

	rq_for_each_segment(bvec, rq, iter) {
		void *mapped = kmap_local_page(bvec.bv_page);
		memcpy(write_data + offset, mapped + bvec.bv_offset,
		       bvec.bv_len);
		kunmap_local(mapped);
		offset += bvec.bv_len;
	}

	down_write(&q->rwsem);

	offset = 0;
	while (offset < total_len) {
		u64 cluster_idx = guest_offset >> q->cluster_bits;
		u32 off_in_cluster = guest_offset & (q->cluster_size - 1);
		u32 bytes = min_t(u32, total_len - offset,
				  q->cluster_size - off_in_cluster);
		struct lbd_cl_cache_entry *ce;
		struct lbd_l2_cache_entry *l2e;
		u32 l1_idx = cluster_idx / q->l2_entries;
		u32 l2_idx = cluster_idx % q->l2_entries;
		int comp_len;
		loff_t phys;
		ssize_t ret;
		int err;
		u64 old_l2_entry;
		u64 old_alloc, new_alloc;

		/* COW L2 table if shared with snapshot */
		err = lbd_qcow2_l2_cow_if_needed(dev, l1_idx);
		if (err) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return err;
		}

		/* Ensure L2 table is allocated */
		err = lbd_qcow2_l2_alloc(dev, l1_idx);
		if (err) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return err;
		}

		/* Load existing cluster into cache (or zeros if new) */
		ce = lbd_qcow2_cl_load(dev, cluster_idx);
		if (!ce) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return -EIO;
		}

		/* Read old L2 entry before modifying */
		l2e = lbd_qcow2_l2_get(dev, l1_idx);
		if (!l2e) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return -EIO;
		}
		old_l2_entry = l2e->table[l2_idx];
		old_alloc = lbd_qcow2_read_old_alloc_size(dev, old_l2_entry);

		/* Apply write data to cluster */
		memcpy(ce->data + off_in_cluster, write_data + offset, bytes);

		/* Compress the full cluster */
		comp_len = LZ4_compress_fast_extState(
			dev->lz4_state, ce->data, q->comp_buf,
			q->cluster_size,
			LZ4_compressBound(q->cluster_size), 1);

		if (comp_len > 0 &&
		    (u32)comp_len < q->cluster_size - sizeof(__be32)) {
			/* Store compressed */
			__be32 comp_size_be = cpu_to_be32(comp_len);
			new_alloc = ALIGN(sizeof(__be32) + comp_len, 4096);

			if (old_l2_entry & LBD_QCOW2_L2_COW) {
				/* Shared with snapshot — must COW */
				err = lbd_qcow2_alloc_space(dev, new_alloc,
							    &phys);
				if (err) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return err;
				}
			} else if (old_alloc > 0 && new_alloc <= old_alloc) {
				phys = old_l2_entry & LBD_QCOW2_L2_OFFSET_MASK;
				atomic64_inc(&dev->stat_alloc_reused);
			} else {
				if (old_alloc > 0) {
					loff_t old_phys = old_l2_entry &
						LBD_QCOW2_L2_OFFSET_MASK;
					err = lbd_qcow2_free_extent(dev,
						old_phys, old_alloc);
					if (err) {
						up_write(&q->rwsem);
						kvfree(write_data);
						return err;
					}
				}
				err = lbd_qcow2_alloc_space(dev, new_alloc,
							    &phys);
				if (err) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return err;
				}
			}

			/* Write size header + compressed data */
			{
				loff_t pos = phys;
				ret = kernel_write(dev->backing_file,
						   &comp_size_be,
						   sizeof(comp_size_be), &pos);
				if (ret != sizeof(comp_size_be)) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return ret < 0 ? ret : -EIO;
				}

				ret = kernel_write(dev->backing_file,
						   q->comp_buf, comp_len,
						   &pos);
				if (ret != comp_len) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return ret < 0 ? ret : -EIO;
				}
			}

			/* Clear COW flag on new entry */
			l2e->table[l2_idx] = LBD_QCOW2_L2_COMPRESSED | phys;
			l2e->dirty = true;
			atomic64_inc(&dev->stat_compressed);
		} else {
			/* Store uncompressed */
			new_alloc = q->cluster_size;

			if (old_l2_entry & LBD_QCOW2_L2_COW) {
				/* Shared with snapshot — must COW */
				err = lbd_qcow2_alloc_space(dev, new_alloc,
							    &phys);
				if (err) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return err;
				}
			} else if (old_alloc > 0 && new_alloc <= old_alloc) {
				phys = old_l2_entry & LBD_QCOW2_L2_OFFSET_MASK;
				atomic64_inc(&dev->stat_alloc_reused);
			} else {
				if (old_alloc > 0) {
					loff_t old_phys = old_l2_entry &
						LBD_QCOW2_L2_OFFSET_MASK;
					err = lbd_qcow2_free_extent(dev,
						old_phys, old_alloc);
					if (err) {
						up_write(&q->rwsem);
						kvfree(write_data);
						return err;
					}
				}
				err = lbd_qcow2_alloc_space(dev, new_alloc,
							    &phys);
				if (err) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return err;
				}
			}

			{
				loff_t pos = phys;
				ret = kernel_write(dev->backing_file,
						   ce->data, q->cluster_size,
						   &pos);
				if (ret != q->cluster_size) {
					up_write(&q->rwsem);
					kvfree(write_data);
					return ret < 0 ? ret : -EIO;
				}
			}

			l2e->table[l2_idx] = phys;
			l2e->dirty = true;
			atomic64_inc(&dev->stat_uncompressed);
		}

		/* Flush L2 to disk */
		err = lbd_qcow2_l2_flush(dev, l2e);
		if (err) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return err;
		}

		/* Update alloc_offset on disk */
		err = lbd_qcow2_write_alloc_offset(dev);
		if (err) {
			up_write(&q->rwsem);
			kvfree(write_data);
			return err;
		}

		offset += bytes;
		guest_offset += bytes;
	}

	up_write(&q->rwsem);
	kvfree(write_data);
	return 0;
}

/* ----------------------------------------------------------------
 * TRIM path
 * ---------------------------------------------------------------- */

int lbd_qcow2_discard(struct lbd_device *dev, struct request *rq)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	loff_t guest_offset = (loff_t)blk_rq_pos(rq) << SECTOR_SHIFT;
	u32 remaining = blk_rq_bytes(rq);
	int err;

	down_write(&q->rwsem);

	while (remaining > 0) {
		u64 cluster_idx = guest_offset >> q->cluster_bits;
		u32 off_in_cluster = guest_offset & (q->cluster_size - 1);
		u32 bytes = min_t(u32, remaining,
				  q->cluster_size - off_in_cluster);
		u32 l1_idx = cluster_idx / q->l2_entries;
		u32 l2_idx = cluster_idx % q->l2_entries;
		struct lbd_l2_cache_entry *l2e;

		/* COW L2 table if shared with snapshot */
		err = lbd_qcow2_l2_cow_if_needed(dev, l1_idx);
		if (err) {
			up_write(&q->rwsem);
			return err;
		}

		if (off_in_cluster == 0 && bytes == q->cluster_size) {
			/* Full-cluster trim */
			if (l1_idx < q->l1_size &&
			    q->l1_table[l1_idx] != 0) {
				l2e = lbd_qcow2_l2_get(dev, l1_idx);
				if (l2e && l2e->table[l2_idx] != 0) {
					u64 old_l2 = l2e->table[l2_idx];

					if (!(old_l2 & LBD_QCOW2_L2_COW)) {
						/* Not shared: free old extent */
						u64 old_sz = lbd_qcow2_read_old_alloc_size(
								dev, old_l2);
						if (old_sz > 0) {
							loff_t old_phys = old_l2 &
								LBD_QCOW2_L2_OFFSET_MASK;
							lbd_qcow2_free_extent(dev,
								old_phys, old_sz);
						}
					}
					/* COW-flagged: don't free, snapshot refs it */
					l2e->table[l2_idx] = 0;
					l2e->dirty = true;
					err = lbd_qcow2_l2_flush(dev, l2e);
					if (err) {
						up_write(&q->rwsem);
						return err;
					}
				}
			}
			lbd_qcow2_cl_invalidate(q, cluster_idx);
		} else {
			/* Partial-cluster trim: read-modify-write */
			struct lbd_cl_cache_entry *ce;

			err = lbd_qcow2_l2_alloc(dev, l1_idx);
			if (err) {
				up_write(&q->rwsem);
				return err;
			}

			ce = lbd_qcow2_cl_load(dev, cluster_idx);
			if (!ce) {
				up_write(&q->rwsem);
				return -EIO;
			}

			l2e = lbd_qcow2_l2_get(dev, l1_idx);
			if (!l2e) {
				up_write(&q->rwsem);
				return -EIO;
			}

			if (l2e->table[l2_idx] == 0) {
				goto next;
			}

			/* Zero the trimmed portion */
			memset(ce->data + off_in_cluster, 0, bytes);

			/* Recompress and write back */
			{
				int comp_len;
				loff_t phys;
				ssize_t ret;
				u64 old_l2 = l2e->table[l2_idx];
				u64 old_alloc = lbd_qcow2_read_old_alloc_size(
						dev, old_l2);
				u64 new_alloc;

				comp_len = LZ4_compress_fast_extState(
					dev->lz4_state, ce->data, q->comp_buf,
					q->cluster_size,
					LZ4_compressBound(q->cluster_size), 1);

				if (comp_len > 0 &&
				    (u32)comp_len < q->cluster_size - sizeof(__be32)) {
					__be32 comp_size_be = cpu_to_be32(comp_len);
					new_alloc = ALIGN(sizeof(__be32) + comp_len, 4096);

					if (old_l2 & LBD_QCOW2_L2_COW) {
						err = lbd_qcow2_alloc_space(dev,
							new_alloc, &phys);
						if (err) {
							up_write(&q->rwsem);
							return err;
						}
					} else if (old_alloc > 0 && new_alloc <= old_alloc) {
						phys = old_l2 & LBD_QCOW2_L2_OFFSET_MASK;
						atomic64_inc(&dev->stat_alloc_reused);
					} else {
						if (old_alloc > 0) {
							loff_t old_phys = old_l2 &
								LBD_QCOW2_L2_OFFSET_MASK;
							lbd_qcow2_free_extent(dev,
								old_phys, old_alloc);
						}
						err = lbd_qcow2_alloc_space(dev,
							new_alloc, &phys);
						if (err) {
							up_write(&q->rwsem);
							return err;
						}
					}

					{
						loff_t pos = phys;
						ret = kernel_write(dev->backing_file,
								   &comp_size_be,
								   sizeof(comp_size_be), &pos);
						if (ret != sizeof(comp_size_be)) {
							up_write(&q->rwsem);
							return ret < 0 ? ret : -EIO;
						}
						ret = kernel_write(dev->backing_file,
								   q->comp_buf, comp_len,
								   &pos);
						if (ret != comp_len) {
							up_write(&q->rwsem);
							return ret < 0 ? ret : -EIO;
						}
					}

					l2e->table[l2_idx] = LBD_QCOW2_L2_COMPRESSED | phys;
					atomic64_inc(&dev->stat_compressed);
				} else {
					new_alloc = q->cluster_size;

					if (old_l2 & LBD_QCOW2_L2_COW) {
						err = lbd_qcow2_alloc_space(dev,
							new_alloc, &phys);
						if (err) {
							up_write(&q->rwsem);
							return err;
						}
					} else if (old_alloc > 0 && new_alloc <= old_alloc) {
						phys = old_l2 & LBD_QCOW2_L2_OFFSET_MASK;
						atomic64_inc(&dev->stat_alloc_reused);
					} else {
						if (old_alloc > 0) {
							loff_t old_phys = old_l2 &
								LBD_QCOW2_L2_OFFSET_MASK;
							lbd_qcow2_free_extent(dev,
								old_phys, old_alloc);
						}
						err = lbd_qcow2_alloc_space(dev,
							new_alloc, &phys);
						if (err) {
							up_write(&q->rwsem);
							return err;
						}
					}

					{
						loff_t pos = phys;
						ret = kernel_write(dev->backing_file,
								   ce->data, q->cluster_size,
								   &pos);
						if (ret != q->cluster_size) {
							up_write(&q->rwsem);
							return ret < 0 ? ret : -EIO;
						}
					}

					l2e->table[l2_idx] = phys;
					atomic64_inc(&dev->stat_uncompressed);
				}

				l2e->dirty = true;
				err = lbd_qcow2_l2_flush(dev, l2e);
				if (err) {
					up_write(&q->rwsem);
					return err;
				}

				err = lbd_qcow2_write_alloc_offset(dev);
				if (err) {
					up_write(&q->rwsem);
					return err;
				}
			}
		}

next:
		guest_offset += bytes;
		remaining -= bytes;
	}

	up_write(&q->rwsem);
	return 0;
}

/* ----------------------------------------------------------------
 * Base layer (thin snapshot) support
 * ---------------------------------------------------------------- */

static inline u64 lbd_qcow2_base_lru_tick(struct lbd_qcow2_base *base)
{
	return base->lru_tick++;
}

/* Find or load an L2 table from the base layer into its cache */
static struct lbd_l2_cache_entry *
lbd_qcow2_base_l2_get(struct lbd_qcow2_base *base, u32 l1_index)
{
	struct lbd_l2_cache_entry *best = NULL;
	u64 oldest = U64_MAX;
	int i;

	/* Check cache for hit */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &base->l2_cache[i];

		if (e->valid && e->l1_index == l1_index) {
			e->lru = lbd_qcow2_base_lru_tick(base);
			return e;
		}
	}

	/* Cache miss: find LRU entry to evict */
	for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
		struct lbd_l2_cache_entry *e = &base->l2_cache[i];

		if (!e->valid) {
			best = e;
			break;
		}
		if (e->lru < oldest) {
			oldest = e->lru;
			best = e;
		}
	}

	/* No dirty tracking — just overwrite on eviction */
	best->l1_index = l1_index;
	best->dirty = false;
	best->lru = lbd_qcow2_base_lru_tick(base);

	if (l1_index < base->l1_size && base->l1_table[l1_index] != 0) {
		loff_t pos = base->l1_table[l1_index];
		__be64 *disk_l2;
		ssize_t ret;
		int j;

		disk_l2 = kvmalloc(base->cluster_size, GFP_NOIO);
		if (!disk_l2) {
			best->valid = false;
			return NULL;
		}

		ret = kernel_read(base->file, disk_l2,
				  base->cluster_size, &pos);
		if (ret != base->cluster_size) {
			pr_warn("lbd: base L2 read failed for l1[%u]\n",
				l1_index);
			kvfree(disk_l2);
			best->valid = false;
			return NULL;
		}

		for (j = 0; j < base->l2_entries; j++)
			best->table[j] = be64_to_cpu(disk_l2[j]);

		kvfree(disk_l2);
	} else {
		/* Unallocated L2: all zeros */
		memset(best->table, 0, base->cluster_size);
	}

	best->valid = true;
	return best;
}

/*
 * Read a full cluster from the base layer into buf.
 * Returns 0 on success, negative errno on failure.
 */
static int lbd_qcow2_base_read_cluster(struct lbd_device *dev,
					u64 cluster_index, void *buf)
{
	struct lbd_qcow2_base *base = dev->base;
	u32 cluster_size = dev->qcow2.cluster_size;

	if (!base->is_qcow2) {
		/* Raw base: direct read */
		loff_t pos = cluster_index * cluster_size;
		ssize_t ret;

		if (pos + cluster_size > base->size) {
			memset(buf, 0, cluster_size);
			return 0;
		}

		ret = kernel_read(base->file, buf, cluster_size, &pos);
		if (ret != cluster_size) {
			pr_warn("lbd%d: base raw read failed at cluster %llu\n",
				dev->index, cluster_index);
			return ret < 0 ? ret : -EIO;
		}
		return 0;
	}

	/* qcow2 base: L1/L2 lookup */
	{
		u32 l1_idx = cluster_index / base->l2_entries;
		u32 l2_idx = cluster_index % base->l2_entries;
		struct lbd_l2_cache_entry *l2e;
		u64 l2_entry, phys_offset;
		ssize_t ret;

		l2e = lbd_qcow2_base_l2_get(base, l1_idx);
		if (!l2e)
			return -EIO;

		l2_entry = l2e->table[l2_idx];

		if (l2_entry == 0) {
			memset(buf, 0, cluster_size);
			return 0;
		}

		phys_offset = l2_entry & LBD_QCOW2_L2_OFFSET_MASK;

		if (l2_entry & LBD_QCOW2_L2_COMPRESSED) {
			__be32 comp_size_be;
			u32 comp_size;
			int dec_len;
			loff_t pos = phys_offset;

			ret = kernel_read(base->file, &comp_size_be,
					  sizeof(comp_size_be), &pos);
			if (ret != sizeof(comp_size_be)) {
				pr_warn("lbd%d: base compressed size read failed\n",
					dev->index);
				return ret < 0 ? ret : -EIO;
			}

			comp_size = be32_to_cpu(comp_size_be);
			if (comp_size > LZ4_compressBound(cluster_size)) {
				pr_warn("lbd%d: base invalid compressed size %u\n",
					dev->index, comp_size);
				return -EIO;
			}

			ret = kernel_read(base->file, base->read_buf,
					  comp_size, &pos);
			if (ret != comp_size) {
				pr_warn("lbd%d: base compressed data read failed\n",
					dev->index);
				return ret < 0 ? ret : -EIO;
			}

			dec_len = LZ4_decompress_safe(base->read_buf, buf,
						      comp_size, cluster_size);
			if (dec_len != cluster_size) {
				pr_warn("lbd%d: base LZ4 decompress failed (%d)\n",
					dev->index, dec_len);
				return -EIO;
			}
		} else {
			/* Uncompressed cluster */
			loff_t pos = phys_offset;

			ret = kernel_read(base->file, buf,
					  cluster_size, &pos);
			if (ret != cluster_size) {
				pr_warn("lbd%d: base cluster read failed\n",
					dev->index);
				return ret < 0 ? ret : -EIO;
			}
		}
	}

	return 0;
}

int lbd_qcow2_base_init(struct lbd_device *dev, const char *path)
{
	struct lbd_qcow2 *q = &dev->qcow2;
	struct lbd_qcow2_base *base;
	struct file *f;
	struct inode *inode, *primary_inode;
	u64 magic;
	loff_t pos;
	ssize_t ret;
	int i;

	f = filp_open(path, O_RDONLY | O_LARGEFILE, 0);
	if (IS_ERR(f)) {
		pr_err("lbd%d: cannot open base file '%s': %ld\n",
		       dev->index, path, PTR_ERR(f));
		return PTR_ERR(f);
	}

	inode = file_inode(f);
	if (!S_ISREG(inode->i_mode)) {
		pr_err("lbd%d: base path must be a regular file\n",
		       dev->index);
		fput(f);
		return -EINVAL;
	}

	if (i_size_read(inode) == 0) {
		pr_err("lbd%d: base file is empty\n", dev->index);
		fput(f);
		return -EINVAL;
	}

	/* Base and primary must be different files */
	primary_inode = file_inode(dev->backing_file);
	if (inode->i_sb == primary_inode->i_sb &&
	    inode->i_ino == primary_inode->i_ino) {
		pr_err("lbd%d: base and primary must be different files\n",
		       dev->index);
		fput(f);
		return -EINVAL;
	}

	base = kzalloc(sizeof(*base), GFP_KERNEL);
	if (!base) {
		fput(f);
		return -ENOMEM;
	}

	base->file = f;
	base->lru_tick = 0;

	/* Detect raw vs qcow2 via magic */
	pos = 0;
	ret = kernel_read(f, &magic, 8, &pos);
	if (ret != 8) {
		pr_err("lbd%d: cannot read base file header\n", dev->index);
		kfree(base);
		fput(f);
		return ret < 0 ? ret : -EIO;
	}

	if (be64_to_cpu(magic) == LBD_QCOW2_MAGIC) {
		/* qcow2 base */
		u8 *hdr;
		__be64 *disk_l1;

		base->is_qcow2 = true;

		hdr = kvmalloc(LBD_QCOW2_HEADER_SIZE, GFP_KERNEL);
		if (!hdr) {
			kfree(base);
			fput(f);
			return -ENOMEM;
		}

		pos = 0;
		ret = kernel_read(f, hdr, LBD_QCOW2_HEADER_SIZE, &pos);
		if (ret != LBD_QCOW2_HEADER_SIZE) {
			pr_err("lbd%d: base qcow2 header read failed\n",
			       dev->index);
			kvfree(hdr);
			kfree(base);
			fput(f);
			return ret < 0 ? ret : -EIO;
		}

		if (lbd_qcow2_hdr_version(hdr) != LBD_QCOW2_VERSION) {
			pr_err("lbd%d: base qcow2 version mismatch (%u)\n",
			       dev->index, lbd_qcow2_hdr_version(hdr));
			kvfree(hdr);
			kfree(base);
			fput(f);
			return -EINVAL;
		}

		base->cluster_bits = lbd_qcow2_hdr_cluster_bits(hdr);
		if (base->cluster_bits != q->cluster_bits) {
			pr_err("lbd%d: base cluster_bits %u != primary %u\n",
			       dev->index, base->cluster_bits, q->cluster_bits);
			kvfree(hdr);
			kfree(base);
			fput(f);
			return -EINVAL;
		}

		base->cluster_size = 1U << base->cluster_bits;
		base->l2_entries = base->cluster_size / sizeof(u64);
		base->size = lbd_qcow2_hdr_virtual_size(hdr);
		base->l1_offset = lbd_qcow2_hdr_l1_table_offset(hdr);
		base->l1_size = lbd_qcow2_hdr_l1_size(hdr);

		kvfree(hdr);

		/* Validate virtual size matches primary */
		if (base->size != q->virtual_size) {
			pr_err("lbd%d: base virtual_size %llu != primary %llu\n",
			       dev->index, base->size, q->virtual_size);
			kfree(base);
			fput(f);
			return -EINVAL;
		}

		/* Load L1 table */
		base->l1_table = kvmalloc_array(base->l1_size, sizeof(u64),
						GFP_KERNEL);
		if (!base->l1_table) {
			kfree(base);
			fput(f);
			return -ENOMEM;
		}

		disk_l1 = kvmalloc_array(base->l1_size, sizeof(__be64),
					 GFP_KERNEL);
		if (!disk_l1) {
			kvfree(base->l1_table);
			kfree(base);
			fput(f);
			return -ENOMEM;
		}

		pos = base->l1_offset;
		ret = kernel_read(f, disk_l1,
				  base->l1_size * sizeof(__be64), &pos);
		if (ret != base->l1_size * sizeof(__be64)) {
			pr_err("lbd%d: base L1 table read failed\n",
			       dev->index);
			kvfree(disk_l1);
			kvfree(base->l1_table);
			kfree(base);
			fput(f);
			return ret < 0 ? ret : -EIO;
		}

		for (i = 0; i < base->l1_size; i++)
			base->l1_table[i] = be64_to_cpu(disk_l1[i]);
		kvfree(disk_l1);

		/* Allocate L2 cache tables */
		for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++) {
			struct lbd_l2_cache_entry *e = &base->l2_cache[i];

			e->table = kvmalloc(base->cluster_size, GFP_KERNEL);
			if (!e->table)
				goto err_l2_cache;
			e->valid = false;
			e->dirty = false;
		}

		/* Allocate read buffer for decompression */
		base->read_buf = kvmalloc(LZ4_compressBound(base->cluster_size),
					  GFP_KERNEL);
		if (!base->read_buf)
			goto err_l2_cache;
	} else {
		/* Raw base */
		base->is_qcow2 = false;
		base->size = i_size_read(inode);

		/* Validate size matches primary */
		if (base->size != q->virtual_size) {
			pr_err("lbd%d: base size %llu != primary virtual_size %llu\n",
			       dev->index, base->size, q->virtual_size);
			kfree(base);
			fput(f);
			return -EINVAL;
		}
	}

	dev->base = base;
	pr_info("lbd%d: base layer attached (%s, %llu bytes)\n",
		dev->index, base->is_qcow2 ? "qcow2-lz4" : "raw",
		base->size);
	return 0;

err_l2_cache:
	if (base->is_qcow2) {
		kvfree(base->read_buf);
		for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++)
			kvfree(base->l2_cache[i].table);
		kvfree(base->l1_table);
	}
	kfree(base);
	fput(f);
	return -ENOMEM;
}

void lbd_qcow2_base_destroy(struct lbd_qcow2_base *base)
{
	int i;

	if (base->is_qcow2) {
		kvfree(base->read_buf);
		for (i = 0; i < LBD_QCOW2_L2_CACHE_SIZE; i++)
			kvfree(base->l2_cache[i].table);
		kvfree(base->l1_table);
	}

	fput(base->file);
	kfree(base);
}
