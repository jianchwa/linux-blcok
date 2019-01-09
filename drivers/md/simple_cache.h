#ifndef _SIMPLE_CACHE_H_
#define _SIMPLE_CACHE_H_

#define SC_MINORS 16 /* partition support */
#define SC_IO_POOL_MAX 64
#define PAGE_SECTORS (PAGE_SIZE / 512)

#define __INIT_KOBJ_ATTR(_name, _mode, _show, _store)			\
{									\
	.attr	= { .name = __stringify(_name), .mode = _mode },	\
	.show	= _show,						\
	.store	= _store,						\
}

#define SC_SYSFS_ATTR_RW(_name, _show, _store)			\
	static struct kobj_attribute sc_sysfs_##_name =		\
			__INIT_KOBJ_ATTR(_name, 0600, _show, _store)

#define SC_SYSFS_ATTR_RO(_name, _show)			\
	static struct kobj_attribute sc_sysfs_##_name =		\
			__INIT_KOBJ_ATTR(_name, 0400, _show, NULL)

#define SC_SYSFS_ATTR_WO(_name, _store)			\
	static struct kobj_attribute sc_sysfs_##_name =		\
			__INIT_KOBJ_ATTR(_name, 0200, NULL, _store)

#define SC_SYSFS_ATTR_PTR(_name)    (&sc_sysfs_##_name.attr)

enum sc_cache_mode {
	SC_CACHE_PASSTHROUGH,
	SC_CACHE_WRITETHROUGH,
	SC_CACHE_WRITEBACK,
};

/*
 * (Assume machine is 64bit. I have to do this because I need
 * more information in 'status' field)
 *
 * 63    48 47   32 31           2 1 0
 * |-------|-------|-------------|-|-|
 *
 * 63:48    last access jiffies
 * 47:32    average access interval
 * 31:2     in-flight IO
 * 1        dirty/clear
 * 0        valid/invalid bit
 *
 * The max last access jiffies is 2^16 (32K), for a machine with HZ=1000,
 * it is about 32s. This is enougth, because a cache block must have been
 * invalidated before this. (Our GC period is less than 30s)
 */
struct sc_cache_info {
	unsigned long status;
	unsigned long block; /* block of backing device */
};

#define SC_CACHE_INFO_VALID(i) (i & 0x1)
#define SC_CACHE_INFO_DIRTY(i) (i & 0x2)
#define SC_CACHE_INFO_INFLIGHT(i) ((i & 0xffffffff) >> 2)
#define SC_CACHE_INFO_LAST(i) (i >> 48)
#define SC_CACHE_INFO_AVG(i) ((i >> 32) & 0xffff)
#define SC_CACHE_INFO(l, a, f, d, i) \
	((l << 48) | ((a << 32) & 0xffff) | \
	 ((f & 0xffffffff) << 2) | \
	 (d << 1) | i)

/*
 * Process of reclaim a cache block
 *        clear dirty
 *             |
 *             v
 *   write cache out to backing
 *             |
 *             v
 *         invalidate     (invalid & inflight io)
 *             |              \
 *             v              |
 *    update mapping to disk   > new update to the same entry will be blocked
 *             |              |
 *             v              /
 *       free cache block
 */

#define SC_MAX_BITMAP_SLOTS (BITS_PER_LONG)

/*
 * bit value
 *     0        available
 *     1        used
 */
struct sc_bitmap_slot {
	unsigned long *map;
	int hint;
	int depth;
	atomic_t available;
};

/*
 * Setting that could be changed by sysfs
 */
struct sc_cache_setting {
	uint32_t 	block_size;
};

struct sc_backing_dev {
	struct block_device *backing_dev;
	struct block_device *caching_dev;

	struct sc_sb *sb; /* superblock on caching device */

	unsigned long slot_available;
	struct sc_bitmap_slot slots[SC_MAX_BITMAP_SLOTS];
	wait_queue_head_t wait_block;
	struct sc_cache_info *scis; /* sc_cache_info array */
	wait_queue_head_t wait_invalidate;

	struct gendisk *front_disk;
	struct request_queue *front_queue;
	struct kobject kobj;
	int minor;

	struct list_head list; /* link to sc_all_backing_dev */
	struct mutex sysfs_lock; /* serialize operations from sysfs */

	mempool_t *sc_io_pool;
	enum sc_cache_mode mode;

	local_t __percpu *inflight_io;
	wait_queue_head_t wait_compl; /* for draining in-flight IO */

	struct sc_cache_setting setting;
};

struct sc_io {
	struct bio clone;
	struct sc_backing_dev *scbd;
	struct bio *front_bio;
	int start_time;
};

struct sc_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct sc_backing_dev *, char *);
	ssize_t (*store)(struct sc_backing_dev *, const char *, size_t);
};

/*
 * caching and backing block mapping
 *
 * Most capacity of caching device is 1T (2^40)
 * Smallest block size is 64K (2^16)
 *
 * So we need 24 bits per entry at most for caching device lba
 * 
 * 31                8 7             0
 * |-------------------|--------------|
 * \________ _________/ 
 *          V
 *     caching lba
 *
 * bit 31 ~ 8 	cache lba in block_size 
 * bit 7 ~ 0 	entry flags
 *
 * bit 0 	valid/invalid
 * bit 1 	dirty/clean
 *
 * others 	reserved
 *
 * Metadata size = (backing_capacity/block_size) * 4 bytes
 * 
 * Backing capacity    Block size    Metadata size
 *              1T           512K    8M
 *              1T           256K    16M
 *              1T           128K    32M
 *              1T            64K    64M
 * Metadata is reserved after the super block sector as following.
 *
 *             +--------+ superblock sector (1 sector)
 *             +--------+
 *             |        | mapping
 *             |        |
 *             +--------+ padding for block size alignement
 *             +--------+
 *             |        |
 *             |        |
 *             .        .
 *             .        . available space for caching
 *             .        .
 *             |        |
 *             +--------+
 *
 *
 */

#define SC_DEFAULT_CACHE_BLOCK_SIZE 131072 /* 128K Bytes */
#define SC_CACHE_MAPPING_ENTRY_SIZE 4 /* Bytes */
#define SC_ENTRIES_PER_PAGE (PAGE_SIZE / SC_CACHE_MAPPING_ENTRY_SIZE)
#define SC_MAPPING_FIRST_PAGE_OFFSET (512 / SC_CACHE_MAPPING_ENTRY_SIZE)

struct sc_entry {
	uint32_t data;
};

typedef struct sc_entry sc_entry_t;

#define SC_CACHE_FLAGS_SHIFT 8
#define SC_CACHE_FLAGS_VALID_SHIFT 0
#define SC_CACHE_FLAGS_DIRTY_SHIFT 1


#define SC_CACHE_VALID(e) (e & (1 << SC_CACHE_FLAGS_VALID_SHIFT))
#define SC_CACHE_DIRTY(e) (e & (1 << SC_CACHE_FLAGS_DIRTY_SHIFT))

#define SC_CACHE_BLOCK(e) (e >> SC_CACHE_FLAGS_SHIFT)
#define SC_CACHE_LBA(e, sb) ((e >> SC_CACHE_FLAGS_SHIFT) << (sb->bitsbsz2sc))


#define SC_MAGIC_NUMBER 0x53435342
/*
 * In-core scache super block
 */
struct sc_sb {
	uint32_t 	block_size;
	uint8_t 	bitsbsz2sc; /* bits need to shift to convert
				       from block_size to sector or reverse */
	sector_t 	bszmask;
	uint64_t 	mlen; /* Bytes, length of all metadata, sb and mapping,
				 block_size aligned */
	struct page 	*first_page; /* super block is contained in it */
	struct page 	**map_pages; /* include the first page */
	sc_entry_t **mappings;
};

/*
 * On-disk scache super block which locates on 1st sector of caching device
 */
struct sc_d_sb {
	__u32 		sc_magic; /* SC_MAGIC_NUMBER */
	__u64 		csum;
	__u32 		block_size; /* Bytes */
	__u64 		mlen; /* Bytes, length of all metadata */
};

#endif
