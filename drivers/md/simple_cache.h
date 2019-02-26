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

#define SC_CACHE_RECLAIM_INTERVAL (10 * HZ)

enum sc_rc_action {
	SC_RCA_NOP,
	SC_RCA_CLEAN,
	SC_RCA_RECLAIM,
};

enum sc_rc_state {
	SC_RC_RD = 0,
	SC_RC_WB,
	SC_RC_LOG,
	SC_RC_COMPLETE,
};

struct sc_rc_io {
	struct list_head wblist;
	struct sc_cache_info *sci;
	struct sc_backing_dev *scbd;
	unsigned long bb, cb;
	struct page **pages;
	struct bio *bio;
	int nr;
	enum sc_rc_state state;
	enum sc_rc_action action;
	struct work_struct async_work;
};

enum sc_ra_state {
	SC_RA_READ_BACKING,
	SC_RA_WRITE_CACHING,
	SC_RA_LOG,
	SC_RA_COMPLETE,
};

struct sc_ra_io {
	struct sc_cache_info *sci;
	struct sc_backing_dev *scbd;
	unsigned long bb, cb;
	struct page **pages;
	struct bio *bio;
	int nr;
	enum sc_ra_state state;
	struct work_struct async_work;
};

/*
 *
 *31  22 21       2 1 0
 * |----|-------- -|-|
 *
 * 31:22    access count
 * 21:3     in-flight IO (512K IO at the same time is enougth )
 * 2:0 		state
 *
 * 0 		readahead
 * 1 		clean
 * 2 		dirty
 * 3 		cleaning
 * 4 		reclaiming
 *
 */

struct sc_cache_info {
	struct {
		uint32_t status;
		unsigned long atime; /* last access time in jiffies */
		unsigned short upper_hc;
		unsigned short flags;
		rwlock_t rwlock;
	}  ____cacheline_aligned_in_smp;
	int bb;
	int cb;
	struct sc_rc_io *wb_rcio; /* for interrupt the wb and
				     the size of sc_cache_info is
				     added again, this is not good*/
	struct llist_head pending_list; /* readahead, dirty log */
};

enum sci_state {
	SCI_READAHEAD = 0,
	SCI_CLEAN,
	SCI_DIRTY,
	SCI_CLEANING,
	SCI_RECLAIMING,
};

#define SCI_STATE(i) (i & 0x7)
#define SCI_INFLIGHT(i) ((i & 0x3fffff) >> 3)
#define SCI_HIT_COUNT(i) (i >> 22)
#define SCI(a, f, s) \
	(((a & 0x3ff) << 22) | ((f & 0x7ffff) << 3) | s)

static inline void sci_read_lock(struct sc_cache_info *sci)
{
	read_lock(&sci->rwlock);
}

static inline void sci_read_unlock(struct sc_cache_info *sci)
{
	read_unlock(&sci->rwlock);
}

/*
 * We use rwlock instead of rcu because both sides are in
 * hot path. synchronize_rcu is very expensive.
 */
static inline void sci_sync(struct sc_cache_info *sci)
{
	write_lock(&sci->rwlock);
	write_unlock(&sci->rwlock);
}

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
	/*
	 * FIXME:
	 *   Needn't this depth for every slot
	 */
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
	struct sc_cache_info **scis; /* sc_cache_info array */
	int scis_arrary_len;
	unsigned long scis_total;
	unsigned long cb_offset;
	wait_queue_head_t wait_invalidate;

	/*
	 * TODO
	 *   Fields about wb and rc should be moved to a separated structure.
	 */
	spinlock_t wb_lock;
	struct list_head wb_pending;
	struct work_struct wb_work;
	atomic_t rcio_running; 
	wait_queue_head_t rcio_wait;
	struct delayed_work	reclaim_work;

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
	struct sc_cache_info *sci;
	int start_time;
	struct llist_node node;
	bool started;
};

struct sc_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct sc_backing_dev *, char *);
	ssize_t (*store)(struct sc_backing_dev *, const char *, size_t);
};

/*
 * caching and backing block mapping
 *
 * 31                 2 1 0
 * |-------------------|--|
 * \________ _________/ 
 *          V
 *     caching lba
 *
 * bit 31 ~ 2 	backing device lba in block_size 
 * bit 1 ~ 0 	entry flags
 *
 * bit 0	valid/invalid
 * bit 1	dirty/clean
 *
 * When the block size is 64K, the largest capacity of backing
 * device is 64T (2^46)
 * Every available cache block has an 4 bytes entry.
 * Metadata size = (caching_capability/block_size) * 4 bytes
 * 
 * Caching capacity    Block size    Metadata size
 *            256G           512K     2M
 *            256G            64K    16M
 *             32G            64K     2M
 *
 * Mapping update log entry
 * 
 * 31              8 7 3 2 0
 * |----------------|---|--|
 * 
 * bit 31 ~ 8 	caching device lba in block_size
 *              most capacity of caching device is 1T and smallest
 *              block is 64K, so we need 24 bits for address at least.
 * bit 7 ~ 3 	generation number, every round of the log ring is a
 * 		generation.
 * bit 2 ~ 0 	opcode
 *
 * opcode
 * 0 		mapping set
 * 1 		mapping clear
 * 2 		dirty set
 * 3 		drity clear
 * 4        nop
 * 5 ~ 7 	reserved
 *
 * The mapping log area is 2 times of mapping entry array.
 * So we have 2 log rings. When one is full, we switch to another one
 * with generation + 1, then start to use the previous one to patch
 * mapping entry array. When patch is completed, we need to update the
 * super block generation field.
 *
 * Metadata is reserved after the super block sector as following.
 *
 *             +--------+ superblock sector (1 sector)
 *             +--------+ padding for PAGE_SIZE alignement
 *             +--------+
 *             |        | mapping
 *             +--------+
 *             |        | log rings
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
 */

#define SC_DEFAULT_CACHE_BLOCK_SIZE 131072 /* 128K Bytes */
#define SC_MAPPING_FIRST_PAGE_OFFSET (512 / SC_CACHE_MAPPING_ENTRY_SIZE)
#define SC_MAPPING_START PAGE_SECTORS
struct sc_entry {
	uint32_t data;
};

#define SC_CACHE_MAPPING_ENTRY_SIZE sizeof(struct sc_entry) /* Bytes */
#define SC_MAPPING_ENTRIES_PER_PAGE (PAGE_SIZE / SC_CACHE_MAPPING_ENTRY_SIZE)

typedef struct sc_entry sc_entry_t;

#define SC_ENTRY_BLOCK_SHIFT 2
#define SC_ENTRY_FLAGS_DIRTY_SHIFT 1
#define SC_ENTRY_FLAGS_VALID_SHIFT 0


#define SC_ENTRY_DIRTY(e) (e & (1 << SC_ENTRY_FLAGS_DIRTY_SHIFT))
#define SC_ENTRY_VALID(e) (e & (1 << SC_ENTRY_FLAGS_VALID_SHIFT))

/*
 * This is the backing device block
 */
#define SC_ENTRY_BLOCK(e) (e >> SC_ENTRY_BLOCK_SHIFT)
#define SC_ENTRY_LBA(e, sb) ((e >> SC_ENTRY_BLOCK_SHIFT) << (sb->bitsbsz2sc))
#define SC_ENTRY_CONSTRUCT(bb, d, v) \
    ((bb << SC_ENTRY_BLOCK_SHIFT) | (d << SC_ENTRY_FLAGS_DIRTY_SHIFT) | v)

struct sc_log {
	uint32_t data;
};
typedef struct sc_log sc_log_t;

#define SC_LOG_ENTRIES_PER_PAGE (PAGE_SIZE / sizeof(struct sc_log))
#define SC_LOG_OP_MAP_SET 0
#define SC_LOG_OP_MAP_CLEAN 1
#define SC_LOG_OP_DIRTY_SET 2
#define SC_LOG_OP_DIRTY_CLEAN 3
#define SC_LOG_OP_NOP 4

#define SC_LOG_BLOCK_SHIFT 8
#define SC_LOG_GEN_SHIFT 3

/*
 * This is the caching device block
 */
#define SC_LOG_BLOCK(l) (l >> SC_LOG_BLOCK_SHIFT)
#define SC_LOG_GEN(l) ((l & ((1 << SC_LOG_BLOCK_SHIFT) - 1)) >> SC_LOG_GEN_SHIFT)
#define SC_LOG_OPCODE(l) (l & ((1 << SC_LOG_GEN_SHIFT)- 1))
/*
 * The block here is the cache device's lba.
 * We reserve the head part as sb and metadata,
 * so the block here mustn't be zero.
 */
#define SC_LOG_VALID(l) SC_LOG_BLOCK(l)

#define SC_LOG_CONSTRUCT(cb, g, o) \
    ((cb << SC_LOG_BLOCK_SHIFT) | (g << SC_LOG_GEN_SHIFT) | o)

#define SC_MAGIC_NUMBER 0x53435342
/*
 * In-core mapping array
 * This mapping array is indexed by backing device lba
 * and saves the caching device lba. This is reverse with
 * the on-disk mapping.
 * We use a linear array here which is inefficient in memory,
 * but we could do lockless search and update.
 *
 * Most capacity of caching device is 1T
 * Smallest block size is 64K
 * So we need 24 bits at most for caching block.
 *
 *                cblock
 *          ________^ _________
 *         /                   \
 * |-------|-------------------|
 * \___ __/
 *     v
 *   flags
 * 31 ~ 24  flags
 *   31     allocating
 *
 * 23 ~ 0   cblock
 */
#define SC_CACHE_ENTRY_CB_ALLOCATING (1 << 31)
#define SC_CACHE_ENTRY_ALLOCATING(e) (e & SC_CACHE_ENTRY_CB_ALLOCATING)
#define SC_CACHE_ENTRY_CB_BITS 24
#define SC_CACHE_ENTRY_CB(e) (e & ((1 << SC_CACHE_ENTRY_CB_BITS) - 1))

struct sc_cache_entry {
	uint32_t cb; /* caching device block */
};

#define SC_CACHE_ENTRY_SIZE sizeof(struct sc_cache_entry)
#define SC_CACHE_ENTRIES_PER_PAGE (PAGE_SIZE / SC_CACHE_ENTRY_SIZE)

enum sc_log_replay {
    SC_LOG_REPLAY_NOTHING = 0,
    SC_LOG_REPLAY_PATCH,
    SC_LOG_REPLAY_RUN,
};

typedef void (*log_done_fn_t)(void *);

struct sc_log_item {
	struct llist_node node;
	struct sc_log_sb *sl;
	uint8_t op;
	uint32_t cb;
	uint32_t bb; /* for SET op to save bblock */
	log_done_fn_t log_done;
	void *private;
};

#define SL_RUN(sl) (sl->toggle)
#define SL_PATCH(sl) (sl->toggle ^ 1)

struct sc_log_sb {
	struct sc_sb *sb;
	sector_t log_start[2]; /* sectors */
	sector_t log_offset[2]; /* sectors */
	sector_t log_len;
	int toggle;
	struct page *log_page;
	int log_page_offset; /* sc_log_t */

	struct llist_head list;
	struct work_struct insert_work;

	bool patch;
	struct work_struct patch_work;

	struct block_device *dev;
	wait_queue_head_t waitq;
};

/*
 * In-core scache super block
 */
struct sc_sb {
	struct sc_backing_dev *scbd;
	uint32_t 	block_size;
	uint8_t 	bitsbsz2sc; /* bits need to shift to convert
				       from block_size to sector or reverse */
	sector_t 	bszmask;
	unsigned long scblkmask;
	uint64_t 	maplen; /* Bytes, length of all metadata, sb and mapping,
				 block_size aligned */
	uint8_t 	mapping_gen;
	uint8_t 	run_gen;
	uint8_t 	patch_gen;
	struct page 	*sb_page; /* super block is contained in it */
	struct page 	**map_pages; /* cache of on-disk mapping array
					we keep them in memory just for patching
					and this looks inefficient */
	struct sc_cache_entry **mappings; /* in-core mapping array 
					     we will allocate it page by page,
					     then it will be easier to get */
	int 		bmaplen;
	int 		max_bb;
	struct 		sc_log_sb log;
};

/*
 * On-disk scache super block which locates on 1st sector of caching device
 */
struct sc_d_sb {
	__u32 		sc_magic; /* SC_MAGIC_NUMBER */
	__u64 		csum;
	__u32 		block_size; /* Bytes */
	__u64 		maplen; /* Bytes, length of mapping array */
	__u8 		gen; /* generation of mapping entry array */
};

#endif
