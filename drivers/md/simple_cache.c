#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <asm/local.h>
#include <linux/blk-mq.h>
#include <linux/log2.h>

#include "simple_cache.h"

/*
 * kobject of the /sys/fs/sc
 */
static struct kobject *sc_sysfs_kobj;
static int sc_major;
static DEFINE_IDA(sc_minor);
struct kmem_cache *sc_io_cache;

/*
 * List containing all of the sc_backing_dev.
 */
static LIST_HEAD(sc_all_backing_dev);
/*
 * Protect list sc_all_backing_dev
 */
static struct mutex sc_all_backing_dev_lock;

static sc_entry_t *sc_get_mapping_entry(struct sc_backing_dev *scbd, sector_t sec);

static void sc_start_io_acct(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct bio *bio = sio->front_bio;
	int rw = bio_data_dir(bio);

	generic_start_io_acct(scbd->front_queue, rw,
			bio_sectors(bio), &scbd->front_disk->part0);

	/*
	 * An IO could be submitted on cpu A and completed on cpu B,
	 * the inflight_io is balanced across all of the cpus, therefore
	 * raw_smp_processor_id() is OK here.
	 */
	local_inc(per_cpu_ptr(scbd->inflight_io, raw_smp_processor_id()));
	sio->start_time = jiffies;
}

static void sc_end_io_acct(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct bio *bio = sio->front_bio;
	int rw = bio_data_dir(bio);

	generic_end_io_acct(scbd->front_queue, rw,
				    &scbd->front_disk->part0, sio->start_time);

	local_dec(per_cpu_ptr(scbd->inflight_io, raw_smp_processor_id()));

	if (unlikely(waitqueue_active(&scbd->wait_compl)))
		wake_up(&scbd->wait_compl);
}

static int sc_in_flight(struct sc_backing_dev *scbd)
{
	int cpu;
	int sum = 0;

	for_each_possible_cpu(cpu)
		sum += local_read(per_cpu_ptr(scbd->inflight_io, cpu));

	return sum;
}

/*
 * If we use TASK_INTERRUPTIBLE, hung task detector cannot find
 * the hung here.
 */
static void sc_wait_for_completion(struct sc_backing_dev *scbd)
{
	DEFINE_WAIT(wait);

	while (1) {
		prepare_to_wait(&scbd->wait_compl, &wait, TASK_UNINTERRUPTIBLE);

		if (!sc_in_flight(scbd))
			break;

		io_schedule();
	}
	finish_wait(&scbd->wait_compl, &wait);
}

static struct sc_io *alloc_sc_io(struct sc_backing_dev *scbd, struct bio *bio)
{
	struct sc_io *sio;
	gfp_t gfp_mask = bio->bi_opf & REQ_NOWAIT ? 0 : GFP_NOIO;

	sio = mempool_alloc(scbd->sc_io_pool, gfp_mask);
	if (unlikely(!sio)) {
		if (!gfp_mask)
			bio_wouldblock_error(bio);
	}
	sio->scbd = scbd;
	return sio;
}

static void free_sc_io(struct sc_io *sio)
{
	mempool_free(sio, sio->scbd->sc_io_pool);
}

static int sc_io_init(struct sc_io *sio)
{
	bio_init(&sio->clone, NULL, 0);

	return 0;
}

static void sio_passthrough_end(struct bio *clone)
{
	struct sc_io *sio = container_of(clone, struct sc_io, clone);
	struct bio *bio = sio->front_bio;

	sc_end_io_acct(sio);

	bio->bi_status = clone->bi_status;
	bio_endio(bio);
	free_sc_io(sio);
}

static blk_qc_t sc_passthrough(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct bio *clone = &sio->clone;
	struct bio *bio = sio->front_bio;

	__bio_clone_fast(clone, bio);
	/*
	 * The backing device could just be a partition
	 */
	bio_set_dev(clone, scbd->backing_dev);
	clone->bi_end_io = sio_passthrough_end;
	clone->bi_private = sio;

	return submit_bio(clone);
}

void sc_writeback_end(struct bio *clone)
{
	struct sc_io *sio = clone->bi_private;
	struct sc_backing_dev *scbd = sio->scbd;
	struct bio *bio = sio->front_bio;
	sc_entry_t *entry;

	sc_end_io_acct(sio);

	bio->bi_status = clone->bi_status;
	if (!bio->bi_status && op_is_write(bio_op(bio))) {
		entry = sc_get_mapping_entry(scbd, bio->bi_iter.bi_sector);

	}
	bio_endio(bio);
	free_sc_io(sio);
}

static bool sc_cache_clear(struct sc_cache_info *sci)
{
	unsigned long new, old;

	old = READ_ONCE(sci->status);
	while (1) {
		if (SC_CACHE_INFO_INFLIGHT(old))
			return false;

		new = SC_CACHE_INFO(SC_CACHE_INFO_LAST(old),
							SC_CACHE_INFO_AVG(old),
							SC_CACHE_INFO_INFLIGHT(old),
							0, 1);
		old = cmpxchg(&sci->status, old, new);
		if (old == new)
			return true;
	}
}

static bool sc_cache_invalidate(struct sc_cache_info *sci)
{
	unsigned long new, old;

	old = READ_ONCE(sci->status);
	while (1) {
		/*
		 * We can only invalidate clear cache block
		 */
		if (SC_CACHE_INFO_INFLIGHT(old) ||
			SC_CACHE_INFO_DIRTY(old))
			return false;

		new = SC_CACHE_INFO(0, 0, 1, 0, 0);
		old = cmpxchg(&sci->status, old, new);
		if (old == new)
			return true;
	}
}

static unsigned long sc_calc_new(unsigned long old)
{
	unsigned int now, last, avg, inv, inflight;

	now = jiffies;
	last = SC_CACHE_INFO_LAST(old);
	inv = now - last;
	inflight = SC_CACHE_INFO_LAST(old);
	avg = SC_CACHE_INFO_AVG(old);
	avg *= 8;
	avg += inv;
	avg /= 8;
	last = now;
	inflight++;

	return SC_CACHE_INFO(last, avg, inflight, 1, 1);
}

void sc_wait_invalidate(struct sc_backing_dev *scbd,
		struct sc_cache_info *sci)
{
	wait_event(&scbd->wait_invalidate,
			!SC_CACHE_INFO_INFLIGHT(READ_ONCE(sci->status)));
}

static bool sc_cache_access(struct sc_backing_dev *scbd,
		struct sc_cache_info *sci)
{
	unsigned long old, new;

	old = READ_ONCE(sci->status);
	while (1) {
		if (!SC_CACHE_INFO_VALID(old)) {
			if (SC_CACHE_INFO_INFLIGHT(old)) {
				/*
				 * Before invalidate a cache block, the average of access interval
				 * and last access time has been checked, so this should not be
				 * a frequent case.
				 */
				pr_info("Accessing a cache block with being invalidated %lx\n",
						sci->block);
				sc_wait_invalidate(scbd, sci);
			}
			return false;
		}

		/*
		 * dirty and valid bits are set
		 */
		new = sc_calc_new(old);
		/*
		 * May race with GC reclaim or concurrent submits and completions.
		 */
		old = cmpxchg(&sci->status, old, new);
		/*
		 * We wins.
		 */
		if (old == new)
			return true;
	}
}

static bool sc_cache_alloc(struct sc_backing_dev *scbd,
		sc_entry_t *se, int block)
{
	/*
	 * Update the se to indicate we are allocating, then
	 * others would go to sleep to wait.
	 *
	 * So we need a bit that shows allocating.
	 */
}

static blk_qc_t sc_writeback(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct sc_sb *sb = scbd->sb;
	struct bio *clone = &sio->clone;
	struct bio *bio = sio->front_bio;
	sector_t offset = bio->bi_iter.bi_sector;
	sc_entry_t *e;

	e = sc_get_mapping_entry(scbd, offset);
	if (SC_CACHE_VALID(READ_ONCE(e->data))) {
	
		/*
		 * Cache hit, write to cache directly
		 */
		__bio_clone_fast(clone, bio);
		clone->bi_iter.bi_sector =
			SC_CACHE_LBA(READ_ONCE(e->data), sb) + (offset - (offset & sb->bszmask));
		bio_set_dev(clone, scbd->caching_dev);
		//clone->bi_end_io = sio_writeback_end;
		clone->bi_private = sio;
		submit_bio(clone);
	}
	return BLK_QC_T_NONE;
}

static blk_qc_t sc_make_request(struct request_queue *q, struct bio *bio)
{
	struct sc_backing_dev *scbd = q->queuedata;
	struct sc_io *sio;
	blk_qc_t ret;

	/*
	 * split the bio based on the cache mapping block size,
	 * then we will only have cache hit or miss cases and don't
	 * need to consider cache hit/miss partially.
	 */
	blk_queue_split(q, &bio);

	sio = alloc_sc_io(scbd, bio);
	if (unlikely(!sio))
		return BLK_QC_T_NONE;

	sc_io_init(sio);
	/*
	 * Note, we mustn't do any modification on the original bio
	 */
	sio->front_bio = bio;

	sc_start_io_acct(sio);
	switch(READ_ONCE(scbd->mode)) {
	case SC_CACHE_PASSTHROUGH:
		ret = sc_passthrough(sio);
		break;
	case SC_CACHE_WRITETHROUGH:
	case SC_CACHE_WRITEBACK:
		ret = BLK_QC_T_NONE;
		break;
	default:
		BUG();
		break;
	}

	return ret;
}

static int sc_blkdev_open(struct block_device *b, fmode_t mode)
{
	return 0;
}

static void sc_blkdev_release(struct gendisk *b, fmode_t mode)
{
}

static int sc_blkdev_ioctl(struct block_device *b, fmode_t mode,
		     unsigned int cmd, unsigned long arg)
{
	return 0;
}


static const struct block_device_operations sc_ops = {
	.open		= sc_blkdev_open,
	.release	= sc_blkdev_release,
	.ioctl		= sc_blkdev_ioctl,
	.owner		= THIS_MODULE,
};

static ssize_t
sc_bd_attr_show(struct kobject *kobj, struct attribute *attr, char *buf)
{
	struct sc_sysfs_entry *entry = container_of(attr, struct sc_sysfs_entry, attr);
	struct sc_backing_dev *scbd =	container_of(kobj, struct sc_backing_dev, kobj);
	ssize_t res;

	if (!entry->show)
		return -EIO;
	mutex_lock(&scbd->sysfs_lock);
	res = entry->show(scbd, buf);
	mutex_unlock(&scbd->sysfs_lock);
	return res;
}

static ssize_t
sc_bd_attr_store(struct kobject *kobj, struct attribute *attr,
		    const char *buf, size_t len)
{
	struct sc_sysfs_entry *entry = container_of(attr, struct sc_sysfs_entry, attr);
	struct sc_backing_dev *scbd =	container_of(kobj, struct sc_backing_dev, kobj);
	ssize_t res;

	if (!entry->store)
		return -EIO;

	mutex_lock(&scbd->sysfs_lock);
	res = entry->store(scbd, buf, len);
	mutex_unlock(&scbd->sysfs_lock);
	return res;
}

static void sc_bd_release(struct kobject *kobj)
{
	struct sc_backing_dev *scbd =	container_of(kobj, struct sc_backing_dev, kobj);

	ida_simple_remove(&sc_minor, scbd->minor);
	mempool_destroy(scbd->sc_io_pool);
	free_percpu(scbd->inflight_io);
	mutex_destroy(&scbd->sysfs_lock);
	kfree(scbd);
	return;
}

static const struct sysfs_ops sc_bd_sysfs_ops = {
	.show	= sc_bd_attr_show,
	.store	= sc_bd_attr_store,
};

void sc_block_wait(struct sc_backing_dev *scbd)
{
	DEFINE_WAIT(wait);

	while (1) {
		prepare_to_wait(&scbd->wait_block, &wait, TASK_UNINTERRUPTIBLE);
		if (READ_ONCE(scbd->slot_available))
			break;
		io_schedule();
	}
	finish_wait(&scbd->wait_block, &wait);
}
/*
 * This is a very special interface which can only be invoked
 * by sc_setup_cache before writeabck mode starts. Nobody would
 * race with us at the moment.
 *
 * TODO:
 *  - noone races with use, so needn't to use atomic primitives.
 */
static void sc_block_set(struct sc_backing_dev *scbd, int block)
{
	int depth = scbd->slots[0].depth;
	int i = block / depth;
	unsigned long *map = scbd->slots[i].map;
	int nr = block % depth;

	set_bit(nr % BITS_PER_LONG, &map[nr / BITS_PER_LONG]);
	if (!atomic_dec_return(&scbd->slots[i].available))
		clear_bit(i, &scbd->slot_available);
}

/*
 * TODO:
 *  - allocate hint
 *  - we need to try best to scatter different cpu to different slot
 *  - make the depth is power2, then just need to shift
 */
static int sc_block_alloc(struct sc_backing_dev *scbd)
{
	int slot, nr, depth;
	unsigned long *map;

retry:
	slot = find_next_zero_bit(&scbd->slot_available, BITS_PER_LONG, 0);
	if (slot >= BITS_PER_LONG) {
		sc_block_wait(scbd);
		goto retry;
	}

	smp_mb__before_atomic();
	if (!atomic_add_unless(&scbd->slots[slot].available, -1, 0))
		goto retry;

	/*
	 * See comments in sc_block_free
	 */
	smp_mb__after_atomic();
	map = scbd->slots[slot].map;
	depth = scbd->slots[slot].depth;
	while (1) {
		/*
		 * find_next_zero_bit support array, but test_and_set_bit not.
		 */
		nr = find_next_zero_bit(map, depth, 0);
		BUG_ON(nr >= depth);

		if (!test_and_set_bit(nr % BITS_PER_LONG,
					&map[nr / BITS_PER_LONG]))
			break;
	}

	return slot * depth + nr;
}

static void sc_block_free(struct sc_backing_dev *scbd, int block)
{
	int depth = scbd->slots[0].depth;
	int i = block / depth;
	unsigned long *map = scbd->slots[i].map;
	int nr = block % depth;

	clear_bit(nr % BITS_PER_LONG, &map[nr / BITS_PER_LONG]);
	/*
	 * Ensure the bit set in map is visible before we add the available
	 */
	smp_mb__before_atomic();
	if (atomic_inc_return(&scbd->slots[i].available) == 1) {
		/*
		 * Ensure the slot available is visible before we set
		 * the slot_available.
		 */
		smp_mb__before_atomic();
		set_bit(i, &scbd->slot_available);
	}

	if (waitqueue_active(&scbd->wait_block))
		wake_up(&scbd->wait_block);
}

static int sc_blocks_allocator_init(struct sc_backing_dev *scbd)
{
	int i;
	struct sc_sb *sb = scbd->sb;
	uint64_t depth, slot;
	sector_t caching_size = part_nr_sects_read(scbd->caching_dev->bd_part);

	depth = round_down((caching_size << 9), sb->block_size);
	depth -= round_up(sb->mlen, sb->block_size);
	depth /= sb->block_size;

	scbd->scis = kzalloc(sizeof(struct sc_cache_info) * depth, GFP_KERNEL);
	if (!scbd->scis) {
		pr_err("Failed to allocate sc_cache_info array\n");
		return -ENOMEM;
	}
	pr_info("available blocks in caching device %llu\n", depth);

	slot = depth / SC_MAX_BITMAP_SLOTS;
	for (i = 0; i < SC_MAX_BITMAP_SLOTS - 1; i++) {
		scbd->slots[i].depth = slot;
		atomic_set(&scbd->slots[i].available, slot);
	}
	pr_info("blocks per slot is %lld\n", slot);

	slot = round_up(slot, BITS_PER_LONG);
	slot /= BITS_PER_LONG;
	for (i = 0; i < SC_MAX_BITMAP_SLOTS - 1; i++) {
		scbd->slots[i].map = kzalloc(slot, GFP_KERNEL);
		BUG_ON(!scbd->slots[i].map);
	}
	/*
	 * Last slot initialization
	 */
	slot = depth % SC_MAX_BITMAP_SLOTS;
	scbd->slots[SC_MAX_BITMAP_SLOTS - 1].depth = slot;
	atomic_set(&scbd->slots[SC_MAX_BITMAP_SLOTS - 1].available, slot);
	pr_info("blocks of last slot is %lld\n", slot);

	slot = round_up(slot, BITS_PER_LONG);
	slot /= BITS_PER_LONG;
	scbd->slots[SC_MAX_BITMAP_SLOTS - 1].map = kzalloc(slot, GFP_KERNEL);
	BUG_ON(!scbd->slots[SC_MAX_BITMAP_SLOTS - 1].map);

	scbd->slot_available = 0;
	init_waitqueue_head(&scbd->wait_block);
	init_waitqueue_head(&scbd->wait_invalidate);
	return 0;
}

static void sc_block_allocator_destroy(struct sc_backing_dev *scbd)
{
	int i;

	for (i = 0; i < SC_MAX_BITMAP_SLOTS; i++)
		kfree(scbd->slots[i].map);
}

static int sc_cache_format(struct sc_backing_dev *scbd,
		struct page *page, struct bio *bio)
{
	struct block_device *cbdev = scbd->caching_dev;
	struct sc_d_sb *dsb = page_address(page);
	uint32_t block_size = scbd->setting.block_size;
	sector_t backing_size = part_nr_sects_read(scbd->backing_dev->bd_part);
	uint64_t mlen;
	sector_t offset, end;
	int ret;

	mlen = round_up((backing_size << 9), block_size) / block_size;
	mlen *= SC_CACHE_MAPPING_ENTRY_SIZE;
	mlen += 512; /* superblock sector */
	mlen = round_up(mlen, PAGE_SIZE); /* Just for convenience of read/write */

	pr_info("backing capacity is %lu G Bytes mlen %lu M Bytes\n",
			(unsigned long)(backing_size << 9) >> 30, (unsigned long)mlen >> 20);
	pr_info("first available block is %llx\n", round_up(mlen, block_size) >> 9);

	offset = 0;
	end = mlen >> 9;

	memset((void *)dsb, 0, PAGE_SIZE);
	while (offset < end) {
		bio_init(bio, bio->bi_inline_vecs, 1);
		bio->bi_iter.bi_sector = offset;
		bio_set_dev(bio, cbdev);
		bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
		bio_add_page(bio, page, PAGE_SIZE, 0);
		ret = submit_bio_wait(bio);
		if (ret) {
			pr_err("Failed to initialize the metadata %d\n", ret);
			return ret;
		}
		offset += PAGE_SIZE;
	}

	dsb->sc_magic = cpu_to_le32(SC_MAGIC_NUMBER);
	dsb->block_size = cpu_to_le32(block_size);
	dsb->mlen = cpu_to_le64(mlen);

	bio_init(bio, bio->bi_inline_vecs, 1);
	bio->bi_iter.bi_sector = 0;
	bio_set_dev(bio, cbdev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	bio_add_page(bio, page, 512, 0);
	ret = submit_bio_wait(bio);
	if (ret)
		pr_err("Failed to write the superblock %d\n", ret);

	return ret;
}

static int sc_get_sb(struct sc_backing_dev *scbd)
{
	struct block_device *cbdev = scbd->caching_dev;
	struct bio *bio;
	struct page *page;
	struct sc_d_sb *dsb;
	struct sc_sb *sb;
	int ret = 0;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	bio = bio_alloc(GFP_KERNEL, 1);

	bio_set_dev(bio, cbdev);
	bio->bi_iter.bi_sector = 0;
	bio_add_page(bio, page, PAGE_SIZE, 0);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	ret = submit_bio_wait(bio);
	if (ret) {
		pr_err("Failed to read in sb %d\n", ret);
		goto fail;
	}

	dsb = page_address(page);

	if (le32_to_cpu(dsb->sc_magic) != SC_MAGIC_NUMBER) {
		pr_warn("This is not scache caching device and "
				"it will be formatted next.\n");
		/*
		 * The professional way should be done by userland
		 * tool and this will be done if scache goes well.
		 */
		ret = sc_cache_format(scbd, page, bio);
		if (ret)
			goto fail;
	}
	/*
	 * We need to check the checksum here.
	 */
	sb = kmalloc(sizeof(*sb), GFP_KERNEL);
	if (!sb) {
		pr_err("Failed to allocate sb\n");
		goto fail;
	}
	sb->block_size = le32_to_cpu(dsb->block_size);
	sb->bitsbsz2sc = ilog2(sb->block_size) - 9;
	sb->bszmask = ~(sb->block_size - 1);
	sb->mlen = le64_to_cpu(dsb->mlen);
	sb->first_page = page;
	scbd->sb = sb;

	bio_put(bio);
	return 0;
fail:
	bio_put(bio);
	put_page(page);
	return ret;
}

static void sc_put_sb(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;

	put_page(sb->first_page);
	kfree(sb);
}

static sc_entry_t *sc_get_mapping_entry(struct sc_backing_dev *scbd, sector_t sec)
{
	struct sc_sb *sb = scbd->sb;
	int block = sec >> sb->bitsbsz2sc;

	block += SC_MAPPING_FIRST_PAGE_OFFSET;

	return &sb->mappings[block / SC_ENTRIES_PER_PAGE][block % SC_ENTRIES_PER_PAGE];
}

struct sc_setup_mapping_data {
	atomic_t bios;
	wait_queue_head_t waitq;
};

static void sc_read_mapping_endio(struct bio *bio)
{
	struct sc_setup_mapping_data *data = bio->bi_private;

	if (!atomic_dec_return(&data->bios))
		wake_up(&data->waitq);
}

static int sc_read_mapping(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct bio *bio = NULL;
	sector_t offset;
	int i, len;
	struct sc_setup_mapping_data data;
	struct blk_plug plug;

	atomic_set(&data.bios, 0);
	init_waitqueue_head(&data.waitq);
	/*
	 * First page has been read in.
	 */
	offset = PAGE_SECTORS;
	len = sb->mlen / PAGE_SIZE - 1;
	i = 1;
	blk_start_plug(&plug);
	while (len) {
		if (!bio) {
			bio = bio_alloc(GFP_KERNEL, min_t(int, len, BIO_MAX_PAGES));
			bio_set_dev(bio, scbd->caching_dev);
			bio->bi_iter.bi_sector = offset;
			bio_set_op_attrs(bio, REQ_OP_READ, 0);
			bio->bi_end_io = sc_read_mapping_endio;
			bio->bi_private = &data;
			atomic_inc(&data.bios);
		}
		if (!bio_add_page(bio, sb->map_pages[i], PAGE_SIZE, 0)) {
			submit_bio(bio);
			bio = NULL;
			continue;
		}
		offset += PAGE_SECTORS;
		len -= 1;
		i += 1;
	}
	if (bio)
		submit_bio(bio);
	blk_finish_plug(&plug);
	wait_event(data.waitq, !atomic_read(&data.bios));

	return 0;
}

static int sc_handle_mapping_early(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, len = sb->mlen / PAGE_SIZE;
	sc_entry_t *start, *end;
	struct sc_cache_info *sci;
	unsigned long cblock, bblock;

	/*
	 * Pick the used blocks out of block allocator.
	 */
	bblock = 0;
	for (i = 0; i < len; i++) {
		start = sb->mappings[i];
		end = start + SC_ENTRIES_PER_PAGE;
		if (i == 0)
			start += SC_MAPPING_FIRST_PAGE_OFFSET;
		for (; start < end; start++) {
			bblock++;
			if (SC_CACHE_VALID(READ_ONCE(start->data))) {
				cblock = SC_CACHE_BLOCK(READ_ONCE(start->data));
				sc_block_set(scbd, cblock);
				sci = &scbd->scis[cblock];
				sci->status = 1; /* valid entry */
				sci->block = bblock; /* reverse mapping */
			}
		}
	}

	return 0;
}

static int sc_setup_mapping(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, ret, len = sb->mlen / PAGE_SIZE;


	sb->map_pages = kzalloc(sizeof(void *) * len, GFP_KERNEL);
	if (!sb->map_pages) {
		pr_err("Failed to allocate map_pages\n");
		return -ENOMEM;
	}
	sb->mappings = kzalloc(sizeof(void *) * len, GFP_KERNEL);
	if (!sb->mappings) {
		pr_err("Failed to allocate mappings\n");
		ret = -ENOMEM;
		goto fail_mappings;
	}

	sb->map_pages[0] = sb->first_page;
	sb->mappings[0] = page_address(sb->first_page);
	for (i = 1; i < len; i++) {
		sb->map_pages[i] = alloc_page(GFP_KERNEL);
		if (!sb->map_pages[i]) {
			pr_err("Failed to allocate map pages\n");
			for (; i > 0; i--)
				put_page(sb->map_pages[i]);
			ret = -ENOMEM;
			goto fail_pages;
		}
		sb->mappings[i] = page_address(sb->map_pages[i]);
	}

	ret = sc_read_mapping(scbd);

	ret = sc_handle_mapping_early(scbd);

fail_pages:
	kfree(sb->mappings);
fail_mappings:
	kfree(sb->map_pages);
	return ret;
}

static void sc_destroy_mapping(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, len = sb->mlen / PAGE_SIZE;
	/*
	 * The dirty mapping should have been written out to disk
	 * First page is freed by sc_put_sb
	 */
	for (i = 1; i < len; i++)
		put_page(sb->map_pages[i]);
	kfree(sb->mappings);
	kfree(sb->map_pages);
}

static int sc_setup_cache(struct sc_backing_dev *scbd)
{
	int ret;

	ret = sc_get_sb(scbd);
	if (ret)
		goto out;

	ret = sc_blocks_allocator_init(scbd);
	if (ret)
		goto fail_ba;

	ret = sc_setup_mapping(scbd);
	/*
	 * writeabck is ready
	 */

	return ret;

fail_ba:
	sc_put_sb(scbd);
out:
	return ret;
}

static ssize_t sc_bd_cache_store(struct sc_backing_dev *scbd,
		const char *buf, size_t len)
{
	char *path;
	int err = len;
	struct block_device *bdev;

	if (READ_ONCE(scbd->caching_dev)) {
		pr_warn("A caching device has been attched\n");
		return -EINVAL;
	}
	path = kstrndup(buf, len, GFP_KERNEL);
	if (!path) {
		pr_err("Failed to allocate buffer for the path");
		err = -ENOMEM;
		goto fail;
	}

	bdev = blkdev_get_by_path(strim(path),
			FMODE_READ|FMODE_WRITE|FMODE_EXCL, scbd);
	if (IS_ERR(bdev)) {
		pr_err("Failed to open block device %s\n", strim(path));
		err = PTR_ERR(bdev);
		goto fail_bdev;
	}

	scbd->caching_dev = bdev;
	err = bd_link_disk_holder(bdev, scbd->front_disk);
	if (err) {
		pr_err("Failed to link caching and front\n");
		goto fail_link_holder;
	}
	err = sc_setup_cache(scbd);
	if (!err) {
		/*
		 * This is the successful path
		 */
		err = len;
		goto fail_bdev;
	}

	bd_unlink_disk_holder(bdev, scbd->front_disk);
fail_link_holder:
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
fail_bdev:
	kfree(path);
fail:
	return err;
}

static void sc_turndown_cache(struct sc_backing_dev *scbd)
{
	/*
	 * Flush dirty metadata into disk
	 */
	/*
	 * Free mapping data
	 */
	sc_destroy_mapping(scbd);
	/*
	 * Free writeabck data
	 */
	/*
	 * Free freespace managment data
	 */
	sc_block_allocator_destroy(scbd);
}

static ssize_t sc_bd_stop_store(struct sc_backing_dev *scbd,
		const char *buf, size_t len)
{
	if (!READ_ONCE(scbd->caching_dev)) {
		pr_warn("Caching device has been detached\n");
		return -EINVAL;
	}
	/*
	 * Start write through mod
	 * then we could delete the caching device transparently
	 */

	/*
	 * Flush all of the pending and in-flight IO on backing and caching device
	 */

	sc_turndown_cache(scbd);

	sc_put_sb(scbd);

	bd_unlink_disk_holder(scbd->caching_dev, scbd->front_disk);
	blkdev_put(scbd->caching_dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	scbd->caching_dev = NULL;

	/*
	 * Need some sync method against the hot path
	 */
	return len;
}

static struct sc_sysfs_entry sc_bd_cache = {
	.attr = {.name = "cache", .mode = S_IWUSR },
	.store = sc_bd_cache_store,
};

static struct sc_sysfs_entry sc_bd_stop = {
	.attr = {.name = "stop", .mode = S_IWUSR },
	.store = sc_bd_stop_store,
};

static struct attribute *default_attrs[] = {
	&sc_bd_cache.attr,
	&sc_bd_stop.attr,
	NULL
};

struct kobj_type sc_bd_ktype = {
	.sysfs_ops	= &sc_bd_sysfs_ops,
	.default_attrs	= default_attrs,
	.release	= sc_bd_release,
};

static struct sc_backing_dev *sc_backing_dev_lookup_and_del(struct block_device *bdev)
{
	struct sc_backing_dev *scbd;

	mutex_lock(&sc_all_backing_dev_lock);
	list_for_each_entry(scbd, &sc_all_backing_dev, list) {
		if (scbd->backing_dev == bdev) {
			list_del_init(&scbd->list);
			mutex_unlock(&sc_all_backing_dev_lock);
			return scbd;
		}
	}
	mutex_unlock(&sc_all_backing_dev_lock);
	return NULL;
}

static void sc_backing_dev_add(struct sc_backing_dev *scbd)
{
	mutex_lock(&sc_all_backing_dev_lock);
	list_add(&scbd->list, &sc_all_backing_dev);
	mutex_unlock(&sc_all_backing_dev_lock);
}

static int sc_backing_init(struct sc_backing_dev *scbd)
{
	int ret = 0;
	int minor;
	sector_t backing_size;
	struct gendisk *front_disk;
	struct request_queue *q;

	INIT_LIST_HEAD(&scbd->list);
	mutex_init(&scbd->sysfs_lock);
	scbd->mode = SC_CACHE_PASSTHROUGH;
	init_waitqueue_head(&scbd->wait_compl);
	scbd->setting.block_size = SC_DEFAULT_CACHE_BLOCK_SIZE;

	scbd->inflight_io = alloc_percpu(local_t);
	if (!scbd->inflight_io) {
		pr_err("Failed to allocate inflight_io\n");
		return -ENOMEM;
	}

	minor = ida_simple_get(&sc_minor, 0, MINORMASK + 1, GFP_KERNEL);
	if (minor < 0) {
		pr_err("Failed to get minor\n");
		goto fail_ida;
	}
	scbd->minor = minor;
	scbd->sc_io_pool = mempool_create_slab_pool(SC_IO_POOL_MAX, sc_io_cache);
	if (!scbd->sc_io_pool) {
		pr_err("Failed to create sc io pool\n");
		ret = -ENOMEM;
		goto fail_create_iopool;
	}

	front_disk = alloc_disk(SC_MINORS);
	if (!front_disk) {
		pr_err("Failed to create front disk\n");
		ret = -ENOMEM;
		goto fail_create_fd;
	}

	backing_size = part_nr_sects_read(scbd->backing_dev->bd_part);
	set_capacity(front_disk, backing_size);
	snprintf(front_disk->disk_name, DISK_NAME_LEN, "sc%i", minor * SC_MINORS);

	front_disk->major = sc_major;
	front_disk->first_minor = minor * SC_MINORS;
	front_disk->fops = &sc_ops;
	front_disk->private_data = scbd;

	scbd->front_disk = front_disk;

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		pr_err("Failed to allocate request_queue\n");
		ret = -ENOMEM;
		goto fail_alloc_q;
	}

	front_disk->queue = q;
	q->queuedata = scbd;
	scbd->front_queue = q;
	blk_queue_make_request(q, sc_make_request);

	/*
	 * default block size is 512
	 */
	blk_set_stacking_limits(&q->limits);

	queue_flag_set_unlocked(QUEUE_FLAG_NONROT,	q);
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD,	q);
	queue_flag_clear_unlocked(QUEUE_FLAG_ADD_RANDOM, q);
	blk_queue_write_cache(q, true, true);

	add_disk(front_disk);

	kobject_init(&scbd->kobj, &sc_bd_ktype);
	ret = kobject_add(&scbd->kobj, &disk_to_dev(front_disk)->kobj, "sc");
	if (ret) {
		pr_err("Failed to add scbd's kobj\n");
		goto fail_add_kobj;
	}

	ret = bd_link_disk_holder(scbd->backing_dev, front_disk);
	if (ret) {
		pr_err("Failed to link holer for backing and front\n");
		goto fail_link_holder;
	}
	sc_backing_dev_add(scbd);

	return 0;
fail_link_holder:
	kobject_del(&scbd->kobj);
fail_add_kobj:
	blk_cleanup_queue(q);
fail_alloc_q:
	del_gendisk(front_disk);
fail_create_fd:
	mempool_destroy(scbd->sc_io_pool);
fail_create_iopool:
	ida_simple_remove(&sc_minor, minor);
fail_ida:
	free_percpu(scbd->inflight_io);
	return ret;
}

static ssize_t sc_sysfs_add_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buffer, size_t size)
{
	char *path;
	struct block_device *bdev;
	struct sc_backing_dev *scbd;
	int err;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

	path = kstrndup(buffer, size, GFP_KERNEL);
	if (!path) {
		pr_err("Failed to allocate buffer for the path");
		err = -ENOMEM;
		goto fail;
	}
	
	scbd = kzalloc(sizeof(*scbd), GFP_KERNEL);
	if (!scbd) {
		pr_err("Failed to allocate sc_backing_dev");
		err = -ENOMEM;
		goto fail_scbd;
	}

	bdev = blkdev_get_by_path(strim(path),
			FMODE_READ|FMODE_WRITE|FMODE_EXCL, scbd);
	if (IS_ERR(bdev)) {
		pr_err("Failed to open block device %s\n", strim(path));
		err = PTR_ERR(bdev);
		goto fail_bdev;
	}

	scbd->backing_dev = bdev;

	err = sc_backing_init(scbd);
	if (err) {
		goto fail_scbd_init;
	} else {
		/*
		 * Successful path here
		 */
		err = size;
		goto fail_scbd;
	}
fail_scbd_init:
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
fail_bdev:
	kfree(scbd);
fail_scbd:
	kfree(path);
fail:
	return err;
}
SC_SYSFS_ATTR_WO(add, sc_sysfs_add_store);

static ssize_t sc_sysfs_del_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buffer, size_t size)
{
	struct sc_backing_dev *scbd;
	char *path;
	struct block_device *bdev;
	int err = size;
	bool caching;

	path = kstrndup(buffer, size, GFP_KERNEL);
	BUG_ON(!path);
	bdev = lookup_bdev(strim(path));
	if (IS_ERR(bdev)) {
		pr_err("Failed to get block_device of %s\n", path);
		err = PTR_ERR(bdev);
		goto fail;
	}

	scbd = sc_backing_dev_lookup_and_del(bdev);
	bdput(bdev);
	if (!scbd) {
		pr_err("No backing_dev for %s\n", path);
		err = -EINVAL;
		goto fail;
	}

	mutex_lock(&scbd->sysfs_lock);
	caching = (scbd->caching_dev != NULL);
	mutex_unlock(&scbd->sysfs_lock);
	if (caching) {
		sc_backing_dev_add(scbd);
		pr_err("Forbid to del backing dev w/o detaching caching dev\n");
		err = -EINVAL;
		goto fail;
	}

	/*
	 * We should have flushed all of the dirty cache into backing device
	 * when detach the caching device.
	 * Stop new IO comming in and drain the in-flight ones.
	 */
	blk_freeze_queue_start(scbd->front_queue);
	blk_mq_freeze_queue_wait(scbd->front_queue);
	sc_wait_for_completion(scbd);

	bd_unlink_disk_holder(scbd->backing_dev, scbd->front_disk);
	kobject_del(&scbd->kobj);
	del_gendisk(scbd->front_disk);
	blk_cleanup_queue(scbd->front_queue);
	blkdev_put(bdev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	kobject_put(&scbd->kobj);
	module_put(THIS_MODULE);
fail:
	kfree(path);
	return err;
}
SC_SYSFS_ATTR_WO(del, sc_sysfs_del_store);

static const struct attribute *sc_sysfs_files[] = {
	SC_SYSFS_ATTR_PTR(add),
	SC_SYSFS_ATTR_PTR(del),
	NULL
};

static int __init sc_init(void)
{
	int ret = 0;

	mutex_init(&sc_all_backing_dev_lock);
	sc_sysfs_kobj =  kobject_create_and_add("sc", fs_kobj);
	if (!sc_sysfs_kobj) {
		pr_err("Failed to create /sys/fs/sc kobj\n");
		ret = -ENOMEM;
		goto fail;
	}
	ret = sysfs_create_files(sc_sysfs_kobj, sc_sysfs_files);
	if (ret) {
		pr_err("Failed to create attribute files\n");
		goto fail_sc_files;
	}

	sc_major = register_blkdev(0, "sc");
	if (sc_major < 0) {
		pr_err("Failed to register 'sc' blkdev\n");
		goto fail_sc_files;
	}

	sc_io_cache =  KMEM_CACHE(sc_io, 0);
	if (!sc_io_cache) {
		pr_err("Failed to create sc_io_cache\n");
		ret = -ENOMEM;
		goto fail_io_cache;
	}
	return 0;

fail_io_cache:
	unregister_blkdev(sc_major, "sc");
fail_sc_files:
	kobject_put(sc_sysfs_kobj);
fail:
	return ret;
}

static void __init sc_exit(void)
{
	kobject_put(sc_sysfs_kobj);
	unregister_blkdev(sc_major, "sc");
	mutex_destroy(&sc_all_backing_dev_lock);
}

module_init(sc_init);
module_exit(sc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianchao Wang jianchao.w.wang@oracle.com");
