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

static struct workqueue_struct *sc_workqueue;
/*
 * List containing all of the sc_backing_dev.
 */
static LIST_HEAD(sc_all_backing_dev);
/*
 * Protect list sc_all_backing_dev
 */
static struct mutex sc_all_backing_dev_lock;

static unsigned int sc_get_mapping_entry(struct sc_backing_dev *scbd, sector_t sec);

struct sc_multi_io {
	atomic_t bios;
	wait_queue_head_t waitq;
};

static void sc_multi_io_endio(struct bio *bio)
{
	struct sc_multi_io *mio = bio->bi_private;
	if (!atomic_dec_return(&mio->bios))
		wake_up(&mio->waitq);
}

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

	sc_end_io_acct(sio);

	bio->bi_status = clone->bi_status;
	if (!bio->bi_status && op_is_write(bio_op(bio))) {

	}
	bio_endio(bio);
	free_sc_io(sio);
}

static bool sc_cache_clear(struct sc_cache_info *sci)
{
	uint64_t new, old;

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
	uint64_t new, old;

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

static unsigned long sc_calc_new(uint64_t old)
{
	uint64_t now, last, avg, inv, inflight;

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
	wait_event(scbd->wait_invalidate,
			!SC_CACHE_INFO_INFLIGHT(READ_ONCE(sci->status)));
}

static bool sc_cache_access(struct sc_backing_dev *scbd,
		struct sc_cache_info *sci)
{
	uint64_t old, new;

	old = READ_ONCE(sci->status);
	while (1) {
		if (!SC_CACHE_INFO_VALID(old)) {
			if (SC_CACHE_INFO_INFLIGHT(old)) {
				/*
				 * Before invalidate a cache block, the average of access interval
				 * and last access time has been checked, so this should not be
				 * a frequent case.
				 */
				pr_info("Accessing a cache block with being invalidated %llx\n",
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

static bool sc_cache_alloc(struct sc_backing_dev *scbd, int block)
{
	/*
	 * Update the se to indicate we are allocating, then
	 * others would go to sleep to wait.
	 *
	 * So we need a bit that shows allocating.
	 */
	return true;
}

static blk_qc_t sc_writeback(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct sc_sb *sb = scbd->sb;
	struct bio *clone = &sio->clone;
	struct bio *bio = sio->front_bio;
	sector_t offset = bio->bi_iter.bi_sector;
	unsigned int cblock;

	cblock = sc_get_mapping_entry(scbd, offset);
	if (cblock) {
	
		/*
		 * Cache hit, write to cache directly
		 */
		__bio_clone_fast(clone, bio);
#if 0
		clone->bi_iter.bi_sector =
			SC_CACHE_LBA(READ_ONCE(e->data), sb) + (offset - (offset & sb->bszmask));
#endif
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

/*
 * Sounds like awkward,
 * if we patch all, return 0
 * if we stop halfway, return the position where we stop.
 * Note, the unit is not bytes, but sc_log_t
 */
static unsigned long __sc_patch_mapping(struct sc_sb *sb, struct page **pages, int nr)
{
	sc_log_t *start, *end;
	uint32_t data;
	int i;
	unsigned long cblock;
	sc_entry_t *e;

	for (i = 0; i < nr; i++) {
		start = (sc_log_t *)page_address(pages[i]);
		end = start + SC_ENTRIES_PER_PAGE;
		for (; start < end; start++) {
			data = READ_ONCE(start->data);
			if (!SC_LOG_VALID(data)) {
				/*
				 * run   patch
				 * +--+  +--+
				 * |44|  |  |
				 * |  |  |  |
				 * +--+  +--+
				 *
				 * Replay the running log
				 */
				goto out;
			}

			if (SC_LOG_GEN(data) <= sb->gen) {
				/*
				 * run   patch
				 * +--+  +--+
				 * |55|  |44|
				 * |33|  |44|
				 * +--+  +--+
				 *
				 * sb gen
				 *   2      error
				 *   3      patch not complete
				 *   4      patch complete, need run
				 *   5      error
				 *
				 */
				goto out;
			}
			cblock = SC_LOG_BLOCK(data);
			e = (sc_entry_t *)page_address(sb->map_pages[cblock/SC_ENTRIES_PER_PAGE]);
			e += cblock % SC_ENTRIES_PER_PAGE;
			switch(SC_LOG_OPCODE(data)) {
			case SC_LOG_OP_MAP_SET:
				/*
				 * The following log entry contains the bblock
				 */
				start++;
				e->data = SC_ENTRY_CONSTRUCT(start->data, 0, 1);
				break;
			case SC_LOG_OP_MAP_CLEAN:
				e->data = 0;
				break;
			case SC_LOG_OP_DIRTY_SET:
				e->data |= 1 << SC_ENTRY_FLAGS_DIRTY_SHIFT;
				break;
			case SC_LOG_OP_DIRTY_CLEAN:
				e->data &= ~(1 << SC_ENTRY_FLAGS_DIRTY_SHIFT);
				break;
			default:
				WARN_ON(1);
				break;
			}
		}
	}
	return 0;
out:
	return (i * SC_ENTRIES_PER_PAGE) + (start - (sc_log_t *)page_address(pages[i]));
}

static unsigned long sc_patch_mapping(struct sc_log_sb *sl, int n)
{
 	int i, nr = sl->sb->block_size / PAGE_SIZE;
	sector_t start = sl->log_start[n];
	struct page **pages;
	struct bio *bio;
	unsigned long pass, ret;

	pages = kzalloc(sizeof(void *) * nr, GFP_NOIO);
	BUG_ON(pages);

	for (i = 0; i < nr; i++) {
		pages[i] = alloc_page(GFP_NOIO);
		if (!pages[i])
			break;
	}

	BUG_ON(i == 0);
	nr = i;
repeat:
	bio = bio_alloc(GFP_NOIO, nr);
	bio->bi_iter.bi_sector = start;
	bio_set_dev(bio, sl->dev);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_META | REQ_SYNC);
	for (i = 0; i < nr; i++)
		bio_add_page(bio, pages[i], PAGE_SIZE, 0);

	/*
	 * What if the caching device fall into error ?
	 * We cannot read out anything and data on backing device
	 * is stale.
	 */
	WARN_ON(submit_bio_wait(bio));

	ret = __sc_patch_mapping(sl->sb, pages, nr);
	
	bio_put(bio);
	if (ret) {
		pass = ((start - sl->log_start[n]) << 9) / SC_CACHE_MAPPING_ENTRY_SIZE;
		return pass + ret;
	}

	start += PAGE_SECTORS * nr;
	if (start < sl->log_len)
		goto repeat;

	return 0;
}

/*
 * TODO:
 *  - Need to figure out a more efficient way to do patch.
 */
static void sc_log_patch_work(struct work_struct *work)
{
	struct sc_log_sb *sl = container_of(work, struct sc_log_sb, patch_work);
	struct sc_sb *sb = sl->sb;
	sector_t start;
	int i;
	struct bio *bio;
	struct blk_plug plug;
	int len;
	struct sc_multi_io mio;
	struct sc_d_sb *sdb;

	BUG_ON(sl->log_offset[SL_PATCH(sl)] != sl->log_len);

	if (sl->patch)
		sc_patch_mapping(sl, SL_PATCH(sl));
	/*
	 * This is for the sc_log_replay_patch which wants to patch the mapping
	 * itself and do other things asynchronously.
	 */
	sl->patch = true;
	/*
	 * submit all of the patched mappings to disk
	 */
	len = sb->maplen / PAGE_SIZE;
	bio = NULL;
	atomic_set(&mio.bios, 0);
	init_waitqueue_head(&mio.waitq);
	start = PAGE_SECTORS;
	blk_start_plug(&plug);
	for (i = 0; i < len; i++) {
		if (!bio) {
			bio = bio_alloc(GFP_NOIO, BIO_MAX_PAGES);
			bio->bi_iter.bi_sector = start;
			bio_set_dev(bio, sl->dev);
			bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_META | REQ_FUA);
			bio->bi_private = &mio;
			bio->bi_end_io = sc_multi_io_endio;
			atomic_inc(&mio.bios);
		}
		if (!bio_add_page(bio, sb->map_pages[i], PAGE_SIZE, 0)) {
			submit_bio(bio);
			bio = NULL;
			continue;
		}
		start += PAGE_SECTORS;
	}
	if (bio)
		submit_bio(bio);
	blk_finish_plug(&plug);
	wait_event(mio.waitq, (!atomic_read(&mio.bios)));
	/*
	 * Update the sb patch version
	 */
	sb->gen++;
	sdb = page_address(sb->sb_page);
	sdb->gen = sb->gen;
	bio = bio_alloc(GFP_NOIO, 1);
	bio->bi_iter.bi_sector = 0;
	bio_set_dev(bio, sl->dev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_META | REQ_FUA);
	bio_add_page(bio, sb->sb_page, PAGE_SIZE, 0);
	WARN_ON(submit_bio_wait(bio));
	/*
	 * write log_offset, wakeup the waiters
	 * FIXME
	 *   Do we need a memory barrier here ?
	 */
	sl->log_offset[SL_PATCH(sl)] = 0;
	wake_up(&sl->waitq);
}

static void sc_log_insert_work(struct work_struct *work)
{
	struct sc_log_sb *sl = container_of(work, struct sc_log_sb, insert_work);
	uint32_t *addr = page_address(sl->log_page);
	int offset = sl->log_page_offset;
	struct llist_node *first, *node, *stop;
	struct sc_log_item *sli;
	struct bio *bio = &sl->log_bio;

	first = llist_del_all(&sl->list);
repeat:
	if (!first)
		return;
	stop = NULL;
	llist_for_each(node, first){
		sli = container_of(node, struct sc_log_item, node);
		/*
		 * The previous log entries will be overwritten.
		 */
		addr[offset] = sli->data;
		offset++; /* so the offset's unit is uint32_t */
		if (SC_LOG_OPCODE(sli->data) == SC_LOG_OP_MAP_SET) {
			addr[offset] = sli->bb;
			offset++;
		}
		if (offset >= SC_ENTRIES_PER_PAGE) {
			stop = node;
			offset = 0;
			break;
		}
	}
	sl->log_page_offset = offset;
	bio_init(bio, bio->bi_inline_vecs, 1);
	bio->bi_iter.bi_sector = sl->log_offset[SL_RUN(sl)] + sl->log_start[SL_RUN(sl)];
	bio_set_dev(bio, sl->dev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_FUA | REQ_META);
	bio_add_page(bio, sl->log_page, PAGE_SIZE, 0);
	WARN_ON(submit_bio_wait(bio));
	
	llist_for_each(node, first){
		sli = container_of(node, struct sc_log_item, node);
		sli->log_done(sli->private);
		if (node == stop)
			break;
	}

	/*
	 * Turn page
	 */
	if (stop) {
		sl->log_offset[SL_RUN(sl)] += PAGE_SECTORS;
		if (sl->log_offset[SL_RUN(sl)] >= sl->log_len) {
			/*
			 * Check and wait the previous patch work complete
			 */
			wait_event(sl->waitq,
				(!READ_ONCE(sl->log_offset[SL_PATCH(sl)])));
			sl->toggle ^= 1;
			queue_work(sc_workqueue, &sl->patch_work);
		}
		first = stop->next;
		goto repeat;
	}
}

static void sc_log_insert(struct sc_log_item *sli)
{
	struct sc_log_sb *sl = sli->sl;
	/*
	 * If the first one, queue the work
	 */
	if (llist_add(&sli->node, &sl->list))
		queue_work(sc_workqueue, &sl->insert_work);
}

static void sc_block_wait(struct sc_backing_dev *scbd)
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

static struct sc_cache_info *sc_get_cache_info(struct sc_backing_dev *scbd, int cblock)
{
	int sci_per_page = PAGE_SIZE / sizeof(struct sc_cache_info);

	if (cblock > scbd->scis_total)
		return NULL;
	return &scbd->scis[cblock/sci_per_page][cblock%sci_per_page];
}


static int sc_blocks_allocator_init(struct sc_backing_dev *scbd)
{
	int i;
	struct sc_sb *sb = scbd->sb;
	uint64_t depth, slot, len;
	int sci_per_page;
	sector_t caching_size = part_nr_sects_read(scbd->caching_dev->bd_part);

	depth = round_down((caching_size << 9), sb->block_size);
	depth -= round_up(sb->maplen, sb->block_size);
	depth /= sb->block_size;

	scbd->scis_total = depth;
	sci_per_page = PAGE_SIZE / sizeof(struct sc_cache_info);
	len = (depth / sci_per_page) + 1;

	scbd->scis = kzalloc(sizeof(void *) * len, GFP_KERNEL);
	if (!scbd->scis) {
		pr_err("Failed to allocate sc_cache_info array\n");
		return -ENOMEM;
	}
	scbd->scis_arrary_len = len;
	for (i = 0; i < len; i++) {
		scbd->scis[i] = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!scbd->scis[i]) {
			pr_err("Failed to allocate sc_cache_info entry\n");
			for (; i >=0; i--)
				kfree(scbd->scis[i]);
			kfree(scbd->scis);
			return -ENOMEM;
		}
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

	for (i = 0; i < scbd->scis_arrary_len; i++)
		kfree(scbd->scis[i]);
	kfree(scbd->scis);
	for (i = 0; i < SC_MAX_BITMAP_SLOTS; i++)
		kfree(scbd->slots[i].map);
}

static int sc_cache_format(struct sc_backing_dev *scbd,
		struct page *page, struct bio *bio)
{
	struct block_device *cbdev = scbd->caching_dev;
	struct sc_d_sb *dsb = page_address(page);
	uint32_t block_size = scbd->setting.block_size;
	sector_t caching_size = part_nr_sects_read(scbd->caching_dev->bd_part);
	uint64_t maplen, total;
	sector_t offset, end;
	int ret;

	maplen = round_up((caching_size << 9), block_size) / block_size;
	maplen *= SC_CACHE_MAPPING_ENTRY_SIZE;
	maplen = round_up(maplen, PAGE_SIZE); /* Just for convenience of read/write */

	total = 3 * maplen; /* 1 for mapping array, 2 for log rings */
	total += PAGE_SIZE; /* superblock sector */

	pr_info("caching capacity is %lu G Bytes maplen %lu K Bytes\n",
			(unsigned long)(caching_size << 9) >> 30, (unsigned long)maplen >> 10);
	pr_info("first available block is %llx\n", round_up(total, block_size) >> 9);

	offset = 0;
	end = total >> 9;

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
		offset += PAGE_SECTORS;
	}

	dsb->sc_magic = cpu_to_le32(SC_MAGIC_NUMBER);
	dsb->block_size = cpu_to_le32(block_size);
	dsb->maplen = cpu_to_le64(maplen);
	dsb->gen = 0;

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
	sb->maplen = le64_to_cpu(dsb->maplen);
	sb->gen = dsb->gen; /* 8bits needn't convert */
	pr_info("sb gen %d\n", sb->gen);
	sb->sb_page = page;
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

	put_page(sb->sb_page);
	kfree(sb);
}

static unsigned int sc_get_mapping_entry(
	struct sc_backing_dev *scbd, sector_t sec)
{
	struct sc_sb *sb = scbd->sb;
	int block = sec >> sb->bitsbsz2sc;
	struct sc_cache_entry *entry;

	entry = sb->mappings[block / SC_ENTRIES_PER_PAGE];

	entry += (block % SC_ENTRIES_PER_PAGE);

	return entry->cb;
}

static int sc_read_mapping(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct bio *bio = NULL;
	sector_t offset;
	int i, len;
	struct sc_multi_io mio;
	struct blk_plug plug;

	atomic_set(&mio.bios, 0);
	init_waitqueue_head(&mio.waitq);

	offset = SC_MAPPING_START;
	len = sb->maplen / PAGE_SIZE;
	i = 0;

	blk_start_plug(&plug);
	while (len) {
		if (!bio) {
			bio = bio_alloc(GFP_KERNEL, min_t(int, len, BIO_MAX_PAGES));
			bio_set_dev(bio, scbd->caching_dev);
			bio->bi_iter.bi_sector = offset;
			bio_set_op_attrs(bio, REQ_OP_READ, 0);
			bio->bi_end_io = sc_multi_io_endio;
			bio->bi_private = &mio;
			atomic_inc(&mio.bios);
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
	wait_event(mio.waitq, !atomic_read(&mio.bios));

	return 0;
}

static inline void sc_cache_entry_set(struct sc_sb *sb,
		unsigned long bblock, unsigned long cblock)
{
	struct sc_cache_entry *entry;

	entry = sb->mappings[bblock / SC_ENTRIES_PER_PAGE];
	entry += bblock % SC_ENTRIES_PER_PAGE;
	entry->cb = cblock;
}

static int sc_handle_mapping_early(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, len = sb->maplen / PAGE_SIZE;
	sc_entry_t *start, *end;
	struct sc_cache_info *sci;
	unsigned long cblock, bblock;
	bool dirty;
	uint32_t data;

	/*
	 * Pick the used blocks out of block allocator.
	 */
	cblock = 0;
	for (i = 0; i < len; i++) {
		start = page_address(sb->map_pages[i]);
		end = start + SC_ENTRIES_PER_PAGE;
		for (; start < end; start++) {
			data = READ_ONCE(start->data);
			if (SC_ENTRY_VALID(data)) {
				bblock = SC_ENTRY_BLOCK(data);
				if (bblock > sb->bmaplen/SC_CACHE_MAPPING_ENTRY_SIZE) {
					pr_err("mapping entry is corrupted, bb %lx\n", bblock);
					continue;
				}
				dirty = SC_ENTRY_DIRTY(data);
				sc_block_set(scbd, cblock);
				sci = sc_get_cache_info(scbd, cblock);
				if (!sci) {
					pr_warn("Failed to get sci when handle mapping early %lx\n", cblock);
					continue;
				}
				sci->status = SC_CACHE_INFO(0, 0, 0, dirty, 1); /* valid entry */
				sci->block = bblock; /* reverse mapping */
				sc_cache_entry_set(sb, bblock, cblock);
			}
			cblock++;
		}
	}

	return 0;
}

static int sc_setup_mapping(struct sc_backing_dev *scbd)
{
	sector_t backing_size = part_nr_sects_read(scbd->backing_dev->bd_part);
	struct sc_sb *sb = scbd->sb;
	unsigned long clen, blen;
	int i, ret = -ENOMEM;

	clen = sb->maplen / PAGE_SIZE;
	sb->map_pages = kzalloc(sizeof(void *) * clen, GFP_KERNEL);
	if (!sb->map_pages) {
		pr_err("Failed to allocate map_pages\n");
		return ret;
	}

	for (i = 0; i < clen; i++) {
		sb->map_pages[i] = alloc_page(GFP_KERNEL);
		if (!sb->map_pages[i]) {
			pr_err("Failed to allocate map pages\n");
			for (; i > 0; i--)
				put_page(sb->map_pages[i]);
			goto fail_pages;
		}
	}
	pr_info("%ld pages for mapping on disk\n", clen);
	blen = (backing_size << 9) / sb->block_size;
	blen *= SC_CACHE_MAPPING_ENTRY_SIZE;

	pr_info("Backing device capacity %ld G in-core mapping %ld K\n",
		(backing_size << 9) >> 30, blen >> 10);
	sb->bmaplen = blen;
	/*
	 * We allocate this page by page, then it would be easier to get.
	 */
	blen /= PAGE_SIZE;
	blen += 1;
	pr_info("%d 4K memory for mapping in-core\n", blen);
	sb->mappings = kzalloc(sizeof(void *) * blen, GFP_KERNEL);
	if (!sb->mappings) {
		pr_err("Failed to allocate mappings\n");
		goto fail_mappings;
	}

	for (i = 0; i < blen; i++) {
		sb->mappings[i] = kzalloc(PAGE_SIZE, GFP_KERNEL);
		if (!sb->mappings[i]) {
			pr_err("Failed to allocate mappings entries\n");
			for (; i >=0; i--)
			    kfree(sb->mappings[i]);
			goto fail_mappings;
		}
	}

	ret = sc_read_mapping(scbd);

	return 0;
fail_mappings:
	for (i = 0; i < clen; i++)
	    put_page(sb->map_pages[i]);
fail_pages:
	kfree(sb->mappings);
	return ret;
}

static void sc_destroy_mapping(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, len;
	len = sb->maplen / PAGE_SIZE;
	/*
	 * The dirty mapping should have been written out to disk
	 */
	for (i = 0; i < len; i++)
		put_page(sb->map_pages[i]);

	len = sb->bmaplen / PAGE_SIZE;

	for (i = 0; i < len; i++)
		kfree(sb->mappings[i]);

	kfree(sb->mappings);
	kfree(sb->map_pages);
}

static int sc_get_log_gen(struct sc_log_sb *sl, int *gen)
{
	struct page *page;
	struct bio *bio;
	sc_log_t *log;
	int i;

	page = alloc_page(GFP_KERNEL);
	
	for (i = 0; i < 2; i++) {
		bio = bio_alloc(GFP_KERNEL, 1);
		bio->bi_iter.bi_sector = sl->log_start[i];
		bio_set_dev(bio, sl->dev);
		bio_set_op_attrs(bio, REQ_OP_READ, REQ_META | REQ_SYNC);
		bio_add_page(bio, page, 512, 0);
		WARN_ON(submit_bio_wait(bio));
		log = page_address(page);
		gen[i] = SC_LOG_GEN(log->data);
		bio_put(bio);
	}
	put_page(page);

	return 0;
}

static void sc_log_replay_patch(struct sc_log_sb *sl, int n)
{
	sl->toggle = n ^ 1; /* toggle ^ 1 is patching one */
	sl->log_offset[SL_PATCH(sl)] = sl->log_len;

	sc_patch_mapping(sl, SL_PATCH(sl));
	sl->patch = false;

	queue_work(sc_workqueue, &sl->patch_work);
}

static void sc_log_replay_run(struct sc_log_sb *sl, int n)
{
	unsigned long ret;
	
	sl->toggle = n; /* toggle is running */

	ret = sc_patch_mapping(sl, n);
	sl->log_offset[SL_RUN(sl)] = (ret / SC_ENTRIES_PER_PAGE) * PAGE_SECTORS;
	sl->log_page_offset = ret & (~SC_ENTRIES_PER_PAGE);
}

/*
 * Most of time, the log is as following
 *
 * run   patch
 * +--+  +--+
 * |55|  |44|
 * |33|  |44|
 * +--+  +--+
 *
 * sb gen
 *   2      error
 *   3      patch not complete
 *   4      patch complete, need run
 *   5      error
 *
 * What we need to do here is:
 * 1. get the version of the two log and figure out the running
 *    and patching one through the first log entry's gen number
 * 2. patch the logs of which version is bigger than sb->gen on in-core mapping
 * 3. set the log with version sb->gen + 1 as patching log, and another as
 *    running one.
 * 4. figure out the postion we start to log in the running log
 */
static int sc_replay_log(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct sc_log_sb *sl = &sb->log;
	int gen[2], patch = -1, run = -1;

	sc_get_log_gen(sl, gen);

	pr_info("log 0 gen %d log 1 gen %d sb gen %d\n", gen[0], gen[1], sb->gen);

	if (gen[0] <= sb->gen && gen[1] <= sb->gen)
		return 0;

	if (gen[0] > sb->gen && gen[1] > sb->gen) {
		if (gen[0] == sb->gen + 1) {
			patch = 0;
			WARN_ON(gen[1] != sb->gen + 2);
			run = 1;
		} else if (gen[1] == sb->gen + 1) {
			patch = 1;
			WARN_ON(gen[0] != sb->gen + 2);
			run = 0;
		} else {
			WARN_ON(1);
		}
	}

	if (gen[0] == sb->gen) {
		WARN_ON((gen[1] != sb->gen + 1));
		run = 1;
	}

	if (gen[1] == sb->gen) {
		WARN_ON((gen[0] != sb->gen + 1));
		run = 0;
	}

	/*
	 * patch means we need to patch the whole log into mapping and
	 * need to flush them into disk asynchronously.
	 */
	if (patch >= 0)
		sc_log_replay_patch(sl, patch);

	/*
	 * run means we need to patch the log entries that have bigger
	 * gen than sb->gen and need to set the log_offset and log_page_offset.
	 */
	if (run >= 0)
		sc_log_replay_run(sl, patch);

	return 0;
}

static int sc_setup_log(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct sc_log_sb *sl = &sb->log;

	sl->sb = sb;
	sl->dev = scbd->caching_dev;
	sl->log_start[0] = (PAGE_SIZE + sb->maplen) >> 9;
	sl->log_start[1] = (PAGE_SIZE + 2 * sb->maplen) >> 9;
	sl->log_offset[0] = 0;
	sl->log_offset[1] = 0;
	init_llist_head(&sl->list);
	sl->toggle = 0;
	sl->patch = true;
	sl->log_page_offset = 0;
	sl->log_len = sb->maplen >> 9;

	INIT_WORK(&sl->insert_work, sc_log_insert_work);
	INIT_WORK(&sl->patch_work, sc_log_patch_work);
	init_waitqueue_head(&sl->waitq);

	sl->log_page = alloc_page(GFP_KERNEL);
	if (!sl->log_page) {
		pr_err("Failed to get log page\n");
		return -ENOMEM;
	}
	memset(page_address(sl->log_page), 0, PAGE_SIZE);
	return 0;
}

static void sc_destroy_log(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct sc_log_sb *sl = &sb->log;

	put_page(sl->log_page);
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
	if (ret)
		goto fail_sm;
	ret = sc_setup_log(scbd);
	if (ret)
		goto fail_log;
	ret = sc_replay_log(scbd);
	ret = sc_handle_mapping_early(scbd);
	/*
	 * writeabck is ready
	 */

	return ret;

fail_log:
	sc_destroy_mapping(scbd);
fail_sm:
	sc_block_allocator_destroy(scbd);
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
	scbd->caching_dev = NULL;
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

	sc_workqueue = alloc_workqueue("scached",
					    WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!sc_workqueue) {
		pr_err("Failed to build sc workqueue\n");
		ret = -ENOMEM;
		goto fail_wq;
	}

	return 0;
fail_wq:
	kmem_cache_destroy(sc_io_cache);
fail_io_cache:
	unregister_blkdev(sc_major, "sc");
fail_sc_files:
	kobject_put(sc_sysfs_kobj);
fail:
	return ret;
}

static void __init sc_exit(void)
{

	kmem_cache_destroy(sc_io_cache);
	kobject_put(sc_sysfs_kobj);
	unregister_blkdev(sc_major, "sc");
	mutex_destroy(&sc_all_backing_dev_lock);
}

module_init(sc_init);
module_exit(sc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jianchao Wang jianchao.w.wang@oracle.com");
