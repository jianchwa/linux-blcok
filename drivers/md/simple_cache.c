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

static char *sc_log_op_strings[] = {
	"MAP_SET",
	"MAP_CLEAN",
	"DIRTY_SET",
	"DIRTY_CLEAN",
	"NOP",
	"MAP_DIRTY",
};

static char *sci_state_strings[] = {
	"READAHEAD",
	"CLEAN",
	"DIRTY",
	"RECLAIMING"
};

static char *sc_ra_state_strings[] = {
	"READ_BACKING",
	"WRITE_CACHING",
	"LOG",
	"COMPLETE"
};

static char *sc_rc_state_strings[] = {
	"READ_DIRTY",
	"WRITE_CACHE",
	"LOG",
	"COMPLETE"
};

static int sc_get_mapping_entry(struct sc_backing_dev *scbd, sector_t sec);
static int sc_block_alloc(struct sc_backing_dev *scbd);
static blk_qc_t sc_writeback(struct sc_io *sio);
static void sc_ra_sm(struct sc_ra_io *raio);
static void sc_log_insert(struct sc_log_item *sli);
static void sc_cache_complete(struct sc_cache_info *sci);
static void sc_handle_pending_list(struct sc_cache_info *sci);
static void sc_rc_sm(struct sc_rc_io *rcio);
static void sc_block_free(struct sc_backing_dev *scbd, int block);
static bool sc_cache_reclaim(struct sc_cache_info *sci, bool *dirty);
static bool sc_cache_clean(struct sc_cache_info *sci, bool ing);
static void sc_cache_dirty(struct sc_cache_info *sci);
static void sc_rc_run_sm(struct sc_rc_io *rcio);

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

static struct sc_cache_info *sc_get_cache_info(struct sc_backing_dev *scbd, int cblock)
{
	int sci_per_page = PAGE_SIZE / sizeof(struct sc_cache_info);

	cblock -= scbd->cb_offset;
	if (cblock > scbd->scis_total)
		return NULL;
	return &scbd->scis[cblock/sci_per_page][cblock%sci_per_page];
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

	sio->started = false;
	return 0;
}

static blk_qc_t sc_cache_io(struct sc_io *sio,
		struct sc_cache_info *sci, bio_end_io_t *end_io)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct sc_sb *sb = scbd->sb;
	struct bio *clone = &sio->clone;
	struct bio *bio = sio->front_bio;
	sector_t offset = bio->bi_iter.bi_sector;

	sio->started = true;
	sio->sci = sci;
	__bio_clone_fast(clone, bio);
	clone->bi_iter.bi_sector = (sci->cb << sb->bitsbsz2sc) + (offset & sb->scblkmask);
	bio_set_dev(clone, scbd->caching_dev);
	clone->bi_end_io = end_io;
	clone->bi_private = sio;

	return submit_bio(clone);
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

static void sc_rc_endio(struct bio *bio)
{
	struct sc_rc_io *rcio = bio->bi_private;

	sc_rc_run_sm(rcio);
}

static void sc_rc_writeback_endio(struct bio *bio)
{
	struct sc_rc_io *rcio = bio->bi_private;
	struct sc_backing_dev *scbd = rcio->scbd;
	unsigned long flags;

	spin_lock_irqsave(&scbd->wb_lock, flags);
	if (!list_empty_careful(&scbd->wb_pending))
		queue_work(sc_workqueue, &scbd->wb_work);
	spin_unlock_irqrestore(&scbd->wb_lock, flags);

	sc_rc_endio(bio);
}

static void sc_rc_writeback(struct sc_rc_io *rcio)
{
	struct sc_backing_dev *scbd = rcio->scbd;
	struct sc_sb *sb = scbd->sb;
	struct bio *bio = rcio->bio;
	int i;

	bio_init(bio, bio->bi_io_vec, rcio->nr);
	bio->bi_iter.bi_sector = rcio->bb << sb->bitsbsz2sc;
	bio_set_dev(bio, scbd->backing_dev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_FUA);
	for (i = 0; i < rcio->nr; i++)
		bio_add_page(bio, rcio->pages[i], PAGE_SIZE, 0);
	bio->bi_private = rcio;
	bio->bi_end_io = sc_rc_writeback_endio;

	submit_bio(bio);
}

static void sc_wb_work(struct work_struct *work)
{
	struct sc_backing_dev *scbd = container_of(work, struct sc_backing_dev, wb_work);
	unsigned long flags;
	struct sc_rc_io *rcio;

	if (list_empty_careful(&scbd->wb_pending))
		return;

	spin_lock_irqsave(&scbd->wb_lock, flags);
	if (list_empty_careful(&scbd->wb_pending)) {
		spin_unlock_irqrestore(&scbd->wb_lock, flags);
		return;
	}
	/*
	 * Need some heuristic to decide submit one by one or
	 * submit all.
	 */
	rcio = list_first_entry(&scbd->wb_pending, struct sc_rc_io, wblist);
	list_del_init(&rcio->wblist);
	spin_unlock_irqrestore(&scbd->wb_lock, flags);

	sc_rc_writeback(rcio);
	return;
}

static void sc_interrupt_wb(struct sc_backing_dev *scbd, struct sc_cache_info *sci)
{
	struct sc_rc_io *rcio = READ_ONCE(sci->data);
	unsigned long flags;

	if (!rcio)
	    return;

	WRITE_ONCE(sci->data, NULL);

	/*
	 * If the rcio is pending on WB list, we steal it
	 * and complete it ourself, otherwise, let the sc_rc_sm
	 * handle the interrupt.
	 * The spin lock operations act as a pair of memory barrier
	 * between sc_interrupt_wb and sc_wb_queue
	 */
	spin_lock_irqsave(&scbd->wb_lock, flags);
	if (list_empty_careful(&rcio->wblist)) {
		spin_unlock_irqrestore(&scbd->wb_lock, flags);
		return;
	}
	list_del_init(&rcio->wblist);
	spin_unlock_irqrestore(&scbd->wb_lock, flags);

	/*
	 * Use SC_RC_LOG state here, then we could enter
	 * sc_rc_interrupted
	 */
	rcio->state = SC_RC_LOG;
	sc_rc_run_sm(rcio);
}

static void sc_wb_queue(struct sc_rc_io *rcio)
{
	struct sc_backing_dev *scbd = rcio->scbd;
	struct sc_rc_io *pos;
	unsigned long flags;
	bool queue = false;

	spin_lock_irqsave(&scbd->wb_lock, flags);

	if (list_empty_careful(&scbd->wb_pending))
		queue = true;

	list_for_each_entry(pos, &scbd->wb_pending, wblist)
		if (pos->sci->bb > rcio->sci->bb)
			break;

	list_add_tail(&rcio->wblist, &pos->wblist);
	spin_unlock_irqrestore(&scbd->wb_lock, flags);
	WRITE_ONCE(rcio->sci->data, rcio);
	if (queue)
		queue_work(sc_workqueue, &scbd->wb_work);
}

static void sc_rc_run_sm(struct sc_rc_io *rcio)
{
	switch (rcio->state) {
		/*
		 * Running in reclaim work context
		 */
	case SC_RC_RD:
		/*
		 * Running in irq completion context, but
		 * the action is safe in irq mode
		 */
	case SC_RC_WB:
		sc_rc_sm(rcio);
		break;
		/*
		 * IO completion context
		 */
	case SC_RC_LOG:
		/*
		 * Running in log insert work context.
		 * To handle log insert faster, queue to work
		 * queue context.
		 *
		 * And also sc_interrupt_wb use this.
		 */
	case SC_RC_COMPLETE:
		queue_work(sc_workqueue, &rcio->async_work);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

static void sc_rc_read_cache(struct sc_rc_io *rcio)
{
	struct sc_backing_dev *scbd = rcio->scbd;
	struct bio *bio;
	int i;

	bio = bio_alloc(GFP_NOIO, rcio->nr);
	bio->bi_iter.bi_sector = rcio->cb << scbd->sb->bitsbsz2sc;
	bio_set_dev(bio, scbd->caching_dev);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	for (i = 0; i < rcio->nr; i++)
		bio_add_page(bio, rcio->pages[i], PAGE_SIZE, 0);
	bio->bi_private = rcio;
	bio->bi_end_io = sc_rc_endio;

	rcio->state = SC_RC_WB; /* next step */
	rcio->bio = bio;

	submit_bio(bio);
}

/*
 * kworker task context
 */
static void sc_rc_log_done(void *data)
{
	sc_rc_run_sm(data);
}

static void sc_rc_log(struct sc_rc_io *rcio)
{
	struct sc_log_item *sli;

	/*
	 * TODO
	 *  - mempool or kmem cache
	 */
	sli = kmalloc(sizeof(*sli), GFP_NOIO);
	sli->sl = &rcio->scbd->sb->log;

	if (rcio->action == SC_RCA_CLEAN)
		sli->op = SC_LOG_OP_DIRTY_CLEAN;
	else if (rcio->action == SC_RCA_RECLAIM)
		sli->op = SC_LOG_OP_MAP_CLEAN;

	sli->cb = rcio->cb;
	sli->bb = ~0;
	sli->log_done = sc_rc_log_done;
	sli->private = rcio;

	rcio->state = SC_RC_COMPLETE; /* next step */

	sc_log_insert(sli);
}

static void sc_drain_rcio(struct sc_backing_dev *scbd)
{
	while (atomic_read(&scbd->rcio_running)) {
		wait_event_timeout(scbd->rcio_wait,
				!atomic_read(&scbd->rcio_running),
				(5 * HZ));
	}
}

static void sc_free_rcio(struct sc_rc_io *rcio)
{
	struct sc_backing_dev *scbd = rcio->scbd;
	int i;

	if (atomic_dec_return(&scbd->rcio_running) == 0 &&
	    waitqueue_active(&scbd->rcio_wait))
	    wake_up(&scbd->rcio_wait);

	for (i = 0; i < rcio->nr; i++)
		put_page(rcio->pages[i]);
	if (rcio->bio)
		bio_put(rcio->bio);
	if (rcio->pages)
		kfree(rcio->pages);
	kfree(rcio);
}

static void sc_rc_complete(struct sc_rc_io *rcio)
{
	sc_cache_clean(rcio->sci, false);
	sci_sync(rcio->sci);
	sc_handle_pending_list(rcio->sci);
#if 0
	WRITE_ONCE(rcio->sci->status, SCI(0, 0, SCI_READAHEAD));
	sc_block_free(rcio->scbd, rcio->cb);
#endif
	sc_free_rcio(rcio);
}

static void sc_rc_interrupted(struct sc_rc_io *rcio)
{
	switch (rcio->action) {
	case SC_RCA_CLEAN:
		sc_cache_dirty(rcio->sci);
		break;
	case SC_RCA_RECLAIM:
		break;
	default:
		WARN_ON(1);
		break;
	}

	sci_sync(rcio->sci);
	sc_handle_pending_list(rcio->sci);
	sc_free_rcio(rcio);
}

/*
 * TODO
 *   reclaim process could be interrupted
 */
static void sc_rc_sm(struct sc_rc_io *rcio)
{
	bool interrupt = false;

	trace_printk("rc bb %lx cb %lx %s\n",
			rcio->bb, rcio->cb, sc_rc_state_strings[rcio->state]);

	if (!llist_empty(&rcio->sci->pending_list))
		interrupt = true;

	switch(rcio->state) {
	case SC_RC_RD:
		/*
		 * Read in the dirty cache
		 * Interruptible
		 */
		if (interrupt)
			goto intr;
		sc_rc_read_cache(rcio);
		break;
	case SC_RC_WB:
		/*
		 * Writeback the dirty cache
		 * Interruptible
		 */
		if (interrupt)
			goto intr;
		/*
		 * It seems that the writeback here could cause
		 * large amount of IO which could block the ra IO
		 */
		rcio->state = SC_RC_LOG; /* next step */
		sc_wb_queue(rcio);
		break;
	case SC_RC_LOG:
		/*
		 * dirty clean / mapping clean log
		 * Interruptible
		 */
		if (interrupt)
			goto intr;
		sc_rc_log(rcio);
		break;
	case SC_RC_COMPLETE:
		/*
		 * Handle pending list
		 */
		sc_rc_complete(rcio);
		break;
	default:
		WARN_ON(1);
		break;
	}

	return;
intr:
	sc_rc_interrupted(rcio);
	return;
}

static void sc_rc_async_work(struct work_struct *work)
{
	struct sc_rc_io *rcio = container_of(work, struct sc_rc_io, async_work);

	sc_rc_sm(rcio);
}

static void sc_reclaim_one(struct sc_backing_dev *scbd,
		struct sc_cache_info *sci, enum sc_rc_action action)
{
	struct sc_rc_io *rcio;
	int nr, i;

	rcio = kmalloc(sizeof(*rcio), GFP_NOIO);
	rcio->scbd = scbd;
	rcio->sci = sci;
	rcio->bb = sci->bb;
	rcio->cb = sci->cb;
	rcio->bio = NULL;
	rcio->action = action;
	INIT_WORK(&rcio->async_work, sc_rc_async_work);
	INIT_LIST_HEAD(&rcio->wblist);

	if (action == SC_RCA_CLEAN) {
		nr = scbd->sb->block_size / PAGE_SIZE;
		rcio->pages = kmalloc(sizeof(void *) * nr, GFP_NOIO);
		for (i = 0; i < nr; i++) {
			rcio->pages[i] = alloc_page(GFP_NOIO);
			BUG_ON(!rcio->pages[i]);
		}
		rcio->nr = nr;
		rcio->state = SC_RC_RD;
	} else {
		rcio->pages = NULL;
		rcio->nr = 0;
		rcio->state = SC_RC_LOG;
	}

	atomic_inc(&scbd->rcio_running);
	sc_rc_run_sm(rcio);
}

/*
 * This is the very core algorithm
 */
static enum sc_rc_action sc_should_reclaim(struct sc_cache_info *sci)
{
	uint32_t data = READ_ONCE(sci->status);
	enum sci_state state = SCI_STATE(data);
	unsigned long atime;
	int hit;
	/*
	 * Just write out the DIRTY blocks
	 */
	if (state == SCI_DIRTY) {

		atime = READ_ONCE(sci->atime);
		hit = SCI_HIT_COUNT(data) + (sci->upper_hc << 10);

		if (time_after(jiffies, atime + (SC_CACHE_RECLAIM_INTERVAL)) &&
			hit < 2)
			return SC_RCA_CLEAN;

		if (time_after(jiffies, atime + (SC_CACHE_RECLAIM_INTERVAL * 2)) &&
			sci->upper_hc < 1)
			return SC_RCA_CLEAN;

		if (time_after(jiffies, atime + (SC_CACHE_RECLAIM_INTERVAL * 3)))
			return SC_RCA_CLEAN;
	}

	return SC_RCA_NOP;
}

static void sc_reclaim(struct sc_backing_dev *scbd)
{
	int i;
	struct sc_cache_info *sci;

	for (i = 0; i < scbd->scis_total; i ++) {
		sci = sc_get_cache_info(scbd, i + scbd->cb_offset);
		switch (sc_should_reclaim(sci)) {
		case SC_RCA_NOP:
			break;
		case SC_RCA_CLEAN:
			if (sc_cache_clean(sci, true))
				sc_reclaim_one(scbd, sci, SC_RCA_CLEAN);
			break;
		case SC_RCA_RECLAIM:
			break;
		default:
			WARN_ON(1);
			break;
		}
	}
}

static void sc_reclaim_work(struct work_struct *work)
{
	struct sc_backing_dev *scbd = container_of(work, struct sc_backing_dev, reclaim_work.work);

	pr_info("%s run...\n", __func__);
	sc_reclaim(scbd);

	queue_delayed_work(sc_workqueue, &scbd->reclaim_work,
			SC_CACHE_RECLAIM_INTERVAL);
}

static void sc_writeback_endio(struct bio *clone)
{
	struct sc_io *sio = clone->bi_private;
	struct bio *bio = sio->front_bio;

	sc_end_io_acct(sio);
	/*
	 * TODO
	 * - handle the failing case
	 */
	sc_cache_complete(sio->sci);
	bio->bi_status = clone->bi_status;
	bio_endio(bio);
	free_sc_io(sio);
}

static unsigned long sc_calc_clean(uint64_t old, bool ing)
{
	int hit, inflight;
	enum sci_state state;

	/*
	 * Inflight must be 0 for CLEANING
	 */
	hit = SCI_HIT_COUNT(old);
	if (ing) {
		state = SCI_CLEANING;
		inflight = 0;
	} else {
		/*
		 * There could be read IO inflight with CLEANING in parallel.
		 */
		inflight = SCI_INFLIGHT(old);
		state = SCI_CLEAN;
	}
	return SCI(hit, inflight, state);
}

static bool sc_cache_clean(struct sc_cache_info *sci, bool ing)
{
	uint32_t new, old, res;

	old = READ_ONCE(sci->status);
	while (1) {
		if (SCI_INFLIGHT(old)) {
			trace_printk("cb %x if %x\n",
					sci->cb,
					SCI_INFLIGHT(old));
			return false;
		}

		new = sc_calc_clean(old, ing);
		res = cmpxchg(&sci->status, old, new);
		if (old == res)
			break;
		old = res;
	}

	return true;
}

static bool sc_cache_reclaim(struct sc_cache_info *sci, bool *dirty)
{
	uint32_t new, old, res;

	old = READ_ONCE(sci->status);
	while (1) {
		if (SCI_INFLIGHT(old)) {
			trace_printk("cb %x if %x\n",
					sci->cb,
					SCI_INFLIGHT(old));
			return false;
		}

		new = SCI(0, 0, SCI_RECLAIMING);
		*dirty = SCI_STATE(old) == SCI_DIRTY;
		res = cmpxchg(&sci->status, old, new);
		if (old == res)
			break;
		old = res;
	}

	return true;
}

static unsigned long sc_calc_complete(uint64_t old)
{
	int hit, inflight;
	enum sci_state state;

	/*
	 * Dirty state will be set by sc_dirty_log_done
	 */
	state = SCI_STATE(old);
	hit = SCI_HIT_COUNT(old);
	inflight = SCI_INFLIGHT(old);
	inflight--;

	return SCI(hit, inflight, state);
}

static void sc_cache_complete(struct sc_cache_info *sci)
{
	uint32_t old, new, res;

	old = READ_ONCE(sci->status);

	/*
	 * During readahead, the log and IO will be submited in parallel
	 * and complete ahead of changing state, so we could complete
	 * under SCI_READAHEAD.
	 */
	if (SCI_STATE(old) == SCI_RECLAIMING) {
		WARN(1, "Wrong sci state %s\n", sci_state_strings[SCI_STATE(old)]);
		return;
	}

	while (1) {
		new = sc_calc_complete(old);
		res = cmpxchg(&sci->status, old, new);
		if (old == res) {
			trace_printk("ended cb %x if %x\n",
					sci->cb,
					SCI_INFLIGHT(old));
			break;
		}
		old = res;
	}
}

static unsigned long sc_calc_dirty(uint64_t old)
{
	int hit, inflight;

	inflight = SCI_INFLIGHT(old);
	hit = SCI_HIT_COUNT(old);
	return SCI(hit, inflight, SCI_DIRTY);
}

/*
 * There could be read IO in parallel with us
 */
static void sc_cache_dirty(struct sc_cache_info *sci)
{
	uint32_t old, new, res;

	old = READ_ONCE(sci->status);

	while (1) {
		new = sc_calc_dirty(old);
		res = cmpxchg(&sci->status, old, new);
		if (old == res)
			break;
		old = res;
	}
}

static unsigned long sc_calc_start(uint64_t old)
{
	int hit, inflight;
	enum sci_state state;

	inflight = SCI_INFLIGHT(old);
	state = SCI_STATE(old);
	hit = SCI_HIT_COUNT(old);
	inflight++;
	hit++;

	return SCI(hit, inflight, state);
}

static enum sci_state sc_cache_start(struct sc_cache_info *sci, bool started, bool w)
{
	uint32_t old, new, res;

	old = READ_ONCE(sci->status);
	while (1) {
		trace_printk("try start cb %x if %x s %s %d\n",
				sci->cb,
				SCI_INFLIGHT(old),
				sci_state_strings[SCI_STATE(old)],
				started);

		/*
		 * Write cannot be ongoing with write IO
		 */
		if (unlikely(SCI_STATE(old) == SCI_CLEANING && w))
			return SCI_CLEANING;

		/*
		 * cblock under SCI_READAHEAD will not be reclaimed.
		 */
		if (SCI_STATE(old) == SCI_READAHEAD)
			return SCI_READAHEAD;

		/*
		 * sios will re-enter sc_writeback after dirty log, they have been
		 * accounted as sci in-flight, so needn't account them again.
		 */
		if (started)
			return SCI_STATE(old);

		new = sc_calc_start(old);
		/*
		 * May race with reclaim or concurrent submits and completions.
		 */
		res = cmpxchg(&sci->status, old, new);
		/*
		 * We wins.
		 */
		if (old == res) {
			trace_printk("started cb %x if %x\n",
					sci->cb,
					(int)SCI_INFLIGHT(old));
			sci->atime = jiffies;
			if (SCI_HIT_COUNT(new) == 0)
				sci->upper_hc++;
			return SCI_STATE(old);
		}
		old = res;
	}
}

static void sc_handle_pending_list(struct sc_cache_info *sci)
{
	struct llist_node *first, *node, *next;
	struct sc_io *sio;

	first = llist_del_all(&sci->pending_list);
	if (!first)
		return;

	llist_for_each_safe(node, next, first){
		sio = container_of(node, struct sc_io, node);
		sc_writeback(sio);
	}
}

static struct sc_ra_io *sc_alloc_raio(int nr)
{
	struct sc_ra_io *raio;
	int i;

	/*
	 * FIXME
	 *   We should consider the failing case.
	 */
	raio = kmalloc(sizeof(*raio), GFP_NOIO);
	raio->pages = kmalloc(sizeof(void *) * nr, GFP_NOIO);
	for (i = 0; i < nr; i++) {
		raio->pages[i] = alloc_page(GFP_NOIO);
		BUG_ON(!raio->pages[i]);
	}
	raio->nr = nr;

	return raio;
}

/*
 * TODO
 * sc_ra_io could be cached somewhere
 */
static void sc_free_raio(struct sc_ra_io *raio)
{
	int i;

	for (i = 0; i < raio->nr; i++)
		put_page(raio->pages[i]);
	if (raio->bio)
		bio_put(raio->bio);
	kfree(raio->pages);
	kfree(raio);
}

static void sc_ra_endio(struct bio *bio)
{
	struct sc_ra_io *raio = bio->bi_private;

	queue_work(sc_workqueue, &raio->async_work);
}

static void sc_ra_write_cache(struct sc_ra_io *raio)
{
	struct sc_backing_dev *scbd = raio->scbd;
	struct bio *bio;
	int i;

	/*
	 * Reuse the bio and pages.
	 */
	bio = raio->bio;
	bio_init(bio, bio->bi_io_vec, raio->nr);
	bio->bi_iter.bi_sector = raio->cb << scbd->sb->bitsbsz2sc;
	bio_set_dev(bio, scbd->caching_dev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	for (i = 0; i < raio->nr; i++)
		bio_add_page(bio, raio->pages[i], PAGE_SIZE, 0);
	bio->bi_private = raio;
	bio->bi_end_io = sc_ra_endio;
	/*
	 * Is it OK to submit this in completion context ?
	 */
	submit_bio(bio);
}

/*
 * kworker task context
 */
static void sc_ra_log_done(void *data)
{
	struct sc_ra_io *raio = data;

	/*
	 * All of the IO submited with log in parallel
	 * have been completed.
	 */
	if (atomic_dec_return(&raio->ios) == 0)
		sc_ra_sm(data);
}

static void sc_ra_io_endio(struct bio *clone)
{
	struct sc_io *sio = clone->bi_private;
	struct sc_ra_io *raio = sio->sci->data;

	if (atomic_dec_return(&raio->ios) == 0)
		queue_work(sc_workqueue, &raio->async_work);
}

static void sc_ra_log(struct sc_ra_io *raio)
{
	struct sc_cache_info *sci = raio->sci;
	struct sc_log_item *sli;
	struct llist_node *first, *node, *next;
	struct sc_io *sio;

	first = llist_del_all(&sci->pending_list);
	BUG_ON(!first);
	llist_for_each_safe(node, next, first){
		sio = container_of(node, struct sc_io, node);
		if (op_is_write(bio_op(sio->front_bio)))
			raio->write_pending = true;
		atomic_inc(&raio->ios);
	}

	raio->io_list = first;
	/*
	 * TODO
	 *  - mempool or kmem cache
	 */
	sli = kmalloc(sizeof(*sli), GFP_NOIO);
	sli->sl = &raio->scbd->sb->log;
	sli->op = raio->write_pending ? SC_LOG_OP_MAP_DIRTY : SC_LOG_OP_MAP_SET;
	sli->cb = raio->cb;
	sli->bb = raio->bb;
	sli->log_done = sc_ra_log_done;
	sli->private = raio;
	
	atomic_inc(&raio->ios);

	sc_log_insert(sli);

	/*
	 * send out the pending IOs with log.
	 * thse IOs can only return to upper layer when log is completed.
	 */
	llist_for_each_safe(node, next, first){
		sio = container_of(node, struct sc_io, node);
		sc_cache_io(sio, sci, sc_ra_io_endio);
	}
}
static void sc_ra_handle_ios(struct sc_ra_io *raio)
{
	struct llist_node *node, *next;
	struct sc_io *sio;

	llist_for_each_safe(node, next, raio->io_list){
		sio = container_of(node, struct sc_io, node);
		sc_writeback_endio(&sio->clone);
	}
	raio->io_list = NULL;
}


static void sc_ra_complete(struct sc_ra_io *raio)
{
	struct sc_cache_info *sci = raio->sci;
	uint64_t data;
	enum sci_state state;

	sc_ra_handle_ios(raio);
	sci->bb = raio->bb;
	state = raio->write_pending ? SCI_DIRTY : SCI_CLEAN;
	sc_free_raio(raio);

	data = 	SCI(0, 0, state);
	WRITE_ONCE(sci->status, data);
	/*
	 * sci_read_lock
	 * get SCI_READAHEAD
	 * add to pending_list    set SCI_CLEAN
	 * sci_read_unlock
	 *                        sci_sync
	 * Therefore,
	 * sc_ra_complete could see all of the sci
	 * added on pending_list if someone doesn't
	 * see SCI_CLEAN.
	 */
	sci_sync(sci);
	/*
	 * The pending_list has been cleaned, so we
	 * have to depend on this to prevent new IO
	 * from triggering readahead again.
	 */
	WRITE_ONCE(sci->data, NULL);
	sc_handle_pending_list(sci);
}

static void sc_ra_sm(struct sc_ra_io *raio)
{
	trace_printk("ra bb %lx cb %lx %s\n",
			raio->bb, raio->cb, sc_ra_state_strings[raio->state]);
	switch (raio->state) {
	case SC_RA_READ_BACKING:
		raio->state = SC_RA_WRITE_CACHING;
		sc_ra_write_cache(raio);
		break;
	case SC_RA_WRITE_CACHING:
		raio->state = SC_RA_LOG;
		sc_ra_log(raio);
		break;
	case SC_RA_LOG:
		raio->state = SC_RA_COMPLETE;
		sc_ra_complete(raio);
		break;
	default:
		WARN_ON(1);
		break;
	}
}

/*
 * Used for irq completion path
 */
static void sc_ra_async_work(struct work_struct *work)
{
	struct sc_ra_io *raio = container_of(work, struct sc_ra_io, async_work);

	sc_ra_sm(raio);
}

static void sc_cache_readahead(struct sc_backing_dev *scbd,
		struct sc_cache_info *sci, unsigned long cb, unsigned long bb)
{
	struct sc_sb *sb = scbd->sb;
	struct bio *bio;
	struct sc_ra_io *raio;
	int i;

	/*
	 * This says the previous pending IOs are issued with log
	 * in parallel, so the pending_list is empty again.
	 */
	if (sci->data)
		return;

	raio = sc_alloc_raio(sb->block_size / PAGE_SIZE);
	raio->scbd = scbd;
	raio->sci = sci;
	raio->bb = bb;
	raio->cb = cb;
	raio->state = SC_RA_READ_BACKING;
	raio->io_list = NULL;
	atomic_set(&raio->ios, 0);
	raio->write_pending = false;
	INIT_WORK(&raio->async_work, sc_ra_async_work);
	sci->data = raio;
	/*
	 * Our max block size is 512K which needs 128 vecs
	 * The max bio vecs is 256.
	 * TODO
	 * - we need a mempool of ourself 
	 */
	bio = bio_alloc(GFP_NOIO, raio->nr);
	bio->bi_iter.bi_sector = bb << sb->bitsbsz2sc;
	bio_set_dev(bio, scbd->backing_dev);
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	for (i = 0; i < raio->nr; i++)
		bio_add_page(bio, raio->pages[i], PAGE_SIZE, 0);
	bio->bi_private = raio;
	bio->bi_end_io = sc_ra_endio;
	raio->bio = bio;

	submit_bio(bio);

	return;
}

static void sc_dirty_log_done(void *data)
{
	struct sc_cache_info *sci = data;

	sc_cache_dirty(sci);
	sci_sync(sci);
	sc_handle_pending_list(sci);
}

static void sc_dirty_log(struct sc_cache_info *sci, struct sc_backing_dev *scbd)
{
	struct sc_log_item *sli;

	/*
	 * TODO
	 *  - mempool or kmem cache
	 */
	sli = kmalloc(sizeof(*sli), GFP_NOIO);
	sli->sl = &scbd->sb->log;
	sli->op = SC_LOG_OP_DIRTY_SET;
	sli->cb = sci->cb;
	sli->bb = ~0; /* Invalid value */
	sli->log_done = sc_dirty_log_done;
	sli->private = sci;

	sc_log_insert(sli);
}

/*
 * How to handle cache miss
 *
 * 1. mark allocating (winner need to be responsible for allocation)
 * 2. allocate cblock
 * 3. readahead
 * 4. insert log
 * 5. update in-core mapping
 */
static blk_qc_t sc_writeback(struct sc_io *sio)
{
	struct sc_backing_dev *scbd = sio->scbd;
	struct sc_sb *sb = scbd->sb;
	struct bio *bio = sio->front_bio;
	struct bio *clone = &sio->clone;
	sector_t offset = bio->bi_iter.bi_sector;
	bool first;

	/*
	 * FIXME:
	 *   the cblock unit is not consistent across the code,
	 *   some are 'int', some are 'unsigned long'.
	 */
	int cblock;
	struct sc_cache_info *sci;
	blk_qc_t ret = BLK_QC_T_NONE;

	if ((bio->bi_iter.bi_sector >> sb->bitsbsz2sc) !=
			((bio_end_sector(bio) - 1) >> sb->bitsbsz2sc)) {
		pr_warn("Single bio spans two blocks, bio %lx - %lx\n",
				bio->bi_iter.bi_sector, bio_end_sector(bio));
	}

	cblock = sc_get_mapping_entry(scbd, offset);
	if (cblock <= 0) {
		/* 1. last part which is smaller than block size
		 *    when the front device is created, the caching
		 *    device has not been attached, so we cannot
		 *    know the block size and do round_down.
		 * 2. no cache space currently
		 *    FIXME:
		 *      This is not a good way.
		 *      Please refer to comments in SCI_READAHEAD case
		 */
		pr_warn("passthrough\n");
		goto passthrough;
	}

	sci = sc_get_cache_info(scbd, cblock);
	if (!sci) {
		pr_err("NULL sci for cb %x off%lx\n", cblock, offset);
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
		return BLK_QC_T_NONE;
	}

	sci_read_lock(sci);
	switch (sc_cache_start(sci, sio->started,
				op_is_write(bio_op(bio)))) {
	case SCI_CLEANING:
		/*
		 * Only for the case writeback and write IO in parallel.
		 */
		llist_add(&sio->node, &sci->pending_list);
		sci_read_unlock(sci);
		if (READ_ONCE(sci->data))
		    sc_interrupt_wb(scbd, sci);
		break;
	case SCI_READAHEAD:
		/*
		 * trigger readahead
		 * the other IOs on the same block should wait for the readahead,
		 * otherwise, the readahead block maybe different from the one on
		 * backing device.
		 */
		first = llist_add(&sio->node, &sci->pending_list);
		/*
		 * See comments in sc_ra_complete
		 */
		sci_read_unlock(sci);
		if (first)
			sc_cache_readahead(scbd, sci, cblock, offset >> sb->bitsbsz2sc);
		break;
	case SCI_CLEAN:
		/*
		 * For write, we need to send out dirty log.
		 */
		if (op_is_write(bio_op(bio))) {
			sio->started = true;
			first = llist_add(&sio->node, &sci->pending_list);
			/*
			 * Same with readahead path
			 */
			sci_read_unlock(sci);
			if (first)
				sc_dirty_log(sci, scbd);
			break;
		}
		/*
		 * fallthrougth for read
		 */
	default:
		/*
		 * cache hit
		 */
		sci_read_unlock(sci);
		trace_printk("cache hit IO ca %lx ba %lx\n", clone->bi_iter.bi_sector, offset);
		ret = sc_cache_io(sio, sci, sc_writeback_endio);
		break;
	}

	return ret;

passthrough:
	/*
	 * We passthrough cache when cache miss first time, and bless followings
	 * But I have to concern that the passthrough IO to backing device would
	 * slow down the readahead IO.
	 */
	return sc_passthrough(sio);
}

static struct bio *sc_bio_split(struct sc_backing_dev *scbd, struct bio *bio)
{
	struct sc_sb *sb = scbd->sb;
	struct bio_vec bv;
	struct bvec_iter iter;
	sector_t start = bio->bi_iter.bi_sector;
	sector_t sectors = 0;
	struct bio *new;

	bio_for_each_segment(bv, bio, iter) {
		sectors += (bv.bv_len >> 9);
		if ((start >> sb->bitsbsz2sc) !=
				((start + sectors) >> sb->bitsbsz2sc)) {
			/*
			 *     split
			 *  _____^_____
			 * /           \|
			 * |------| |---|--| |------|
			 *              |
			 *         block boundary
			 */
			sectors = ((start + sectors) & (~sb->scblkmask)) - start;
			if (sectors != bio_sectors(bio))
				goto split;
		}

		/* FIXME
		 * There are some codes about seg_size in blk_queue_split.
		 * We need to backport them here.
		 */
	}

	return bio;
split:
	trace_printk("split bio %lx len %x at %lx\n",
			bio->bi_iter.bi_sector, bio_sectors(bio), sectors);
	new = bio_split(bio, sectors, GFP_NOIO, scbd->front_queue->bio_split);
	new->bi_opf |= REQ_NOMERGE;
	bio_chain(new, bio);
	generic_make_request(bio);
	return new;
}

static struct sc_io *sc_setup_io(struct sc_backing_dev *scbd, struct bio *bio)
{
	struct sc_io *sio;

	sio = alloc_sc_io(scbd, bio);
	if (unlikely(!sio))
		return NULL;

	sc_io_init(sio);
	/*
	 * Note, we mustn't do any modification on the original bio
	 */
	sio->front_bio = bio;

	sc_start_io_acct(sio);

	return sio;
}

static blk_qc_t sc_make_request(struct request_queue *q, struct bio *bio)
{
	struct sc_backing_dev *scbd = q->queuedata;
	struct sc_io *sio;
	blk_qc_t ret;

	switch(READ_ONCE(scbd->mode)) {
	case SC_CACHE_WRITETHROUGH:
	case SC_CACHE_WRITEBACK:
		if (bio_sectors(bio)) {
			/*
			 * split the bio based on the cache mapping block alignment,
			 * then we will only have cache hit or miss cases and don't
			 * need to consider cache hit/miss partially.
			 */
			bio = sc_bio_split(scbd, bio);
			sio = sc_setup_io(scbd, bio);
			ret = sc_writeback(sio);
			break;
		}
		/* fallthrougth if no data */
	case SC_CACHE_PASSTHROUGH:
		sio = sc_setup_io(scbd, bio);
		ret = sc_passthrough(sio);
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
	struct sc_backing_dev *scbd = sb->scbd;
	sc_log_t *start, *end;
	uint32_t data;
	int i;
	unsigned long cblock;
	sc_entry_t *e;

	for (i = 0; i < nr; i++) {
		start = (sc_log_t *)page_address(pages[i]);
		end = start + SC_LOG_ENTRIES_PER_PAGE;
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

			if (SC_LOG_GEN(data) <= sb->mapping_gen) {
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
			if (cblock - scbd->cb_offset >= scbd->scis_total) {
				pr_err("Corrupted log entry %x\n", data);
				continue;
			}

			e = (sc_entry_t *)page_address(sb->map_pages[cblock/SC_MAPPING_ENTRIES_PER_PAGE]);
			e += cblock % SC_MAPPING_ENTRIES_PER_PAGE;
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
			case SC_LOG_OP_NOP:
				break;
			case SC_LOG_OP_MAP_DIRTY:
				/*
				 * The following log entry contains the bblock
				 */
				start++;
				e->data = SC_ENTRY_CONSTRUCT(start->data, 1, 1);
				break;
			default:
				WARN_ON(1);
				break;
			}
		}
	}
	return nr * SC_LOG_ENTRIES_PER_PAGE;
out:
	return (i * SC_LOG_ENTRIES_PER_PAGE) + (start - (sc_log_t *)page_address(pages[i]));
}

/*
 * Read in run or patch log and apply them on cache pages of on-disk
 * mapping entries (sc_sb.map_pages[]). It will return the number of
 * log entries applied.
 */
static unsigned long sc_patch_mapping(struct sc_log_sb *sl, int n)
{
 	int i, nr = sl->sb->block_size / PAGE_SIZE;
	sector_t start = sl->log_start[n];
	sector_t end = start + sl->log_len;
	struct page **pages;
	struct bio *bio;
	unsigned long ret, pass = 0;

	pages = kzalloc(sizeof(void *) * nr, GFP_NOIO);
	BUG_ON(!pages);

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
	pr_info("start %lx has %lx valid entries\n", start, ret);
	bio_put(bio);
	/*
	 * Stop halfway means there are invalid or time out
	 * log entries.
	 */
	if (ret < (nr * SC_LOG_ENTRIES_PER_PAGE))
		return pass + ret;

	start += PAGE_SECTORS * nr;
	pass += nr * SC_LOG_ENTRIES_PER_PAGE;
	if (start < end)
		goto repeat;

	return pass;
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

	/*
	 * Read in logs and apply them.
	 */
	if (sl->patch)
		sc_patch_mapping(sl, SL_PATCH(sl));
	/*
	 * This is for the sc_log_replay_patch.
	 * It has applied the patch log with sc_patch_mapping and
	 * just wants to flush patched in-core mappings to disk.
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
	sdb = page_address(sb->sb_page);
	pr_info("sb gen update from %d to %d\n", sdb->gen, sb->patch_gen);
	sdb->gen = sb->patch_gen;
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
	struct sc_sb *sb = sl->sb;
	uint32_t *addr = page_address(sl->log_page);
	int offset = sl->log_page_offset;
	struct llist_node *node, *stop, *next, *start;
	struct sc_log_item *sli;
	struct bio *bio;

	BUG_ON(offset > (PAGE_SIZE/SC_CACHE_MAPPING_ENTRY_SIZE));
	start = llist_del_all(&sl->list);
repeat:
	if (!start)
		return;
	stop = NULL;
	/*
	 * FIXME:
	 *   the list is newest to oldest, we should traverse it in reverse odler
	 */
	llist_for_each_safe(node, next, start){

		sli = container_of(node, struct sc_log_item, node);
		trace_printk("bb %x cb %x op %s offset %x run gen %d\n",
			sli->bb, sli->cb,
			sc_log_op_strings[sli->op],
			offset,
			sb->run_gen);

		/*
		 * MAP_SET need two entries.
		 */
		if ((sli->op == SC_LOG_OP_MAP_SET ||
		     sli->op == SC_LOG_OP_MAP_DIRTY) &&
		    (offset == (SC_LOG_ENTRIES_PER_PAGE - 1))) {
			addr[offset] = SC_LOG_CONSTRUCT(sli->cb, sb->run_gen, SC_LOG_OP_NOP);
			offset++;
		}

		if (offset >= SC_LOG_ENTRIES_PER_PAGE) {
			stop = node;
			offset = 0;
			break;
		}
		/*
		 * The previous log entries will be overwritten.
		 */
		addr[offset] = SC_LOG_CONSTRUCT(sli->cb, sb->run_gen, sli->op);
		offset++; /* so the offset's unit is uint32_t */
		if (sli->op == SC_LOG_OP_MAP_SET || sli->op == SC_LOG_OP_MAP_DIRTY) {
			addr[offset] = sli->bb;
			offset++;
		}
	}
	sl->log_page_offset = offset;
	bio = bio_alloc(GFP_NOIO, 1);
	bio->bi_iter.bi_sector = sl->log_offset[SL_RUN(sl)] + sl->log_start[SL_RUN(sl)];
	bio_set_dev(bio, sl->dev);
	bio_set_op_attrs(bio, REQ_OP_WRITE, REQ_FUA | REQ_META);
	bio_add_page(bio, sl->log_page, PAGE_SIZE, 0);
	WARN_ON(submit_bio_wait(bio));
	bio_put(bio);

	llist_for_each_safe(node, next, start){
		if (node == stop)
			break;
		sli = container_of(node, struct sc_log_item, node);
		sli->log_done(sli->private);
		kfree(sli);
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
			sb->patch_gen = sb->run_gen;
			/*
			 * skip 0 if overflow.
			 */
			sb->run_gen = (sb->run_gen == 0xff) ? 1 : (sb->run_gen + 1);
			pr_info("run log gen update to %d\n", sb->run_gen);
			queue_work(sc_workqueue, &sl->patch_work);
		}
		start = stop;
		goto repeat;
	}
}

static void sc_log_insert(struct sc_log_item *sli)
{
	struct sc_log_sb *sl = sli->sl;
	/*
	 * If the first one, queue the work
	 */
	trace_printk("insert log bb %x cb %x op %s\n",
			sli->bb, sli->cb, sc_log_op_strings[sli->op]);
	if (llist_add(&sli->node, &sl->list)) {
		queue_work(sc_workqueue, &sl->insert_work);
		trace_printk("queue insert work\n");
	}
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
	int i, nr;
	unsigned long *map;

	block -= scbd->cb_offset;
	i = block / depth;
	map = scbd->slots[i].map;
	nr = block % depth;

	set_bit(nr % BITS_PER_LONG, &map[nr / BITS_PER_LONG]);
	if (!atomic_dec_return(&scbd->slots[i].available))
		set_bit(i, &scbd->slot_available);
}

/*
 * TODO:
 *  - allocate hint
 *  - we need to try best to scatter different cpu to different slot
 *  - make the depth is power2, then just need to shift
 */
static int sc_block_alloc(struct sc_backing_dev *scbd)
{
	int slot, nr, depth, ret;
	unsigned long *map;

retry:
	slot = find_next_zero_bit(&scbd->slot_available, BITS_PER_LONG, 0);
	if (slot >= BITS_PER_LONG) {
		return -1;
	}

	smp_mb__before_atomic();
	ret = __atomic_add_unless(&scbd->slots[slot].available, -1, 0);
	if (ret == 1)
		set_bit(slot, &scbd->slot_available);
	else if (ret == 0)
		goto retry;

	/*
	 * See comments in sc_block_free
	 */
	smp_mb__after_atomic();
	map = scbd->slots[slot].map;
	/*
	 * 0 ~ (SC_MAX_BITMAP_SLOTS - 1) has the same depth
	 * and we never uses the last slot's depth when calculate the final
	 * cblock.
	 */
	depth = scbd->slots[0].depth;
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

	return slot * depth + nr + scbd->cb_offset;
}

static void sc_block_free(struct sc_backing_dev *scbd, int block)
{
	int depth = scbd->slots[0].depth;
	int i, nr;
	unsigned long *map;

	block -= scbd->cb_offset;
	i = block / depth;
	map = scbd->slots[i].map;
	nr = block % depth;

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
		clear_bit(i, &scbd->slot_available);
	}

	if (waitqueue_active(&scbd->wait_block))
		wake_up(&scbd->wait_block);
}

static int sc_blocks_allocator_init(struct sc_backing_dev *scbd)
{
	int i;
	struct sc_sb *sb = scbd->sb;
	uint64_t depth, slot, len, mt_to;
	int sci_per_page;
	sector_t caching_size = part_nr_sects_read(scbd->caching_dev->bd_part);
	struct sc_cache_info *sci;
	int now;

	mt_to = (3 * sb->maplen) + PAGE_SIZE;
	mt_to = round_up(mt_to, sb->block_size);
	scbd->cb_offset = mt_to / sb->block_size;

	pr_info("First available cb is %lx\n", scbd->cb_offset);
	depth = round_down((caching_size << 9), sb->block_size);
	depth -= mt_to;
	depth /= sb->block_size;

	scbd->scis_total = depth;
	sci_per_page = PAGE_SIZE / sizeof(struct sc_cache_info);
	len = (depth / sci_per_page) + 1;

	/*
	 * TODO
	 *   initialization of scis array should be moved out
	 */
	scbd->scis = kzalloc(sizeof(void *) * len, GFP_KERNEL);
	if (!scbd->scis) {
		pr_err("Failed to allocate sc_cache_info array\n");
		return -ENOMEM;
	}
	scbd->scis_arrary_len = len;
	for (i = 0; i < len; i++) {
		scbd->scis[i] = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (!scbd->scis[i]) {
			pr_err("Failed to allocate sc_cache_info entry\n");
			for (; i >=0; i--)
				kfree(scbd->scis[i]);
			kfree(scbd->scis);
			return -ENOMEM;
		}
	}
	now = jiffies;
	for (i = 0; i < scbd->scis_total; i++) {
		sci = sc_get_cache_info(scbd, i + scbd->cb_offset);
		sci->cb = i + scbd->cb_offset;
		sci->bb = ~0;
		sci->atime = now;
		sci->status = SCI(0, 0, SCI_READAHEAD);
		sci->data = NULL;
		rwlock_init(&sci->rwlock);
		init_llist_head(&sci->pending_list);
	}

	pr_info("available blocks in caching device %llu\n", depth);

	slot = depth / SC_MAX_BITMAP_SLOTS;
	for (i = 0; i < SC_MAX_BITMAP_SLOTS - 1; i++) {
		scbd->slots[i].depth = slot;
		atomic_set(&scbd->slots[i].available, slot);
	}
	pr_info("blocks per slot is %lld\n", slot);

	slot = round_up(slot, BITS_PER_LONG);
	slot /= 8;
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
	slot /= 8;
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
	dsb->gen = 0; /* invalid gen indicates invalid mapping */

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
	sb->mapping_gen = dsb->gen; /* 8bits needn't convert */
	sb->scblkmask = (1 << sb->bitsbsz2sc) - 1;
	sb->sb_page = page;
	scbd->sb = sb;
	sb->scbd = scbd;

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

static int sc_get_mapping_entry(
	struct sc_backing_dev *scbd, sector_t sec)
{
	struct sc_sb *sb = scbd->sb;
	int block = sec >> sb->bitsbsz2sc;
	struct sc_cache_entry *entry;
	uint32_t data;
	int cb;

	/*
	 * This is to handle the last part of backing_dev
	 * which is smaller than block size.
	 */
	if (unlikely(block >= sb->max_bb))
		return -1;

	entry = sb->mappings[block / SC_CACHE_ENTRIES_PER_PAGE];
	entry += (block % SC_CACHE_ENTRIES_PER_PAGE);
retry:
	data = READ_ONCE(entry->cb);
	if (SC_CACHE_ENTRY_CB(data))
		return SC_CACHE_ENTRY_CB(data);

	if (SC_CACHE_ENTRY_ALLOCATING(data))
		goto spin;

	/*
	 * There could be multiple tasks encounter cache miss on
	 * the same block. Only let the winner do the allocation
	 * and others spin.
	 */
	if (cmpxchg(&entry->cb, data, SC_CACHE_ENTRY_CB_ALLOCATING) != data)
		goto retry;

	cb = sc_block_alloc(scbd);
	trace_printk("alloc cb %x %p\n", cb, current);
	if (cb < 0)
		data = 0;
	else
		data = cb;
	WRITE_ONCE(entry->cb, data);

	return cb;
spin:
	/*
	 * FIXME
	 *   I need a better way to wait the allocation completes
	 */
	preempt_disable();
	while (SC_CACHE_ENTRY_ALLOCATING(READ_ONCE(entry->cb))) {
		cpu_relax();
	}
	preempt_enable();
	goto retry;
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

	entry = sb->mappings[bblock / SC_CACHE_ENTRIES_PER_PAGE];
	entry += bblock % SC_CACHE_ENTRIES_PER_PAGE;
	entry->cb = cblock;
}

static int sc_handle_mapping_early(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	int i, len = sb->maplen / PAGE_SIZE;
	sc_entry_t *start, *end;
	struct sc_cache_info *sci;
	unsigned long cblock, bblock;
	uint32_t data;
	enum sci_state state;

	/*
	 * Pick the used blocks out of block allocator.
	 */
	cblock = 0;
	for (i = 0; i < len; i++) {
		start = page_address(sb->map_pages[i]);
		end = start + SC_MAPPING_ENTRIES_PER_PAGE;
		for (; start < end; start++) {
			data = READ_ONCE(start->data);
			if (SC_ENTRY_VALID(data)) {
				bblock = SC_ENTRY_BLOCK(data);
				if (bblock > sb->bmaplen/SC_CACHE_MAPPING_ENTRY_SIZE) {
					pr_err("mapping entry is corrupted %x\n", start->data);
					continue;
				}
				sc_block_set(scbd, cblock);
				sci = sc_get_cache_info(scbd, cblock);
				if (!sci) {
					pr_warn("Failed to get sci when handle mapping early %lx\n", cblock);
					continue;
				}
				state = SC_ENTRY_DIRTY(data) ? SCI_DIRTY:SCI_CLEAN;
				sci->status = SCI(0, 0, state);
				sci->bb = bblock; /* reverse mapping */
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

	/*
	 * We will passthrough the last unaligned blocks.
	 */
	blen = (backing_size << 9);
	blen = round_down(blen, sb->block_size);
	blen /= sb->block_size;
	sb->max_bb = blen;

	blen *= SC_CACHE_MAPPING_ENTRY_SIZE;

	pr_info("Backing device capacity %ld G in-core mapping %ld K\n",
		(backing_size << 9) >> 30, blen >> 10);
	sb->bmaplen = blen;
	/*
	 * We allocate this page by page, then it would be easier to get.
	 */
	blen /= PAGE_SIZE;
	blen += 1;
	pr_info("%ld 4K memory for mapping in-core\n", blen);
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
static void sc_readahead_log_page(struct sc_log_sb *sl)
{
	struct bio *bio;

	bio = bio_alloc(GFP_KERNEL, 1);
	bio->bi_iter.bi_sector = sl->log_offset[SL_RUN(sl)] + sl->log_start[SL_RUN(sl)];
	bio_set_dev(bio, sl->dev);
	bio_set_op_attrs(bio, REQ_OP_READ, REQ_META | REQ_SYNC);
	bio_add_page(bio, sl->log_page, PAGE_SIZE, 0);
	WARN_ON(submit_bio_wait(bio));
	bio_put(bio);
}

static void sc_log_replay_run(struct sc_log_sb *sl, int n)
{
	unsigned long ret;
	
	sl->toggle = n; /* toggle is running */

	ret = sc_patch_mapping(sl, n);
	sl->log_offset[SL_RUN(sl)] = (ret / SC_LOG_ENTRIES_PER_PAGE) * PAGE_SECTORS;
	sl->log_page_offset = ret & (SC_LOG_ENTRIES_PER_PAGE - 1);
	sc_readahead_log_page(sl);
	pr_info("run log %d total %ld offset %lx log page offset %x\n",
			n, ret, sl->log_offset[SL_RUN(sl)], sl->log_page_offset);
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
 * 2. patch the logs of which version is bigger than sb->mapping_gen on in-core mapping
 * 3. set the log with version sb->mapping_gen + 1 as patching log, and another as
 *    running one.
 * 4. figure out the postion we start to log in the running log
 */
static int sc_replay_log(struct sc_backing_dev *scbd)
{
	struct sc_sb *sb = scbd->sb;
	struct sc_log_sb *sl = &sb->log;
	int gen[2], patch = -1, run = -1;

	sc_get_log_gen(sl, gen);

	pr_info("log 0 gen %d log 1 gen %d sb mapping gen %d\n", gen[0], gen[1], sb->mapping_gen);

	/*
	 * Invalid gen number in log, so there is not any mapping in log space.
	 * This is the initial state.
	 */
	if (gen[0] == 0 && gen[1] == 0) {
		/*
		 * First valid gen number is 1
		 */
		sb->run_gen = 1;
		return 0;
	}
	/*
	 * FIXME:
	 *   Need to handle the overflow case.
	 */

	/*
	 * If both log gen numbers are bigger than sb mapping gen, it says patch has
	 * not completed.
	 */
	if (gen[0] > sb->mapping_gen && gen[1] > sb->mapping_gen) {
		/*
		 * log 0 is the first to be used by default
		 */
		if (gen[0] == sb->mapping_gen + 1) {
			patch = 0;
			WARN_ON(gen[1] != sb->mapping_gen + 2);
			run = 1;
		} else if (gen[1] == sb->mapping_gen + 1) {
			patch = 1;
			WARN_ON(gen[0] != sb->mapping_gen + 2);
			run = 0;
		} else {
			WARN_ON(1);
		}
	}

	if (gen[0] == sb->mapping_gen) {
		WARN_ON(gen[1] != sb->mapping_gen + 1);
		run = 1;
	}

	if (gen[1] == sb->mapping_gen) {
		WARN_ON(gen[0] != sb->mapping_gen + 1);
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
	 * gen than sb->mapping_gen and need to set the log_offset and log_page_offset.
	 */
	if (run >= 0)
		sc_log_replay_run(sl, run);

	sb->run_gen = gen[run];
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

	queue_delayed_work(sc_workqueue, &scbd->reclaim_work,
			SC_CACHE_RECLAIM_INTERVAL);
	/*
	 * writeabck is ready
	 */
	blk_mq_freeze_queue(scbd->front_queue);
	WRITE_ONCE(scbd->mode, SC_CACHE_WRITEBACK);
	blk_mq_unfreeze_queue(scbd->front_queue);

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
	cancel_delayed_work_sync(&scbd->reclaim_work);
	sc_drain_rcio(scbd);
	/*
	 * Drain all of the work in writeback and reclaim path,
	 * could ensure insert_work to be able to stopped.
	 * But we also need to sync (cancel should also be OK)
	 * the patch work.
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
	 * FIXME
	 *   When stop the cache, what should we do ?
	 *   Flush all of the cache out and set paththrough ?
	 *
	 *   Anyway, it is not safe to set to passthrough directly.
	 *   We set passthrough here just to avoid new work into sc_writeback.
	 *
	 *   drain all of the IO could ensure there is no pending work
	 *   in sc_writeback path.
	 */
	blk_mq_freeze_queue(scbd->front_queue);
	WRITE_ONCE(scbd->mode, SC_CACHE_PASSTHROUGH);
	blk_mq_unfreeze_queue(scbd->front_queue);
	/*
	 * Start write through mod
	 * then we could delete the caching device transparently
	 */

	/*
	 * Flush all of the pending and in-flight IO on backing and caching device
	 */

	sc_turndown_cache(scbd);
	sc_destroy_log(scbd);
	sc_put_sb(scbd);

	bd_unlink_disk_holder(scbd->caching_dev, scbd->front_disk);
	blkdev_put(scbd->caching_dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	scbd->caching_dev = NULL;

	/*
	 * Need some sync method against the hot path
	 */
	return len;
}

/*
 * FIXME:
 *
 * There is no protect against the cache stop
 */
static ssize_t sc_bd_map_show(struct sc_backing_dev *scbd, char *buf)
{
	unsigned long i = scbd->cb_offset;
	struct sc_cache_info *sci;

	printk("SC: dump valid mapping entries at jiffies %ld\n", jiffies);
	for (; i < scbd->scis_total; i++) {
		sci = sc_get_cache_info(scbd, i);
		if (SCI_STATE(sci->status))
			printk("[%x -> %x]: ac %d at %ld if %d s %s\n",
				sci->cb, sci->bb,
				SCI_HIT_COUNT(sci->status),
				sci->atime,
				SCI_INFLIGHT(sci->status),
				sci_state_strings[SCI_STATE(sci->status)]);
	}
	return 0;
}


static ssize_t sc_bd_blocks_show(struct sc_backing_dev *scbd, char *buf)
{
	int i;

	for (i = 0; i < SC_MAX_BITMAP_SLOTS; i++) {
		printk("slot %d available %d\n", i, atomic_read(&scbd->slots[i].available));
	}
	return 0;
}

static struct sc_sysfs_entry sc_bd_blocks = {
	.attr = {.name = "blocks", .mode = S_IRUSR},
	.show = sc_bd_blocks_show,
};

static struct sc_sysfs_entry sc_bd_map = {
	.attr = {.name = "map", .mode = S_IRUSR},
	.show = sc_bd_map_show,
};

static struct sc_sysfs_entry sc_bd_cache = {
	.attr = {.name = "cache", .mode = S_IWUSR },
	.store = sc_bd_cache_store,
};

static struct sc_sysfs_entry sc_bd_stop = {
	.attr = {.name = "stop", .mode = S_IWUSR },
	.store = sc_bd_stop_store,
};

static struct attribute *default_attrs[] = {
	&sc_bd_blocks.attr,
	&sc_bd_map.attr,
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
	//queue_flag_set_unlocked(QUEUE_FLAG_DISCARD,	q);
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

	INIT_DELAYED_WORK(&scbd->reclaim_work, sc_reclaim_work);
	spin_lock_init(&scbd->wb_lock);
	INIT_LIST_HEAD(&scbd->wb_pending);
	INIT_WORK(&scbd->wb_work, sc_wb_work);
	atomic_set(&scbd->rcio_running, 0);
	init_waitqueue_head(&scbd->rcio_wait);

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
