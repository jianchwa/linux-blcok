#include <linux/blkdev.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sysfs.h>
#include <asm/local.h>
#include <linux/blk-mq.h>

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

static int sc_setup_cache(struct sc_backing_dev *scbd)
{
	/*
	 * Read in the super block of the caching_dev (1st sector ?)
	 * If not there, setup a new one here.
	 */

	/*
	 * Read in the mapping
	 */

	/*
	 * Pick up the busy blocks and setup a freespace list
	 */

	/*
	 * writeabck is ready
	 */
	return 0;
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
	if (!err)
		goto fail;

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
	 * Free mapping data
	 * Free writeabck data
	 * Free freespace managment data
	 */
}

static ssize_t sc_bd_stop_store(struct sc_backing_dev *scbd,
		const char *buf, size_t len)
{
	/*
	 * Stop new IO on front disk
	 */

	/*
	 * Flush all of the pending and in-flight IO on backing and caching device
	 */

	sc_turndown_cache(scbd);
	blkdev_put(scbd->caching_dev, FMODE_READ|FMODE_WRITE|FMODE_EXCL);
	scbd->caching_dev = NULL;

	/*
	 * Start write through mod
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
