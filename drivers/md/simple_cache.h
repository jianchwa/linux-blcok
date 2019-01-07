#ifndef _SIMPLE_CACHE_H_
#define _SIMPLE_CACHE_H_

#define SC_MINORS 16 /* partition support */
#define SC_IO_POOL_MAX 64

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

struct sc_backing_dev {
	struct block_device *backing_dev;
	struct block_device *caching_dev;

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

#endif
