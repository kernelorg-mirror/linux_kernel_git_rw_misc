// SPDX-License-Identifier: GPL-2.0
/*
 * MUSE: MTD in userspace
 * Copyright (C) 2021 sigma star gmbh
 * Author: Richard Weinberger <richard@nod.at>
 */

#define pr_fmt(fmt) "MUSE: " fmt

#include <linux/fuse.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

#include "fuse_i.h"

/*
 * struct muse_conn - MUSE connection object.
 *
 * @fm: FUSE mount object.
 * @fc: FUSE connection object.
 * @mtd: MTD object.
 * @creator: PID of the creating process.
 * @want_exit: Denotes that userspace is disconncted and the MTD shall be
 * removed as soon the last user vanishes.
 * @mtd_registered: true if this MUSE connection sucessfully registered an MTD.
 * @mtd_exit_work: work context for async MTD removal.
 * @ref_mutex: synchronizes @want_exit and MTD put/get.
 *
 * Describes a connection to a userspace server.
 * Each connection implements a single (master) MTD.
 *
 */
struct muse_conn {
	struct fuse_mount fm;
	struct fuse_conn fc;
	struct mtd_info mtd;
	pid_t creator;
	bool want_exit;
	bool mtd_registered;
	struct work_struct mtd_exit_work;
	struct mutex ref_mutex;
};

/*
 * struct muse_init_args - MUSE init arguments.
 *
 * @ap: FUSE argument pages object.
 * @in: MUSE init parameters sent to userspace.
 * @out: MUSE init parameters sent from userspace.
 * @page: A single pages used to pass stringy key-value parameters
 *        from userspace to this module.
 * @desc: FUSE page description object.
 *
 * Descripes arguments used by the MUSE_INIT FUSE opcode.
 *
 */
struct muse_init_args {
	struct fuse_args_pages ap;
	struct muse_init_in in;
	struct muse_init_out out;
	struct page *page;
	struct fuse_page_desc desc;
};

/*
 * struct muse_mtd_create_req - MUSE MTD creation request.
 *
 * @name: Name of the (master) MTD, usually something like muse-<pid>.
 * @type: Type of the MTD, one out of MTD_RAM, MTD_ROM, MTD_NORFLASH,
 *        MTD_NANDFLASH, MTD_DATAFLASH or MTD_MLCNANDFLASH.
 * @size: Total size of the MTD.
 * @writesize: writesize of the MTD.
 * @writebufsize: writebufsize of the MTD, usually euqal to @writesize.
 * @erasesize: erasesize of the MTD.
 * @oobsize: Total number of out-of-band bytes per page (writesize),
 *           only useful for NAND style MTDs.
 * @oobavail: Number of available bytes in the out-of-band area.
 *            Only useful for NAND style MTDs.
 * @subpage_shift: Subpages shift value, either 0, 1 or 2. Only useful for
 *                 NAND style MTDs.
 * @mtdparts: mtdparts string *without* leading MTD name which describes
 *            partitioning of the MTD as understood by
 *            drivers/mtd/parsers/cmdlinepart.c.
 *
 * Describes the MTD as desired by userspace.
 *
 */
struct muse_mtd_create_req {
	const char *name;
	unsigned int type;
	uint32_t flags;
	uint64_t size;
	uint32_t writesize;
	uint32_t writebufsize;
	uint32_t erasesize;
	uint32_t oobsize;
	uint32_t oobavail;
	unsigned int subpage_shift;
	const char *mtdparts;
};

/*
 * struct muse_mtd_init_ctx
 *
 * @mtd_init_work: workqueue context object.
 * @pd: Extra parameters for the MTD partition parser, usually an mtdparts
 *      string.
 * @mc: MUSE connection this object belongs to.
 *
 * Describes the parameter object passed to a workqueue worker to create the
 * MTD asynchronously.
 *
 */
struct muse_mtd_init_ctx {
	struct work_struct mtd_init_work;
	struct mtd_part_parser_data pd;
	struct muse_conn *mc;
};

static void muse_fc_release(struct fuse_conn *fc)
{
	struct muse_conn *mc = container_of(fc, struct muse_conn, fc);

	WARN_ON_ONCE(mc->mtd.usecount);
	kfree_rcu(mc, fc.rcu);
}

static struct muse_conn *get_mc_from_mtd(struct mtd_info *mtd)
{
	struct mtd_info *master = mtd_get_master(mtd);

	return master->priv;
}

static int muse_mtd_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);
	struct fuse_mount *fm = &mc->fm;
	struct muse_erase_in inarg;
	FUSE_ARGS(args);
	ssize_t ret;

	inarg.addr = instr->addr;
	inarg.len = instr->len;

	args.opcode = MUSE_ERASE;
	args.nodeid = FUSE_ROOT_ID;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;

	ret = fuse_simple_request(fm, &args);
	if (ret < 0)
		return ret;

	return 0;
}

static int muse_mtd_markbad(struct mtd_info *mtd, loff_t addr)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);
	struct fuse_mount *fm = &mc->fm;
	struct muse_markbad_in inarg;
	FUSE_ARGS(args);
	ssize_t ret;

	inarg.addr = addr;

	args.opcode = MUSE_MARKBAD;
	args.nodeid = FUSE_ROOT_ID;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;

	ret = fuse_simple_request(fm, &args);
	if (ret < 0)
		return ret;

	return 0;
}

static int muse_mtd_isbad(struct mtd_info *mtd, loff_t addr)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);
	struct fuse_mount *fm = &mc->fm;
	struct muse_isbad_in inarg;
	struct muse_isbad_out outarg;
	FUSE_ARGS(args);
	ssize_t ret;

	inarg.addr = addr;

	args.opcode = MUSE_ISBAD;
	args.nodeid = FUSE_ROOT_ID;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;
	args.out_numargs = 1;
	args.out_args[0].size = sizeof(outarg);
	args.out_args[0].value = &outarg;

	ret = fuse_simple_request(fm, &args);
	if (ret < 0)
		return ret;

	return outarg.result;
}

static void muse_mtd_sync(struct mtd_info *mtd)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);
	struct fuse_mount *fm = &mc->fm;
	FUSE_ARGS(args);

	args.opcode = MUSE_SYNC;
	args.nodeid = FUSE_ROOT_ID;
	args.in_numargs = 0;

	fuse_simple_request(fm, &args);
}

static ssize_t muse_send_write(struct fuse_args_pages *ap, struct fuse_mount *fm,
			       loff_t from, size_t count, int flags, int *soft_error)
{
	struct fuse_args *args = &ap->args;
	ssize_t ret;

	struct muse_write_in in;
	struct muse_write_out out;

	in.addr = from;
	in.len = count;
	in.flags = flags;
	args->opcode = MUSE_WRITE;
	args->nodeid = FUSE_ROOT_ID;
	args->in_numargs = 2;
	args->in_args[0].size = sizeof(in);
	args->in_args[0].value = &in;
	/*
	 * args->in_args[1].value was set in set_ap_inout_bufs()
	 */
	args->in_args[1].size = count;
	args->out_numargs = 1;
	args->out_args[0].size = sizeof(out);
	args->out_args[0].value = &out;

	ret = fuse_simple_request(fm, &ap->args);
	if (ret < 0)
		goto out;

	ret = out.len;
	*soft_error = out.soft_error;

out:
	return ret;
}

static ssize_t muse_send_read(struct fuse_args_pages *ap, struct fuse_mount *fm,
			      loff_t from, size_t count, int flags, int *soft_error)
{
	struct fuse_args *args = &ap->args;
	ssize_t ret;

	struct muse_read_in in;
	struct muse_read_out out;

	in.addr = from;
	in.len = count;
	in.flags = flags;
	args->opcode = MUSE_READ;
	args->nodeid = FUSE_ROOT_ID;
	args->in_numargs = 1;
	args->in_args[0].size = sizeof(in);
	args->in_args[0].value = &in;
	args->out_argvar = true;
	args->out_numargs = 2;
	args->out_args[0].size = sizeof(out);
	args->out_args[0].value = &out;
	/*
	 * args->out_args[1].value was set in set_ap_inout_bufs()
	 */
	args->out_args[1].size = count;

	ret = fuse_simple_request(fm, &ap->args);
	if (ret < 0)
		goto out;

	ret = out.len;
	*soft_error = out.soft_error;

out:
	return ret;
}

/*
 * set_ap_inout_bufs - Set in/out buffers for fuse args
 *
 * @ap: FUSE args pages object
 * @iter: IOV iter which describes source/destination of the IO operation
 * @count: Inputs the max amount of data we can process,
 *	   outputs the amount of data @iter has left.
 * @write: If non-zero, this is a write operation, read otherwise.
 *
 * This function takes a IOV iter object and sets up FUSE args pointer.
 * Since in MTD all buffers are kernel memory we can directly use
 * fuse_get_user_addr().
 */
static void set_ap_inout_bufs(struct fuse_args_pages *ap, struct iov_iter *iter,
			      size_t *count, int write)
{
	unsigned long addr;
	size_t frag_size;

	addr = fuse_get_user_addr(iter);
	frag_size = fuse_get_frag_size(iter, *count);

	if (write)
		ap->args.in_args[1].value = (void *)addr;
	else
		ap->args.out_args[1].value = (void *)addr;

	iov_iter_advance(iter, frag_size);
	*count = frag_size;
}

/*
 * muse_do_io - MUSE main IO processing function.
 *
 * @mc: MUSE connection object.
 * @ops: MTD read/write operation object.
 * @pos: Where to start reading/writing on the MTD.
 * @write: If non-zero, this is a write operation, read otherwise.
 *
 * This function is responsible for processing reads and writes to the MTD.
 * It directly takes @pos and @ops from the MTD subsystem.
 * All IO is synchronous and buffers provided by @ops have to be kernel memory.
 * The userspace server can inject also custom errors into the IO path,
 * mostly -EUCLEAN to signal fixed bit-flips or -EBADMSG for uncorrectable
 * bit-flips.
 *
 */
static int muse_do_io(struct muse_conn *mc, struct mtd_oob_ops *ops,
		      loff_t pos, int write)
{
	struct fuse_mount *fm = &mc->fm;
	struct fuse_conn *fc = &mc->fc;
	size_t fc_max_io = write ? fc->max_write : fc->max_read;
	struct fuse_args_pages ap;
	int oob = !!ops->ooblen;
	unsigned int max_pages;
	struct iov_iter iter;
	struct kvec iov;
	size_t count;
	size_t retlen = 0;
	int bitflips = 0;
	int eccerrors = 0;
	int retcode = 0;
	int io_mode = 0;
	ssize_t ret = 0;

	/*
	 * We don't support accessing in- and out-of-band data in the same op.
	 * AFAICT FUSE does not support attaching two variable sized buffers to
	 * a request.
	 */
	if ((ops->len && ops->ooblen) || (ops->datbuf && ops->oobbuf)) {
		ret = -ENOTSUPP;
		goto out;
	}

	if (!oob) {
		iov.iov_base = ops->datbuf;
		iov.iov_len = ops->len;
		iov_iter_kvec(&iter, write ? WRITE : READ, &iov, 1, ops->len);

		/*
		 * When ops->ooblen is not set, we don't care about
		 * MTD_OPS_PLACE_OOB vs. MTD_OPS_AUTO_OOB.
		 */
		io_mode |= MUSE_IO_INBAND;
		if (ops->mode == MTD_OPS_RAW)
			io_mode |= MUSE_IO_RAW;
	} else {
		iov.iov_base = ops->oobbuf;
		iov.iov_len = ops->ooblen;
		iov_iter_kvec(&iter, write ? WRITE : READ, &iov, 1, ops->ooblen);

		/*
		 * When accessing OOB we just move the address by ooboffs.
		 * This works because oobsize is smaller than writesize.
		 */
		pos += ops->ooboffs;

		if (ops->mode == MTD_OPS_PLACE_OOB) {
			io_mode |= MUSE_IO_OOB_PLACE;
		} else if (ops->mode == MTD_OPS_AUTO_OOB) {
			io_mode |= MUSE_IO_OOB_AUTO;
		} else if (ops->mode == MTD_OPS_RAW) {
			io_mode |= MUSE_IO_OOB_PLACE | MUSE_IO_RAW;
		} else {
			ret = -ENOTSUPP;
			goto out;
		}
	}

	/*
	 * A full page needs to fit into a single FUSE request.
	 */
	if (fc_max_io < mc->mtd.writebufsize) {
		ret = -ENOBUFS;
		goto out;
	}

	count = iov_iter_count(&iter);

	max_pages = iov_iter_npages(&iter, fc->max_pages);
	memset(&ap, 0, sizeof(ap));

	ap.pages = fuse_pages_alloc(max_pages, GFP_KERNEL, &ap.descs);
	if (!ap.pages) {
		ret = -ENOMEM;
		goto out;
	}

	while (count) {
		size_t nbytes = min_t(size_t, count, fc_max_io);
		int soft_error = 0;

		set_ap_inout_bufs(&ap, &iter, &nbytes, write);

		if (write)
			ret = muse_send_write(&ap, fm, pos, nbytes, io_mode, &soft_error);
		else
			ret = muse_send_read(&ap, fm, pos, nbytes, io_mode, &soft_error);

		kfree(ap.pages);
		ap.pages = NULL;

		if (ret < 0) {
			iov_iter_revert(&iter, nbytes);
			break;
		}

		if (soft_error) {
			/*
			 * Userspace wants to inject an error code.
			 */

			if (write) {
				/*
				 * For writes, take it as-is.
				 */
				ret = soft_error;
				break;
			}

			/*
			 * -EUCLEAN and -EBADMSG are special for reads
			 * in MTD, it expects from a device to return all
			 * requsted data even if there are (un)correctable errors.
			 * The upper layer, such as UBI, has to deal with them.
			 */
			if (soft_error == -EUCLEAN) {
				bitflips++;
			} else if (soft_error == -EBADMSG) {
				eccerrors++;
			} else {
				ret = soft_error;
				break;
			}
		}

		/*
		 * No short reads are allowed in MTD.
		 */
		if (ret != nbytes) {
			iov_iter_revert(&iter, nbytes - ret);
			ret = -EIO;
			break;
		}

		count -= ret;
		retlen += ret;
		pos += ret;

		if (count) {
			max_pages = iov_iter_npages(&iter, fc->max_pages);
			memset(&ap, 0, sizeof(ap));
			ap.pages = fuse_pages_alloc(max_pages, GFP_KERNEL, &ap.descs);
			if (!ap.pages)
				break;
		}
	}

	kfree(ap.pages);

	if (bitflips)
		retcode = -EUCLEAN;
	if (eccerrors)
		retcode = -EBADMSG;

out:
	/*
	 * If ret is set, it must be a fatal error which overrides
	 * -EUCLEAN and -EBADMSG.
	 */
	if (ret < 0)
		retcode = ret;

	if (oob)
		ops->oobretlen = retlen;
	else
		ops->retlen = retlen;

	return retcode;
}

static int muse_mtd_read_oob(struct mtd_info *mtd, loff_t from, struct mtd_oob_ops *ops)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);

	return muse_do_io(mc, ops, from, 0);
}

static int muse_mtd_write_oob(struct mtd_info *mtd, loff_t to, struct mtd_oob_ops *ops)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);

	return muse_do_io(mc, ops, to, 1);
}

static int muse_mtd_get_device(struct mtd_info *mtd)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);
	int ret = 0;

	mutex_lock(&mc->ref_mutex);

	/*
	 * Refuse a new reference if userspace is no longer connected.
	 */
	if (mc->want_exit) {
		ret = -ENODEV;
		goto out;
	}

	fuse_conn_get(&mc->fc);

out:
	mutex_unlock(&mc->ref_mutex);
	return ret;
}

static ssize_t muse_pid_show(struct device *dev, struct device_attribute *attr,
			     char *buf)
{
	struct mtd_info *mtd = dev_get_drvdata(dev);
	struct muse_conn *mc = container_of(mtd_get_master(mtd), struct muse_conn, mtd);

	return sprintf(buf, "%d\n", mc->creator);
}

static DEVICE_ATTR_RO(muse_pid);

static int install_sysfs_attrs(struct mtd_info *mtd)
{
	bool part_master = IS_ENABLED(CONFIG_MTD_PARTITIONED_MASTER);
	struct mtd_info *child;
	int ret = 0;

	/*
	 * Create the sysfs file only for visible MTDs, on the master device only
	 * if CONFIG_MTD_PARTITIONED_MASTER enabled or it is unpartitioned.
	 */
	if (part_master || list_empty(&mtd->partitions)) {
		ret = sysfs_create_file(&mtd->dev.kobj, &dev_attr_muse_pid.attr);
		if (ret || !part_master)
			goto out;
	}

	/*
	 * ... and to all partitions, if there are any.
	 */
	list_for_each_entry(child, &mtd->partitions, part.node) {
		ret = sysfs_create_file(&child->dev.kobj, &dev_attr_muse_pid.attr);
		if (ret)
			break;
	}

out:
	return ret;
}

static void remove_sysfs_attrs(struct mtd_info *mtd)
{
	bool part_master = IS_ENABLED(CONFIG_MTD_PARTITIONED_MASTER);
	struct mtd_info *child;

	/*
	 * Same logic as in install_sysfs_attrs().
	 */
	if (part_master || list_empty(&mtd->partitions)) {
		sysfs_remove_file(&mtd->dev.kobj, &dev_attr_muse_pid.attr);
		if (!part_master)
			return;
	}

	list_for_each_entry(child, &mtd->partitions, part.node) {
		sysfs_remove_file(&child->dev.kobj, &dev_attr_muse_pid.attr);
	}
}

static void muse_exit_mtd_work(struct work_struct *work)
{
	struct muse_conn *mc = container_of(work, struct muse_conn, mtd_exit_work);

	if (mc->mtd_registered) {
		remove_sysfs_attrs(&mc->mtd);
		mtd_device_unregister(&mc->mtd);
		kfree(mc->mtd.name);
	}
	fuse_conn_put(&mc->fc);
}

/*
 * MTD deregristation has to happen asynchronously.
 * It will grap mtd_table_mutex but depending on the context
 * we hold it already or hold mc->ref_mutex.
 * The locking order is mtd_table_mutex > mc->ref_mutex.
 */
static void muse_remove_mtd_async(struct muse_conn *mc)
{
	INIT_WORK(&mc->mtd_exit_work, muse_exit_mtd_work);
	schedule_work(&mc->mtd_exit_work);
}

static void muse_mtd_put_device(struct mtd_info *mtd)
{
	struct muse_conn *mc = get_mc_from_mtd(mtd);

	mutex_lock(&mc->ref_mutex);

	if (mc->want_exit && mc->mtd.usecount == 0) {
		/*
		 * This was the last reference on the MTD, remove it now.
		 */
		muse_remove_mtd_async(mc);
	} else {
		/*
		 * The MTD has users or userspace is still connected,
		 * keep the MTD and just decrement the FUSE connection
		 * reference counter.
		 */
		fuse_conn_put(&mc->fc);
	}
	mutex_unlock(&mc->ref_mutex);
}

static int muse_verify_mtdreq(struct muse_mtd_create_req *req)
{
	int ret = -EINVAL;
	uint64_t tmp;

	if (!req->name)
		goto out;

	if (!req->size || !req->writesize || !req->erasesize)
		goto out;

	tmp = req->size;
	if (do_div(tmp, req->writesize))
		goto out;

	tmp = req->size;
	if (do_div(tmp, req->erasesize))
		goto out;

	if (req->oobsize < req->oobavail)
		goto out;

	if (req->oobsize >= req->writesize)
		goto out;

	if (req->flags & ~(MTD_WRITEABLE | MTD_BIT_WRITEABLE | MTD_NO_ERASE))
		goto out;

	if (req->subpage_shift > 2)
		goto out;

	switch (req->type) {
	case MTD_RAM:
	case MTD_ROM:
	case MTD_NORFLASH:
	case MTD_NANDFLASH:
	case MTD_DATAFLASH:
	case MTD_MLCNANDFLASH:
		break;
	default:
		goto out;
	}

	ret = 0;

out:
	return ret;
}

static int muse_parse_mtdreq(char *p, size_t len, struct mtd_info *mtd,
			    struct mtd_part_parser_data *pd)
{
	struct muse_mtd_create_req req = {0};
	char *end = p + len;
	char *key, *val;
	int ret;

	for (;;) {
		ret = fuse_kv_parse_one(&p, end, &key, &val);
		if (ret < 0)
			goto out;
		if (!ret)
			break;

		if (strcmp(key, "NAME") == 0) {
			req.name = val;
		} else if (strcmp(key, "TYPE") == 0) {
			unsigned int type;

			ret = kstrtouint(val, 10, &type);
			if (ret)
				goto out;

			req.type = type;
		} else if (strcmp(key, "FLAGS") == 0) {
			ret = kstrtou32(val, 10, &req.flags);
			if (ret)
				goto out;
		} else if (strcmp(key, "SIZE") == 0) {
			ret = kstrtou64(val, 10, &req.size);
			if (ret)
				goto out;
		} else if (strcmp(key, "WRITESIZE") == 0) {
			ret = kstrtou32(val, 10, &req.writesize);
			if (ret)
				goto out;
		} else if (strcmp(key, "WRITEBUFSIZE") == 0) {
			ret = kstrtou32(val, 10, &req.writebufsize);
			if (ret)
				goto out;
		} else if (strcmp(key, "OOBSIZE") == 0) {
			ret = kstrtou32(val, 10, &req.oobsize);
			if (ret)
				goto out;
		} else if (strcmp(key, "OOBAVAIL") == 0) {
			ret = kstrtou32(val, 10, &req.oobavail);
			if (ret)
				goto out;
		} else if (strcmp(key, "ERASESIZE") == 0) {
			ret = kstrtou32(val, 10, &req.erasesize);
			if (ret)
				goto out;
		} else if (strcmp(key, "SUBPAGESHIFT") == 0) {
			ret = kstrtouint(val, 10, &req.subpage_shift);
			if (ret)
				goto out;
		} else if (strcmp(key, "PARTSCMDLINE") == 0) {
			req.mtdparts = val;
		} else {
			pr_warn("Ignoring unknown MTD param \"%s\"\n", key);
		}
	}

	if (req.name && req.mtdparts && strlen(req.mtdparts) > 0) {
		pd->mtdparts = kasprintf(GFP_KERNEL, "%s:%s", req.name, req.mtdparts);
		if (!pd->mtdparts) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = muse_verify_mtdreq(&req);
	if (ret)
		goto out;

	mtd->name = kstrdup(req.name, GFP_KERNEL);
	if (!mtd->name) {
		kfree(pd->mtdparts);
		ret = -ENOMEM;
		goto out;
	}

	mtd->size = req.size;
	mtd->erasesize = req.erasesize;
	mtd->writesize = req.writesize;

	if (req.writebufsize)
		mtd->writebufsize = req.writebufsize;
	else
		mtd->writebufsize = mtd->writesize;

	mtd->oobsize = req.oobsize;
	mtd->oobavail = req.oobavail;
	mtd->subpage_sft = req.subpage_shift;

	mtd->type = req.type;
	mtd->flags = MTD_MUSE | req.flags;

	ret = 0;
out:
	return ret;
}

static void muse_init_mtd_work(struct work_struct *work)
{
	struct muse_mtd_init_ctx *ctx = container_of(work, struct muse_mtd_init_ctx, mtd_init_work);
	static const char * const part_probe_types[] = { "cmdlinepart", NULL };
	struct muse_conn *mc = ctx->mc;

	if (mtd_device_parse_register(&mc->mtd, part_probe_types, &ctx->pd, NULL, 0) != 0)
		goto abort;

	if (install_sysfs_attrs(&mc->mtd))
		goto abort;

	goto free_mtdparts;

abort:
	fuse_abort_conn(&mc->fc);

free_mtdparts:
	mc->mtd_registered = true;
	kfree(ctx->pd.mtdparts);
	kfree(ctx);
}

static void muse_process_init_reply(struct fuse_mount *fm,
				    struct fuse_args *args, int error)
{
	struct fuse_conn *fc = fm->fc;
	struct muse_init_args *mia = container_of(args, struct muse_init_args, ap.args);
	struct muse_conn *mc = container_of(fc, struct muse_conn, fc);
	struct fuse_args_pages *ap = &mia->ap;
	struct muse_init_out *arg = &mia->out;
	struct page *page = ap->pages[0];
	struct mtd_info *mtd = &mc->mtd;
	struct muse_mtd_init_ctx *init_ctx = NULL;
	int ret;

	init_ctx = kzalloc(sizeof(*init_ctx), GFP_KERNEL);
	if (!init_ctx)
		goto abort;

	init_ctx->mc = mc;

	if (error || arg->fuse_major != FUSE_KERNEL_VERSION || arg->fuse_minor < 34)
		goto free_ctx;

	fc->minor = arg->fuse_minor;
	fc->max_read = max_t(unsigned int, arg->max_read, 4096);
	fc->max_write = max_t(unsigned int, arg->max_write, 4096);

	ret = muse_parse_mtdreq(page_address(page), ap->args.out_args[1].size,
				mtd, &init_ctx->pd);
	if (ret)
		goto free_ctx;

	mtd->_erase = muse_mtd_erase;
	mtd->_sync = muse_mtd_sync;
	mtd->_read_oob = muse_mtd_read_oob;
	mtd->_write_oob = muse_mtd_write_oob;
	mtd->_get_device = muse_mtd_get_device;
	mtd->_put_device = muse_mtd_put_device;

	/*
	 * Bad blocks make only sense on NAND devices.
	 * As soon _block_isbad is set, upper layer such as
	 * UBI expects a working _block_isbad, so userspace
	 * has to implement MUSE_ISBAD.
	 */
	if (mtd_type_is_nand(mtd)) {
		mtd->_block_isbad = muse_mtd_isbad;
		mtd->_block_markbad = muse_mtd_markbad;
	}

	mtd->priv = mc;
	mtd->owner = THIS_MODULE;

	/*
	 * We want one READ/WRITE op per MTD io. So the MTD pagesize needs
	 * to fit into max_write/max_read
	 */
	if (fc->max_write < mtd->writebufsize || fc->max_read < mtd->writebufsize)
		goto free_name;

	mc->creator = task_tgid_vnr(current);

	kfree(mia);
	__free_page(page);

	INIT_WORK(&init_ctx->mtd_init_work, muse_init_mtd_work);

	/*
	 * MTD can access the device while probing it.
	 * e.g. scanning for bad blocks or custom partition parsers.
	 * So we need to do the final step in a different process
	 * context. Otherwise we will lockup here if the userspace
	 * side of this MUSE MTD is single threaded.
	 */
	schedule_work(&init_ctx->mtd_init_work);
	return;

free_name:
	kfree(mtd->name);
free_ctx:
	kfree(init_ctx);
abort:
	kfree(mia);
	__free_page(page);
	fuse_abort_conn(fc);
}

static int muse_send_init(struct muse_conn *mc)
{
	struct fuse_mount *fm = &mc->fm;
	struct fuse_args_pages *ap;
	struct muse_init_args *mia;
	struct page *page;
	int ret = -ENOMEM;

	BUILD_BUG_ON(MUSE_INIT_INFO_MAX > PAGE_SIZE);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto err;

	mia = kzalloc(sizeof(*mia), GFP_KERNEL);
	if (!mia)
		goto err_page;

	ap = &mia->ap;
	mia->in.fuse_major = FUSE_KERNEL_VERSION;
	mia->in.fuse_minor = FUSE_KERNEL_MINOR_VERSION;
	ap->args.opcode = MUSE_INIT;
	ap->args.in_numargs = 1;
	ap->args.in_args[0].size = sizeof(mia->in);
	ap->args.in_args[0].value = &mia->in;
	ap->args.out_numargs = 2;
	ap->args.out_args[0].size = sizeof(mia->out);
	ap->args.out_args[0].value = &mia->out;
	ap->args.out_args[1].size = MUSE_INIT_INFO_MAX;
	ap->args.out_argvar = true;
	ap->args.out_pages = true;
	ap->num_pages = 1;
	ap->pages = &mia->page;
	ap->descs = &mia->desc;
	mia->page = page;
	mia->desc.length = ap->args.out_args[1].size;
	ap->args.end = muse_process_init_reply;

	ret = fuse_simple_background(fm, &ap->args, GFP_KERNEL);
	if (ret)
		goto err_ia;

	return 0;

err_ia:
	kfree(mia);
err_page:
	__free_page(page);
err:
	return ret;
}

static int muse_ctrl_open(struct inode *inode, struct file *file)
{
	struct muse_conn *mc;
	struct fuse_dev *fud;
	int ret;

	/*
	 * Paranoia check.
	 */
	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto err;
	}

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc) {
		ret = -ENOMEM;
		goto err;
	}

	mutex_init(&mc->ref_mutex);

	fuse_conn_init(&mc->fc, &mc->fm, get_user_ns(&init_user_ns),
		       &fuse_dev_fiq_ops, NULL);

	fud = fuse_dev_alloc_install(&mc->fc);
	if (!fud) {
		ret = -ENOMEM;
		goto err_free;
	}

	mc->fc.release = muse_fc_release;
	mc->fc.initialized = 1;

	ret = muse_send_init(mc);
	if (ret)
		goto err_dev;

	file->private_data = fud;

	return 0;

err_dev:
	fuse_dev_free(fud);
	fuse_conn_put(&mc->fc);
err_free:
	kfree(mc);
err:
	return ret;
}

static int muse_ctrl_release(struct inode *inode, struct file *file)
{
	struct fuse_dev *fud = file->private_data;
	struct muse_conn *mc = container_of(fud->fc, struct muse_conn, fc);

	mutex_lock(&mc->ref_mutex);
	/*
	 * Make sure that nobody can gain a new reference on our MTD.
	 */
	mc->want_exit = true;

	/*
	 * If the MTD has no users, remove it right now, keep it otherwise
	 * until the last user is gone. During this phase all operations will
	 * fail with -ENOTCONN.
	 */
	if (mc->mtd.usecount == 0)
		muse_remove_mtd_async(mc);
	else
		fuse_conn_put(&mc->fc);
	mutex_unlock(&mc->ref_mutex);

	return fuse_dev_release(inode, file);
}

static struct file_operations muse_ctrl_fops;

static struct miscdevice muse_ctrl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "muse",
	.fops = &muse_ctrl_fops,
};

static int __init muse_init(void)
{
	/*
	 * Inherit from fuse_dev_operations and override open() plus release().
	 */
	muse_ctrl_fops = fuse_dev_operations;
	muse_ctrl_fops.owner = THIS_MODULE;
	muse_ctrl_fops.open = muse_ctrl_open;
	muse_ctrl_fops.release = muse_ctrl_release;

	return misc_register(&muse_ctrl_dev);
}

static void __exit muse_exit(void)
{
	misc_deregister(&muse_ctrl_dev);
}

module_init(muse_init);
module_exit(muse_exit);

MODULE_AUTHOR("Richard Weinberger <richard@nod.at>");
MODULE_DESCRIPTION("MTD in userspace");
MODULE_LICENSE("GPL");
