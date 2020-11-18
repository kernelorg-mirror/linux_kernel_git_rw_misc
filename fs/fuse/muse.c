// SPDX-License-Identifier: GPL-2.0
/*
 * MUSE: MTD in userspace
 * Copyright (C) 2020 sigma star gmbh
 * Author: Richard Weinberger <richard@nod.at>
 */

#define pr_fmt(fmt) "MUSE: " fmt

#include <linux/anon_inodes.h>
#include <linux/fuse.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/slab.h>

#include "fuse_i.h"

static struct file_operations muse_ctrl_fops;

struct muse_conn {
	struct fuse_mount fm;
	struct fuse_conn fc;
	struct fuse_file *ff;
	struct mtd_info mtd;
	struct file *dummy_file;
	bool init_done;
};

struct muse_init_args {
	struct fuse_args_pages ap;
	struct muse_init_in in;
	struct muse_init_out out;
	struct page *page;
	struct fuse_page_desc desc;
};

static int dummy_file_open(struct inode *inode, struct file *filp)
{
	WARN_ON_ONCE(1);
	return -EIO;
}

static const struct file_operations dummy_file_ops = {
	.open = dummy_file_open,
};

static void muse_fc_release(struct fuse_conn *fc)
{
	struct muse_conn *mc = container_of(fc, struct muse_conn, fc);

	fput(mc->dummy_file);
	kfree_rcu(mc, fc.rcu);
}

static int muse_mtd_erase(struct mtd_info *mtd, struct erase_info *instr)
{
	struct muse_conn *mc = mtd->priv;
	struct fuse_mount *fm = &mc->fm;
	struct muse_erase_in inarg;
	FUSE_ARGS(args);

	inarg.addr = instr->addr;
	inarg.len = instr->len;

	args.opcode = MUSE_ERASE;
	args.nodeid = mc->ff->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;

	return fuse_simple_request(fm, &args);
}

static void muse_mtd_sync(struct mtd_info *mtd)
{
	struct muse_conn *mc = mtd->priv;
	struct fuse_mount *fm = &mc->fm;
	struct fuse_fsync_in inarg;
	FUSE_ARGS(args);

	memset(&inarg, 0, sizeof(inarg));
	inarg.fh = mc->ff->fh;
	inarg.fsync_flags = 0;

	/*
	 * We reuse FUSE_FSYNC to sync the whole MTD.
	 */
	args.opcode = FUSE_FSYNC;
	args.nodeid = mc->ff->nodeid;
	args.in_numargs = 1;
	args.in_args[0].size = sizeof(inarg);
	args.in_args[0].value = &inarg;

	fuse_simple_request(fm, &args);
}

static int do_dio(struct kiocb *kiocb, struct iov_iter *iter, loff_t *pos, int flags)
{
	struct fuse_io_priv io = FUSE_IO_PRIV_SYNC(kiocb);

	return fuse_direct_io(&io, iter, pos, flags);
}

static int muse_mtd_read(struct mtd_info *mtd, loff_t from, size_t len,
			 size_t *retlen, u_char *buf)
{
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	struct muse_conn *mc = mtd->priv;
	struct kiocb kiocb;
	struct iov_iter to;
	loff_t pos = from;
	int ret;

	iov_iter_kvec(&to, READ, &iov, 1, len);
	init_sync_kiocb(&kiocb, mc->dummy_file);

	ret = do_dio(&kiocb, &to, &pos, FUSE_DIO_NOFS);

	*retlen = len;
	return len;
}

static int muse_mtd_write(struct mtd_info *mtd, loff_t to, size_t len,
			  size_t *retlen, const u_char *buf)
{
	struct kvec iov = { .iov_base = (u_char *)buf, .iov_len = len };
	struct muse_conn *mc = mtd->priv;
	struct iov_iter from;
	struct kiocb kiocb;
	loff_t pos = to;
	int ret;

	iov_iter_kvec(&from, WRITE, &iov, 1, len);
	init_sync_kiocb(&kiocb, mc->dummy_file);

	ret = do_dio(&kiocb, &from, &pos, FUSE_DIO_WRITE | FUSE_DIO_NOFS);

	*retlen = len;
	return 0;
}

static int muse_mtd_get_device(struct mtd_info *mtd)
{
	struct muse_conn *mc = mtd->priv;

	fuse_conn_get(&mc->fc);

	return 0;
}

static void muse_mtd_put_device(struct mtd_info *mtd)
{
	struct muse_conn *mc = mtd->priv;

	fuse_conn_put(&mc->fc);
}

struct mtdreq {
	const char *name;
	struct mtd_info_user mi;
};

static int muse_parse_mtdreq(char *p, size_t len, struct mtd_info *mtd)
{
	struct mtdreq req = {};
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
			req.mi.type = (uint8_t)simple_strtoul(val, NULL, 10);
		} else if (strcmp(key, "FLAGS") == 0) {
			req.mi.flags = simple_strtoul(val, NULL, 10);
		} else if (strcmp(key, "SIZE") == 0) {
			req.mi.size = simple_strtoul(val, NULL, 10);
		} else if (strcmp(key, "WRITESIZE") == 0) {
			req.mi.writesize = simple_strtoul(val, NULL, 10);
		} else if (strcmp(key, "ERASESIZE") == 0) {
			req.mi.erasesize = simple_strtoul(val, NULL, 10);
		} else {
			pr_warn("Ignoring unknown MTD param \"%s\"\n", key);
		}
	}

	ret = -EINVAL;

	if (!req.name)
		goto out;

	if (!req.mi.size || !req.mi.writesize || !req.mi.erasesize)
		goto out;

	if (req.mi.size % req.mi.writesize)
		goto out;

	if (req.mi.size % req.mi.erasesize)
		goto out;

	if (req.mi.flags & ~(MTD_WRITEABLE | MTD_BIT_WRITEABLE | MTD_NO_ERASE))
		goto out;

	if (req.mi.type == MTD_ABSENT || req.mi.type == MTD_UBIVOLUME)
		goto out;

	mtd->name = kstrdup(req.name, GFP_KERNEL);
	if (!mtd->name) {
		ret = -ENOMEM;
		goto out;
	}

	mtd->size = req.mi.size;
	mtd->erasesize = req.mi.erasesize;
	mtd->writesize = req.mi.writesize;
	mtd->writebufsize = mtd->writesize;
	mtd->type = req.mi.type;
	mtd->flags = MTD_MUSE | req.mi.flags;

	ret = 0;
out:
	return ret;
}

static void muse_process_init_reply(struct fuse_mount *fm,
				    struct fuse_args *args, int error)
{
	struct fuse_conn *fc = fm->fc;
	struct muse_init_args *ia = container_of(args, struct muse_init_args, ap.args);
	struct muse_conn *mc = container_of(fc, struct muse_conn, fc);
	struct fuse_args_pages *ap = &ia->ap;
	struct muse_init_out *arg = &ia->out;
	struct page *page = ap->pages[0];
	int ret;

	if (error || arg->fuse_major != FUSE_KERNEL_VERSION || arg->fuse_minor < 33) {
		goto abort;
	}

	fc->minor = arg->fuse_minor;
	fc->max_read = max_t(unsigned int, arg->max_read, 4096);
	fc->max_write = max_t(unsigned int, arg->max_write, 4096);

        ret = muse_parse_mtdreq(page_address(page), ap->args.out_args[1].size,
				&mc->mtd);
	if (ret)
		goto abort;

	mc->ff = fuse_file_alloc(fm);
	if (!mc->ff)
		goto abort;

	/*
	 * HACK:
	 * fuse_direct_io() expects a file object.
	 */
	mc->dummy_file = anon_inode_getfile("[muse]", &dummy_file_ops, NULL, O_RDWR);
	if (!mc->dummy_file)
		goto abort_free_ff;

	mc->dummy_file->private_data = mc->ff;

	mc->ff->fh = 0;
	mc->ff->open_flags = FOPEN_DIRECT_IO;

	/*
	 * With MUSE there are no files, so we use one fuse file for the mtd object
	 * with nodeid FUSE_ROOT_ID.
	 */
	mc->ff->nodeid = FUSE_ROOT_ID;

	mc->mtd._erase = muse_mtd_erase;
	mc->mtd._read = muse_mtd_read;
	mc->mtd._sync = muse_mtd_sync;
	mc->mtd._write = muse_mtd_write;
	mc->mtd._get_device = muse_mtd_get_device;
	mc->mtd._put_device = muse_mtd_put_device;
	mc->mtd.priv = mc;
	mc->mtd.owner = THIS_MODULE;

	/*
	 * We want one READ/WRITE op per MTD io. So the MTD pagesize needs
	 * to fit into max_write/max_read:
	 */
	if (fc->max_write < mc->mtd.writesize || fc->max_read < mc->mtd.writesize)
		goto abort_put_file;

	if (mtd_device_register(&mc->mtd, NULL, 0) != 0)
		goto abort_put_file;

	mc->init_done = true;

	kfree(ia);
	__free_page(page);
	return;

abort_put_file:
	fput(mc->dummy_file);
abort_free_ff:
	fuse_file_free(mc->ff);
abort:
	fuse_abort_conn(fc);
}

static int muse_send_init(struct muse_conn *mc)
{
	struct fuse_mount *fm = &mc->fm;
	struct fuse_args_pages *ap;
	struct muse_init_args *ia;
	struct page *page;
	int ret = -ENOMEM;

	BUILD_BUG_ON(MUSE_INIT_INFO_MAX > PAGE_SIZE);

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		goto err;

	ia = kzalloc(sizeof(*ia), GFP_KERNEL);
	if (!ia)
		goto err_page;

	ap = &ia->ap;
	ia->in.fuse_major = FUSE_KERNEL_VERSION;
	ia->in.fuse_minor = FUSE_KERNEL_MINOR_VERSION;
	ap->args.opcode = MUSE_INIT;
	ap->args.in_numargs = 1;
	ap->args.in_args[0].size = sizeof(ia->in);
	ap->args.in_args[0].value = &ia->in;
	ap->args.out_numargs = 2;
	ap->args.out_args[0].size = sizeof(ia->out);
	ap->args.out_args[0].value = &ia->out;
	ap->args.out_args[1].size = MUSE_INIT_INFO_MAX;
	ap->args.out_argvar = true;
	ap->args.out_pages = true;
	ap->num_pages = 1;
	ap->pages = &ia->page;
	ap->descs = &ia->desc;
	ia->page = page;
	ia->desc.length = ap->args.out_args[1].size;
	ap->args.end = muse_process_init_reply;

	ret = fuse_simple_background(fm, &ap->args, GFP_KERNEL);
	if (ret)
		goto err_ia;

	return 0;

err_ia:
	kfree(ia);
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

	if (!capable(CAP_SYS_ADMIN)) {
		ret = -EPERM;
		goto err;
	}

	mc = kzalloc(sizeof(*mc), GFP_KERNEL);
	if (!mc) {
		ret = -ENOMEM;
		goto err;
	}

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

	if (mc->init_done)
		mtd_device_unregister(&mc->mtd);

	fuse_conn_put(&mc->fc);

	return fuse_dev_release(inode, file);
}

static struct miscdevice muse_ctrl_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "muse",
	.fops = &muse_ctrl_fops,
};

static int __init muse_init(void)
{
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
MODULE_LICENSE("GPLv2");
