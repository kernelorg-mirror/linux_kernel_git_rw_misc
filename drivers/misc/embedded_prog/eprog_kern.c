#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/freezer.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/umh.h>
#include <linux/usermode_driver.h>

extern char embedded_umh_start;
extern char embedded_umh_end;

static struct umd_info eprog_ctx = {
	.driver_name = "eprog_user",
};

static struct task_struct *eprog_thread_tsk;
static char *read_buf;
#define READ_BUFSZ 128

static int eprog_thread(void *data)
{
	struct umd_info *eprog_ctx = data;
	loff_t pos = 0;
	ssize_t nread;

	set_freezable();

	for (;;) {
		if (kthread_should_stop())
			break;

		if (try_to_freeze())
			continue;

		nread = kernel_read(eprog_ctx->pipe_from_umh, read_buf, READ_BUFSZ - 1, &pos);
		if (nread > 0) {
			read_buf[nread] = '\0';
			pr_info("From userspace: %s", read_buf);
		} else if (nread == -ERESTARTSYS) {
			break;
		} else {
			pr_err("Fatal error while reading from userspace: %ld\n", nread);
			/*
			 * Suspend ourself and wait for termination.
			 */
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		}
	}

	return 0;
}

static void kill_umh(struct umd_info *eprog_ctx)
{
	struct pid *eprog_tgid = eprog_ctx->tgid;

	kill_pid(eprog_tgid, SIGKILL, 1);
	wait_event(eprog_tgid->wait_pidfd, thread_group_exited(eprog_tgid));
	umd_cleanup_helper(eprog_ctx);
}

static int __init eprog_init(void)
{
	int ret;

	read_buf = kmalloc(READ_BUFSZ, GFP_KERNEL);
	if (!read_buf) {
		ret = -ENOMEM;
		goto out;
	}

	ret = umd_load_blob(&eprog_ctx, &embedded_umh_start, &embedded_umh_end - &embedded_umh_start);
	if (ret) {
		pr_err("Unable to load embedded user mode helper blob: %i\n", ret);
		kfree(read_buf);
		goto out;
	}

	ret = fork_usermode_driver(&eprog_ctx);
	if (ret) {
		pr_err("Unable to start embedded user mode helper: %i\n", ret);
		umd_unload_blob(&eprog_ctx);
		kfree(read_buf);
		goto out;
	}

	eprog_thread_tsk = kthread_create(eprog_thread, &eprog_ctx, "eprog_thread");
	if (IS_ERR(eprog_thread_tsk)) {
		ret = PTR_ERR(eprog_thread_tsk);
		pr_err("Unable to start kernel thread: %i\n", ret);
		kill_umh(&eprog_ctx);
		umd_unload_blob(&eprog_ctx);
		kfree(read_buf);
		goto out;
	}

	wake_up_process(eprog_thread_tsk);
	ret = 0;
out:
	return ret;
}

static void __exit eprog_exit(void)
{
	kthread_stop(eprog_thread_tsk);
	kill_umh(&eprog_ctx);
	kfree(read_buf);
	umd_unload_blob(&eprog_ctx);
}

module_init(eprog_init);
module_exit(eprog_exit);
MODULE_LICENSE("GPL");
