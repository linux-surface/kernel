// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/sched/task.h>

#include "thread.h"

bool ipts_thread_should_stop(struct ipts_thread *thread)
{
	if (!thread)
		return false;

	return READ_ONCE(thread->should_stop);
}

static int ipts_thread_runner(void *data)
{
	int ret = 0;
	struct ipts_thread *thread = data;

	if (!thread)
		return -EFAULT;

	if (!thread->threadfn)
		return -EFAULT;

	ret = thread->threadfn(thread);
	complete_all(&thread->done);

	return ret;
}

int ipts_thread_start(struct ipts_thread *thread, int (*threadfn)(struct ipts_thread *thread),
		      void *data, const char *name)
{
	struct task_struct *task = NULL;

	if (!thread)
		return -EFAULT;

	if (!threadfn)
		return -EFAULT;

	init_completion(&thread->done);

	thread->data = data;
	thread->exit_code = 0;
	thread->should_stop = false;
	thread->threadfn = threadfn;

	task = kthread_create(ipts_thread_runner, thread, "%s", name);
	if (IS_ERR(task)) {
		thread->thread = NULL;
		thread->threadfn = NULL;
		thread->data = NULL;
		return PTR_ERR(task);
	}

	/*
	 * Keep the task_struct until ipts_thread_stop() is done with it, even if the
	 * thread exits on its own (or dies) before that.
	 */
	get_task_struct(task);
	thread->thread = task;
	wake_up_process(task);

	return 0;
}

int ipts_thread_stop(struct ipts_thread *thread, unsigned int timeout_ms)
{
	int ret = 0;
	unsigned long end = 0;
	struct task_struct *task = NULL;

	if (!thread)
		return -EFAULT;

	task = thread->thread;
	if (!task)
		return 0;

	WRITE_ONCE(thread->should_stop, true);

	/*
	 * Make sure that the write has gone through before waiting.
	 */
	wmb();

	end = jiffies + msecs_to_jiffies(timeout_ms);

	while (!wait_for_completion_timeout(&thread->done,
					    msecs_to_jiffies(IPTS_THREAD_STOP_POLL_MS))) {
		/*
		 * A thread that died in an oops is unwinding through do_exit() and will
		 * never complete. It runs no driver code anymore, so it counts as stopped.
		 * kthread_stop() could wait for its exit forever, so it is not called.
		 */
		if ((task->flags & PF_EXITING) && !completion_done(&thread->done)) {
			pr_err("ipts: thread %s died without finishing\n", task->comm);
			ret = -EOWNERDEAD;
			goto out;
		}

		if (time_after(jiffies, end))
			return -ETIMEDOUT;
	}

	thread->exit_code = kthread_stop(task);

out:
	put_task_struct(task);

	thread->thread = NULL;
	thread->data = NULL;
	thread->threadfn = NULL;

	return ret;
}
