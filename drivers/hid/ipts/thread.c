// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/mutex.h>
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
	thread->should_stop = false;
	thread->threadfn = threadfn;

	task = kthread_create(ipts_thread_runner, thread, name);
	if (IS_ERR(task)) {
		thread->thread = NULL;
		return PTR_ERR(task);
	}

	/*
	 * The runner can return before ipts_thread_stop() calls kthread_stop(), and the task
	 * goes away once it has exited. Keep a reference until the thread has been stopped.
	 */
	get_task_struct(task);
	thread->thread = task;
	wake_up_process(task);

	return 0;
}

int ipts_thread_stop(struct ipts_thread *thread)
{
	int ret = 0;

	if (!thread)
		return -EFAULT;

	if (!thread->thread)
		return 0;

	WRITE_ONCE(thread->should_stop, true);

	/*
	 * Make sure that the write has gone through before waiting.
	 */
	wmb();

	wait_for_completion(&thread->done);
	ret = kthread_stop_put(thread->thread);

	thread->thread = NULL;
	thread->data = NULL;
	thread->threadfn = NULL;

	return ret;
}
