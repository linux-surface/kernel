/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2023 Dorian Stoll
 *
 * Linux driver for Intel Precise Touch & Stylus
 */

#ifndef IPTS_THREAD_H
#define IPTS_THREAD_H

#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/sched.h>

/*
 * This wrapper over kthread is necessary, because calling kthread_stop makes it impossible
 * to issue MEI commands from that thread while it shuts itself down. By using a custom
 * boolean variable and a completion object, we can call kthread_stop only when the thread
 * already finished all of its work and has returned.
 */
struct ipts_thread {
	struct task_struct *thread;

	bool should_stop;
	struct completion done;

	/*
	 * Return value of the thread function, valid after ipts_thread_stop() returned 0.
	 */
	int exit_code;

	void *data;
	int (*threadfn)(struct ipts_thread *thread);
};

/**
 * ipts_thread_should_stop() - Returns true if the thread is asked to terminate.
 * @thread: The current thread.
 *
 * Returns: true if the thread should stop, false if not.
 */
bool ipts_thread_should_stop(struct ipts_thread *thread);

/**
 * ipts_thread_start() - Starts an IPTS thread.
 * @thread: The thread to initialize and start.
 * @threadfn: The function to execute.
 * @data: An argument that will be passed to threadfn.
 * @name: The name of the new thread.
 *
 * Returns: 0 on success, <0 on error.
 */
int ipts_thread_start(struct ipts_thread *thread, int (*threadfn)(struct ipts_thread *thread),
		      void *data, const char name[]);

/*
 * How often ipts_thread_stop() checks whether the thread died while it waits.
 */
#define IPTS_THREAD_STOP_POLL_MS 100

/**
 * ipts_thread_stop() - Asks the thread to terminate and waits until it has finished.
 * @thread: The thread that should stop.
 * @timeout_ms: How long to wait for the thread function to return.
 *
 * The wait is bounded. A thread that died (oops) without finishing runs no driver code
 * anymore and is treated as stopped. A thread that is still running after the timeout is
 * left alone, and nothing it uses may be freed.
 *
 * Returns: 0 if the thread function returned (its return value is in thread->exit_code),
 * -EOWNERDEAD if the thread died without returning, -ETIMEDOUT if it is still running,
 * <0 on other errors.
 */
int ipts_thread_stop(struct ipts_thread *thread, unsigned int timeout_ms);

#endif /* IPTS_THREAD_H */
