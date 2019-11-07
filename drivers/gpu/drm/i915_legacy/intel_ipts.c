/*
 * Copyright  2016 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include <drm/drmP.h>
#include <linux/ipts-gfx.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "intel_guc_submission.h"
#include "i915_drv.h"

#define SUPPORTED_IPTS_INTERFACE_VERSION 1

#define REACQUIRE_DB_THRESHOLD 10

#define DB_LOST_CHECK_STEP1_INTERVAL 2500 // ms
#define DB_LOST_CHECK_STEP2_INTERVAL 1000 // ms

// CTX for ipts support
struct ipts {
	struct drm_device *dev;
	struct i915_gem_context *ipts_context;
	struct ipts_callback ipts_clbks;

	// buffers' list
	struct {
		spinlock_t lock;
		struct list_head list;
	} buffers;

	void *data;

	struct delayed_work reacquire_db_work;
	struct ipts_wq_info wq_info;
	u32 old_tail;
	u32 old_head;
	bool need_reacquire_db;

	bool connected;
	bool initialized;
};

struct ipts ipts;

struct ipts_object {
	struct list_head list;
	struct drm_i915_gem_object *gem_obj;
	void *cpu_addr;
};

static struct ipts_object *ipts_object_create(size_t size, u32 flags)
{
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	struct ipts_object *obj = NULL;
	struct drm_i915_gem_object *gem_obj = NULL;
	int ret = 0;

	obj = kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!obj)
		return NULL;

	size = roundup(size, PAGE_SIZE);
	if (size == 0) {
		ret = -EINVAL;
		goto err_out;
	}

	// Allocate the new object
	gem_obj = i915_gem_object_create(dev_priv, size);
	if (gem_obj == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (flags & IPTS_BUF_FLAG_CONTIGUOUS) {
		ret = i915_gem_object_attach_phys(gem_obj, PAGE_SIZE);
		if (ret) {
			pr_info(">> ipts no contiguous : %d\n", ret);
			goto err_out;
		}
	}

	obj->gem_obj = gem_obj;

	spin_lock(&ipts.buffers.lock);
	list_add_tail(&obj->list, &ipts.buffers.list);
	spin_unlock(&ipts.buffers.lock);

	return obj;

err_out:

	if (gem_obj)
		i915_gem_free_object(&gem_obj->base);

	kfree(obj);

	return NULL;
}

static void ipts_object_free(struct ipts_object *obj)
{
	spin_lock(&ipts.buffers.lock);
	list_del(&obj->list);
	spin_unlock(&ipts.buffers.lock);

	i915_gem_free_object(&obj->gem_obj->base);
	kfree(obj);
}

static int ipts_object_pin(struct ipts_object *obj,
		struct i915_gem_context *ipts_ctx)
{
	struct i915_address_space *vm = NULL;
	struct i915_vma *vma = NULL;
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	int ret = 0;

	if (ipts_ctx->ppgtt)
		vm = &ipts_ctx->ppgtt->vm;
	else
		vm = &dev_priv->ggtt.vm;

	vma = i915_vma_instance(obj->gem_obj, vm, NULL);
	if (IS_ERR(vma)) {
		DRM_ERROR("cannot find or create vma\n");
		return -1;
	}

	ret = i915_vma_pin(vma, 0, PAGE_SIZE, PIN_USER);

	return ret;
}

static void ipts_object_unpin(struct ipts_object *obj)
{
	// TODO: Add support
}

static void *ipts_object_map(struct ipts_object *obj)
{
	return i915_gem_object_pin_map(obj->gem_obj, I915_MAP_WB);
}

static void ipts_object_unmap(struct ipts_object *obj)
{
	i915_gem_object_unpin_map(obj->gem_obj);
	obj->cpu_addr = NULL;
}

static int create_ipts_context(void)
{
	struct i915_gem_context *ipts_ctx = NULL;
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	struct intel_context *ce = NULL;
	int ret = 0;

	// Initialize the context right away.
	ret = i915_mutex_lock_interruptible(ipts.dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return ret;
	}

	ipts_ctx = i915_gem_context_create_ipts(ipts.dev);
	if (IS_ERR(ipts_ctx)) {
		DRM_ERROR("Failed to create IPTS context (error %ld)\n",
			  PTR_ERR(ipts_ctx));
		ret = PTR_ERR(ipts_ctx);
		goto err_unlock;
	}

	ce = intel_context_pin(ipts_ctx, dev_priv->engine[RCS0]);
	if (IS_ERR(ce)) {
		DRM_ERROR("Failed to create intel context (error %ld)\n",
			  PTR_ERR(ce));
		ret = PTR_ERR(ce);
		goto err_unlock;
	}

	ret = execlists_context_deferred_alloc(ce, ce->engine);
	if (ret) {
		DRM_DEBUG("lr context allocation failed: %d\n", ret);
		goto err_ctx;
	}

	ret = execlists_context_pin(ce);
	if (ret) {
		DRM_DEBUG("lr context pinning failed: %d\n", ret);
		goto err_ctx;
	}

	// Release the mutex
	mutex_unlock(&ipts.dev->struct_mutex);

	spin_lock_init(&ipts.buffers.lock);
	INIT_LIST_HEAD(&ipts.buffers.list);

	ipts.ipts_context = ipts_ctx;

	return 0;

err_ctx:
	if (ipts_ctx)
		i915_gem_context_put(ipts_ctx);

err_unlock:
	mutex_unlock(&ipts.dev->struct_mutex);

	return ret;
}

static void destroy_ipts_context(void)
{
	struct i915_gem_context *ipts_ctx = NULL;
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	struct intel_context *ce = NULL;
	int ret = 0;

	ipts_ctx = ipts.ipts_context;

	ce = intel_context_lookup(ipts_ctx, dev_priv->engine[RCS0]);

	// Initialize the context right away.
	ret = i915_mutex_lock_interruptible(ipts.dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return;
	}

	execlists_context_unpin(ce);
	intel_context_unpin(ce);
	i915_gem_context_put(ipts_ctx);

	mutex_unlock(&ipts.dev->struct_mutex);
}

int ipts_notify_complete(void)
{
	if (ipts.ipts_clbks.workload_complete)
		ipts.ipts_clbks.workload_complete(ipts.data);

	return 0;
}

int ipts_notify_backlight_status(bool backlight_on)
{
	if (ipts.ipts_clbks.notify_gfx_status) {
		if (backlight_on) {
			ipts.ipts_clbks.notify_gfx_status(
				IPTS_NOTIFY_STA_BACKLIGHT_ON, ipts.data);
			schedule_delayed_work(&ipts.reacquire_db_work,
				msecs_to_jiffies(DB_LOST_CHECK_STEP1_INTERVAL));
		} else {
			ipts.ipts_clbks.notify_gfx_status(
				IPTS_NOTIFY_STA_BACKLIGHT_OFF, ipts.data);
			cancel_delayed_work(&ipts.reacquire_db_work);
		}
	}

	return 0;
}

static void ipts_reacquire_db(struct ipts *ipts_p)
{
	int ret = 0;

	ret = i915_mutex_lock_interruptible(ipts_p->dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return;
	}

	// Reacquire the doorbell
	i915_guc_ipts_reacquire_doorbell(ipts_p->dev->dev_private);

	mutex_unlock(&ipts_p->dev->struct_mutex);
}

static int ipts_get_wq_info(uint64_t gfx_handle,
		struct ipts_wq_info *wq_info)
{
	if (gfx_handle != (uint64_t)&ipts) {
		DRM_ERROR("invalid gfx handle\n");
		return -EINVAL;
	}

	*wq_info = ipts.wq_info;

	ipts_reacquire_db(&ipts);
	schedule_delayed_work(&ipts.reacquire_db_work,
		msecs_to_jiffies(DB_LOST_CHECK_STEP1_INTERVAL));

	return 0;
}

static int set_wq_info(void)
{
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	struct intel_guc *guc = &dev_priv->guc;
	struct intel_guc_client *client;
	struct guc_process_desc *desc;
	struct ipts_wq_info *wq_info;
	void *base = NULL;
	u64 phy_base = 0;

	wq_info = &ipts.wq_info;

	client = guc->ipts_client;
	if (!client) {
		DRM_ERROR("IPTS GuC client is NOT available\n");
		return -EINVAL;
	}

	base = client->vaddr;
	desc = (struct guc_process_desc *)
		((u64)base + client->proc_desc_offset);

	desc->wq_base_addr = (u64)base + GUC_DB_SIZE;
	desc->db_base_addr = (u64)base + client->doorbell_offset;

	// IPTS expects physical addresses to pass it to ME
	phy_base = sg_dma_address(client->vma->pages->sgl);

	wq_info->db_addr = desc->db_base_addr;
	wq_info->db_phy_addr = phy_base + client->doorbell_offset;
	wq_info->db_cookie_offset = offsetof(struct guc_doorbell_info, cookie);
	wq_info->wq_addr = desc->wq_base_addr;
	wq_info->wq_phy_addr = phy_base + GUC_DB_SIZE;
	wq_info->wq_head_addr = (u64)&desc->head;
	wq_info->wq_tail_addr = (u64)&desc->tail;
	wq_info->wq_size = desc->wq_size_bytes;

	wq_info->wq_head_phy_addr = phy_base + client->proc_desc_offset +
		offsetof(struct guc_process_desc, head);

	wq_info->wq_tail_phy_addr = phy_base + client->proc_desc_offset +
		offsetof(struct guc_process_desc, tail);

	return 0;
}

static int ipts_init_wq(void)
{
	int ret = 0;

	ret = i915_mutex_lock_interruptible(ipts.dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return ret;
	}

	// disable IPTS submission
	i915_guc_ipts_submission_disable(ipts.dev->dev_private);

	// enable IPTS submission
	ret = i915_guc_ipts_submission_enable(ipts.dev->dev_private,
		ipts.ipts_context);
	if (ret) {
		DRM_ERROR("i915_guc_ipts_submission_enable failed: %d\n", ret);
		goto out;
	}

	ret = set_wq_info();
	if (ret) {
		DRM_ERROR("set_wq_info failed\n");
		goto out;
	}

out:
	mutex_unlock(&ipts.dev->struct_mutex);

	return ret;
}

static void ipts_release_wq(void)
{
	int ret = 0;

	ret = i915_mutex_lock_interruptible(ipts.dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return;
	}

	// disable IPTS submission
	i915_guc_ipts_submission_disable(ipts.dev->dev_private);

	mutex_unlock(&ipts.dev->struct_mutex);
}

static int ipts_map_buffer(u64 gfx_handle, struct ipts_mapbuffer *mapbuf)
{
	struct ipts_object *obj;
	struct i915_gem_context *ipts_ctx = NULL;
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);
	struct i915_address_space *vm = NULL;
	struct i915_vma *vma = NULL;
	int ret = 0;

	if (gfx_handle != (uint64_t)&ipts) {
		DRM_ERROR("invalid gfx handle\n");
		return -EINVAL;
	}

	// Acquire mutex first
	ret = i915_mutex_lock_interruptible(ipts.dev);
	if (ret) {
		DRM_ERROR("i915_mutex_lock_interruptible failed\n");
		return -EINVAL;
	}

	obj = ipts_object_create(mapbuf->size, mapbuf->flags);
	if (!obj)
		return -ENOMEM;

	ipts_ctx = ipts.ipts_context;
	ret = ipts_object_pin(obj, ipts_ctx);
	if (ret) {
		DRM_ERROR("Not able to pin iTouch obj\n");
		ipts_object_free(obj);
		mutex_unlock(&ipts.dev->struct_mutex);
		return -ENOMEM;
	}

	if (mapbuf->flags & IPTS_BUF_FLAG_CONTIGUOUS)
		obj->cpu_addr = obj->gem_obj->phys_handle->vaddr;
	else
		obj->cpu_addr = ipts_object_map(obj);

	if (ipts_ctx->ppgtt)
		vm = &ipts_ctx->ppgtt->vm;
	else
		vm = &dev_priv->ggtt.vm;

	vma = i915_vma_instance(obj->gem_obj, vm, NULL);
	if (IS_ERR(vma)) {
		DRM_ERROR("cannot find or create vma\n");
		return -EINVAL;
	}

	mapbuf->gfx_addr = (void *)vma->node.start;
	mapbuf->cpu_addr = (void *)obj->cpu_addr;
	mapbuf->buf_handle = (u64)obj;
	if (mapbuf->flags & IPTS_BUF_FLAG_CONTIGUOUS)
		mapbuf->phy_addr = (u64)obj->gem_obj->phys_handle->busaddr;

	// Release the mutex
	mutex_unlock(&ipts.dev->struct_mutex);

	return 0;
}

static int ipts_unmap_buffer(uint64_t gfx_handle, uint64_t buf_handle)
{
	struct ipts_object *obj = (struct ipts_object *)buf_handle;

	if (gfx_handle != (uint64_t)&ipts) {
		DRM_ERROR("invalid gfx handle\n");
		return -EINVAL;
	}

	if (!obj->gem_obj->phys_handle)
		ipts_object_unmap(obj);

	ipts_object_unpin(obj);
	ipts_object_free(obj);

	return 0;
}

int ipts_connect(struct ipts_connect *ipts_connect)
{
	u32 flags = DL_FLAG_PM_RUNTIME | DL_FLAG_AUTOREMOVE_CONSUMER;
	struct drm_i915_private *dev_priv = to_i915(ipts.dev);

	if (!ipts.initialized)
		return -EIO;

	if (!ipts_connect)
		return -EINVAL;

	if (ipts_connect->if_version > SUPPORTED_IPTS_INTERFACE_VERSION)
		return -EINVAL;

	// set up device-link for PM
	if (!device_link_add(ipts_connect->client, ipts.dev->dev, flags))
		return -EFAULT;

	// return gpu operations for ipts
	ipts_connect->ipts_ops.get_wq_info = ipts_get_wq_info;
	ipts_connect->ipts_ops.map_buffer = ipts_map_buffer;
	ipts_connect->ipts_ops.unmap_buffer = ipts_unmap_buffer;
	ipts_connect->gfx_version = INTEL_INFO(dev_priv)->gen;
	ipts_connect->gfx_handle = (uint64_t)&ipts;

	// save callback and data
	ipts.data = ipts_connect->data;
	ipts.ipts_clbks = ipts_connect->ipts_cb;

	ipts.connected = true;

	return 0;
}
EXPORT_SYMBOL_GPL(ipts_connect);

void ipts_disconnect(uint64_t gfx_handle)
{
	if (!ipts.initialized)
		return;

	if (gfx_handle != (uint64_t)&ipts || !ipts.connected) {
		DRM_ERROR("invalid gfx handle\n");
		return;
	}

	ipts.data = 0;
	memset(&ipts.ipts_clbks, 0, sizeof(struct ipts_callback));

	ipts.connected = false;
}
EXPORT_SYMBOL_GPL(ipts_disconnect);

static void reacquire_db_work_func(struct work_struct *work)
{
	struct delayed_work *d_work = container_of(work,
		struct delayed_work, work);
	struct ipts *ipts_p = container_of(d_work,
		struct ipts, reacquire_db_work);
	u32 head;
	u32 tail;
	u32 size;
	u32 load;

	head = *(u32 *)ipts_p->wq_info.wq_head_addr;
	tail = *(u32 *)ipts_p->wq_info.wq_tail_addr;
	size = ipts_p->wq_info.wq_size;

	if (head >= tail)
		load = head - tail;
	else
		load = head + size - tail;

	if (load < REACQUIRE_DB_THRESHOLD) {
		ipts_p->need_reacquire_db = false;
		goto reschedule_work;
	}

	if (ipts_p->need_reacquire_db) {
		if (ipts_p->old_head == head &&
				ipts_p->old_tail == tail)
			ipts_reacquire_db(ipts_p);
		ipts_p->need_reacquire_db = false;
	} else {
		ipts_p->old_head = head;
		ipts_p->old_tail = tail;
		ipts_p->need_reacquire_db = true;

		// recheck
		schedule_delayed_work(&ipts_p->reacquire_db_work,
			msecs_to_jiffies(DB_LOST_CHECK_STEP2_INTERVAL));
		return;
	}

reschedule_work:
	schedule_delayed_work(&ipts_p->reacquire_db_work,
		msecs_to_jiffies(DB_LOST_CHECK_STEP1_INTERVAL));
}

/**
 * ipts_init - Initialize ipts support
 * @dev: drm device
 *
 * Setup the required structures for ipts.
 */
int ipts_init(struct drm_device *dev)
{
	int ret = 0;

	pr_info("ipts: initializing ipts\n");

	ipts.dev = dev;
	INIT_DELAYED_WORK(&ipts.reacquire_db_work,
		reacquire_db_work_func);

	ret = create_ipts_context();
	if (ret)
		return -ENOMEM;

	ret = ipts_init_wq();
	if (ret)
		return ret;

	ipts.initialized = true;
	pr_info("ipts: Intel iTouch framework initialized\n");

	return ret;
}

void ipts_cleanup(struct drm_device *dev)
{
	struct ipts_object *obj, *n;

	if (ipts.dev != dev)
		return;

	list_for_each_entry_safe(obj, n, &ipts.buffers.list, list) {
		struct i915_vma *vma, *vn;

		list_for_each_entry_safe(vma, vn, &obj->list, obj_link) {
			vma->flags &= ~I915_VMA_PIN_MASK;
			i915_vma_destroy(vma);
		}

		list_del(&obj->list);

		if (!obj->gem_obj->phys_handle)
			ipts_object_unmap(obj);

		ipts_object_unpin(obj);
		i915_gem_free_object(&obj->gem_obj->base);
		kfree(obj);
	}

	ipts_release_wq();
	destroy_ipts_context();
	cancel_delayed_work(&ipts.reacquire_db_work);
}
