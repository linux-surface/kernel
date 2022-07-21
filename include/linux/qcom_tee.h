/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface driver for the Qualcomm Trusted Execution Environment (TrEE/TEE) /
 * TrustZone OS (TzOS). Manages communication via Secure Channel Manager (SCM)
 * calls.
 *
 * Copyright (C) 2022 Maximilian Luz <luzmaximilian@gmail.com>
 */

#ifndef _LINUX_QCOM_TEE_H
#define _LINUX_QCOM_TEE_H

#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/qcom_scm.h>
#include <linux/types.h>


/* -- DMA helpers. ---------------------------------------------------------- */

/* DMA requirements for TrEE SCM calls. */
#define QCTEE_DMA_ALIGNMENT		8
#define QCTEE_DMA_ALIGN(ptr)		ALIGN(ptr, QCTEE_DMA_ALIGNMENT)

/**
 * struct qctee_dma - DMA memory region.
 * @size: Size of the memory region, in bytes.
 * @virt: Pointer / virtual address to the memory, accessible by the kernel.
 * @phys: Physical address of the memory region.
 */
struct qctee_dma {
	unsigned long size;
	void *virt;
	dma_addr_t phys;
};

/**
 * qctee_dma_alloc() - Allocate a DMA-able memory region suitable for TrEE SCM
 * calls.
 * @dev:  The device used for DMA memory allocation.
 * @dma:  Where to write the allocated memory addresses and size to.
 * @size: Minimum size of the memory to be allocated.
 * @gfp:  Flags used for allocation.
 *
 * Allocate a DMA-able memory region suitable for interaction with TrEE
 * services and the TzOS. The provided size is treated as the minimum required
 * size and rounded up, if necessary. The actually allocated memory region will
 * be stored in @dma. Allocated memory must be freed via qctee_dma_free().
 *
 * Return: Returns zero on success, -ENOMEM on allocation failure.
 */
static inline int qctee_dma_alloc(struct device *dev, struct qctee_dma *dma,
				  unsigned long size, gfp_t gfp)
{
	size = PAGE_ALIGN(size);

	dma->virt = dma_alloc_coherent(dev, size, &dma->phys, GFP_KERNEL);
	if (!dma->virt)
		return -ENOMEM;

	dma->size = size;
	return 0;
}

/**
 * qctee_dma_free() - Free a DMA memory region.
 * @dev: The device used for allocation.
 * @dma: The DMA region to be freed.
 *
 * Free a DMA region previously allocated via qctee_dma_alloc(). Note that
 * freeing sub-regions is not supported.
 */
static inline void qctee_dma_free(struct device *dev, struct qctee_dma *dma)
{
	dma_free_coherent(dev, dma->size, dma->virt, dma->phys);
}

/**
 * qctee_dma_realloc() - Re-allocate DMA memory region with the requested size.
 * @dev:  The device used for allocation.
 * @dma:  The region descriptor to be updated.
 * @size: The new requested size.
 * @gfp:  Flags used for allocation.
 *
 * Re-allocates a DMA memory region suitable for TrEE SCM calls to fit the
 * requested amount of bytes, if necessary. Does nothing if the provided region
 * already has enough space to store the requested data.
 *
 * See qctee_dma_alloc() for details.
 *
 * Return: Returns zero on success, -ENOMEM on allocation failure.
 */
static inline int qctee_dma_realloc(struct device *dev, struct qctee_dma *dma,
				    unsigned long size, gfp_t gfp)
{
	if (PAGE_ALIGN(size) <= dma->size)
		return 0;

	qctee_dma_free(dev, dma);
	return qctee_dma_alloc(dev, dma, size, gfp);
}

/**
 * qctee_dma_aligned() - Create a aligned DMA memory sub-region suitable for
 * TrEE SCM calls.
 * @base:   Base DMA memory region, in which the new region will reside.
 * @out:    Descriptor to store the aligned sub-region in.
 * @offset: The offset inside base region at which to place the new sub-region.
 *
 * Creates an aligned DMA memory region suitable for TrEE SCM calls at or after
 * the given offset. The size of the sub-region will be set to the remaining
 * size in the base region after alignment, i.e. the end of the sub-region will
 * be equal the end of the base region.
 *
 * Return: Returns zero on success or -EINVAL if the new aligned memory address
 * would point outside the base region.
 */
static inline int qctee_dma_aligned(const struct qctee_dma *base, struct qctee_dma *out,
				    unsigned long offset)
{
	void *aligned = (void *)QCTEE_DMA_ALIGN((uintptr_t)base->virt + offset);

	if (aligned - base->virt > base->size)
		return -EINVAL;

	out->virt = aligned;
	out->phys = base->phys + (out->virt - base->virt);
	out->size = base->size - (out->virt - base->virt);

	return 0;
}


/* -- Secure-OS SCM call interface. ----------------------------------------- */

#define QCTEE_TZ_OWNER_TZ_APPS			48
#define QCTEE_TZ_OWNER_QSEE_OS			50

#define QCTEE_TZ_SVC_APP_ID_PLACEHOLDER		0
#define QCTEE_TZ_SVC_APP_MGR			1

enum qctee_os_scm_result {
	QCTEE_OS_RESULT_SUCCESS			= 0,
	QCTEE_OS_RESULT_INCOMPLETE		= 1,
	QCTEE_OS_RESULT_BLOCKED_ON_LISTENER	= 2,
	QCTEE_OS_RESULT_FAILURE			= 0xFFFFFFFF,
};

enum qctee_os_scm_resp_type {
	QCTEE_OS_SCM_RES_APP_ID			= 0xEE01,
	QCTEE_OS_SCM_RES_QSEOS_LISTENER_ID	= 0xEE02,
};

/**
 * struct qctee_os_scm_resp - TrEE / TzOS SCM call response.
 * @status:    Status of the SCM call. See &enum qctee_os_scm_result.
 * @resp_type: Type of the response. See &enum qctee_os_scm_resp_type.
 * @data:      Response data. The type of this data is given in @resp_type.
 */
struct qctee_os_scm_resp {
	u64 status;
	u64 resp_type;
	u64 data;
};

int qctee_os_scm_call(struct device *dev, const struct qcom_scm_desc *desc,
		      struct qctee_os_scm_resp *res);


/* -- Secure App interface. ------------------------------------------------- */

#define QCTEE_MAX_APP_NAME_SIZE			64

int qctee_app_get_id(struct device *dev, const char *app_name, u32 *app_id);
int qctee_app_send(struct device *dev, u32 app_id, struct qctee_dma *req, struct qctee_dma *rsp);

#endif /* _LINUX_QCOM_TEE_H */
