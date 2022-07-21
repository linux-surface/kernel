/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface driver for the Qualcomm Trusted Execution Environment / TrustZone
 * OS. Manages communication via Secure Channel Manager (SCM) calls.
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

#define QCTEE_DMA_ALIGNMENT		8
#define QCTEE_DMA_ALIGN(ptr)		ALIGN(ptr, QCTEE_DMA_ALIGNMENT)

struct qctee_dma {
	unsigned long size;
	void *virt;
	dma_addr_t phys;
};

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

static inline void qctee_dma_free(struct device *dev, struct qctee_dma *dma)
{
	dma_free_coherent(dev, dma->size, dma->virt, dma->phys);
}

static inline int qctee_dma_realloc(struct device *dev, struct qctee_dma *dma,
				    unsigned long size, gfp_t gfp)
{
	if (PAGE_ALIGN(size) <= dma->size)
		return 0;

	qctee_dma_free(dev, dma);
	return qctee_dma_alloc(dev, dma, size, gfp);
}

static inline void qctee_dma_aligned(const struct qctee_dma *base, struct qctee_dma *out,
				     unsigned long offset)
{
	out->virt = (void *)QCTEE_DMA_ALIGN((uintptr_t)base->virt + offset);
	out->phys = base->phys + (out->virt - base->virt);
	out->size = base->size - (out->virt - base->virt);
}


/* -- Secure-OS SCM call interface. ----------------------------------------- */

#define QCTEE_TZ_OWNER_TZ_APPS			48
#define QCTEE_TZ_OWNER_QSEE_OS			50

#define QCTEE_TZ_SVC_APP_ID_PLACEHOLDER		0
#define QCTEE_TZ_SVC_APP_MGR			1
#define QCTEE_TZ_SVC_LISTENER			2

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
