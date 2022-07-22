// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Client driver for Qualcomm UEFI Secure Application (qcom.tz.uefisecapp).
 * Provides access to UEFI variables on platforms where they are secured by the
 * aforementioned Trusted Execution Environment (TEE) application.
 *
 * Copyright (C) 2022 Maximilian Luz <luzmaximilian@gmail.com>
 */

#include <linux/efi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/qcom_tee.h>
#include <linux/slab.h>
#include <linux/types.h>


/* -- UTF-16 helpers. ------------------------------------------------------- */

static unsigned long utf16_strnlen(const efi_char16_t *str, unsigned long max)
{
	size_t i;

	for (i = 0; *str != 0 && i < max; i++, str++) {
		/* Do nothing, all is handled in the for statement. */
	}

	return i;
}

/**
 * utf16_strsize() - Compute the number of bytes required to store a
 * null-terminated UTF-16 string.
 * @str: The string to compute the size for.
 *
 * Return: Returns the minimum number of bytes required to store the given
 * null-terminated string, including its null-terminator.
 */
static unsigned long utf16_strsize(const efi_char16_t *str)
{
	return (utf16_strnlen(str, U32_MAX) + 1) * sizeof(str[0]);
}

static unsigned long utf16_strlcpy(efi_char16_t *dst, const efi_char16_t *src, unsigned long size)
{
	unsigned long actual = utf16_strnlen(src, size - 1);

	memcpy(dst, src, actual * sizeof(src[0]));
	dst[actual] = 0;

	return actual;
}

/**
 * utf16_copy_to_buf() - Copy the given UTF-16 string to a buffer.
 * @dst:   Pointer to the output buffer
 * @src:   Pointer to the null-terminated UTF-16 string to be copied.
 * @bytes: Maximum number of bytes to copy.
 *
 * Copies the given string to the given buffer, ensuring that the output buffer
 * is not overrun and that the string in the output buffer will always be
 * null-terminated.
 *
 * Return: Returns the length of the copied string, without null-terminator.
 */
static unsigned long utf16_copy_to_buf(efi_char16_t *dst, const efi_char16_t *src,
				       unsigned long bytes)
{
	return utf16_strlcpy(dst, src, bytes / sizeof(src[0]));
}


/* -- Qualcomm "uefisecapp" interface definitions. -------------------------- */

#define QCTEE_UEFISEC_APP_NAME			"qcom.tz.uefisecapp"

#define QCTEE_CMD_UEFI(x)			(0x8000 | (x))
#define QCTEE_CMD_UEFI_GET_VARIABLE		QCTEE_CMD_UEFI(0)
#define QCTEE_CMD_UEFI_SET_VARIABLE		QCTEE_CMD_UEFI(1)
#define QCTEE_CMD_UEFI_GET_NEXT_VARIABLE	QCTEE_CMD_UEFI(2)
#define QCTEE_CMD_UEFI_QUERY_VARIABLE_INFO	QCTEE_CMD_UEFI(3)

/**
 * struct qctee_req_uefi_get_variable - Request for GetVariable command.
 * @command_id:  The ID of the command. Must be %QCTEE_CMD_UEFI_GET_VARIABLE.
 * @length:      Length of the request in bytes, including this struct and any
 *               parameters (name, GUID) stored after it as well as any padding
 *               thereof for alignment.
 * @name_offset: Offset from the start of this struct to where the variable
 *               name is stored (as utf-16 string), in bytes.
 * @name_size:   Size of the name parameter in bytes, including null-terminator.
 * @guid_offset: Offset from the start of this struct to where the GUID
 *               parameter is stored, in bytes.
 * @guid_size:   Size of the GUID parameter in bytes, i.e. sizeof(efi_guid_t).
 * @data_size:   Size of the output buffer, in bytes.
 */
struct qctee_req_uefi_get_variable {
	u32 command_id;
	u32 length;
	u32 name_offset;
	u32 name_size;
	u32 guid_offset;
	u32 guid_size;
	u32 data_size;
} __packed;

/**
 * struct qctee_rsp_uefi_get_variable - Response for GetVariable command.
 * @command_id:  The ID of the command. Should be %QCTEE_CMD_UEFI_GET_VARIABLE.
 * @length:      Length of the response in bytes, including this struct and the
 *               returned data.
 * @status:      Status of this command.
 * @attributes:  EFI variable attributes.
 * @data_offset: Offset from the start of this struct to where the data is
 *               stored, in bytes.
 * @data_size:   Size of the returned data, in bytes. In case status indicates
 *               that the buffer is too small, this will be the size required
 *               to store the EFI variable data.
 */
struct qctee_rsp_uefi_get_variable {
	u32 command_id;
	u32 length;
	u32 status;
	u32 attributes;
	u32 data_offset;
	u32 data_size;
} __packed;

/**
 * struct qctee_req_uefi_set_variable - Request for the SetVariable command.
 * @command_id:  The ID of the command. Must be %QCTEE_CMD_UEFI_SET_VARIABLE.
 * @length:      Length of the request in bytes, including this struct and any
 *               parameters (name, GUID, data) stored after it as well as any
 *               padding thereof required for alignment.
 * @name_offset: Offset from the start of this struct to where the variable
 *               name is stored (as utf-16 string), in bytes.
 * @name_size:   Size of the name parameter in bytes, including null-terminator.
 * @guid_offset: Offset from the start of this struct to where the GUID
 *               parameter is stored, in bytes.
 * @guid_size:   Size of the GUID parameter in bytes, i.e. sizeof(efi_guid_t).
 * @attributes:  The EFI variable attributes to set for this variable.
 * @data_offset: Offset from the start of this struct to where the EFI variable
 *               data is stored, in bytes.
 * @data_size:   Size of EFI variable data, in bytes.
 *
 */
struct qctee_req_uefi_set_variable {
	u32 command_id;
	u32 length;
	u32 name_offset;
	u32 name_size;
	u32 guid_offset;
	u32 guid_size;
	u32 attributes;
	u32 data_offset;
	u32 data_size;
} __packed;

/**
 * struct qctee_rsp_uefi_set_variable - Response for the SetVariable command.
 * @command_id:  The ID of the command. Should be %QCTEE_CMD_UEFI_SET_VARIABLE.
 * @length:      The length of this response, i.e. the size of this struct in
 *               bytes.
 * @status:      Status of this command.
 * @_unknown1:   Unknown response field.
 * @_unknown2:   Unknown response field.
 */
struct qctee_rsp_uefi_set_variable {
	u32 command_id;
	u32 length;
	u32 status;
	u32 _unknown1;
	u32 _unknown2;
} __packed;

/**
 * struct qctee_req_uefi_get_next_variable - Request for the
 * GetNextVariableName command.
 * @command_id:  The ID of the command. Must be
 *               %QCTEE_CMD_UEFI_GET_NEXT_VARIABLE.
 * @length:      Length of the request in bytes, including this struct and any
 *               parameters (name, GUID) stored after it as well as any padding
 *               thereof for alignment.
 * @guid_offset: Offset from the start of this struct to where the GUID
 *               parameter is stored, in bytes.
 * @guid_size:   Size of the GUID parameter in bytes, i.e. sizeof(efi_guid_t).
 * @name_offset: Offset from the start of this struct to where the variable
 *               name is stored (as utf-16 string), in bytes.
 * @name_size:   Size of the name parameter in bytes, including null-terminator.
 */
struct qctee_req_uefi_get_next_variable {
	u32 command_id;
	u32 length;
	u32 guid_offset;
	u32 guid_size;
	u32 name_offset;
	u32 name_size;
} __packed;

/**
 * struct qctee_rsp_uefi_get_next_variable - Response for the
 * GetNextVariableName command.
 * @command_id:  The ID of the command. Should be
 *               %QCTEE_CMD_UEFI_GET_NEXT_VARIABLE.
 * @length:      Length of the response in bytes, including this struct and any
 *               parameters (name, GUID) stored after it as well as any padding
 *               thereof for alignment.
 * @status:      Status of this command.
 * @guid_size:   Size of the GUID parameter in bytes, i.e. sizeof(efi_guid_t).
 * @name_offset: Offset from the start of this struct to where the variable
 *               name is stored (as utf-16 string), in bytes.
 * @name_size:   Size of the name parameter in bytes, including null-terminator.
 */
struct qctee_rsp_uefi_get_next_variable {
	u32 command_id;
	u32 length;
	u32 status;
	u32 guid_offset;
	u32 guid_size;
	u32 name_offset;
	u32 name_size;
} __packed;

/**
 * struct qctee_req_uefi_query_variable_info - Response for the
 * GetNextVariableName command.
 * @command_id: The ID of the command. Must be
 *              %QCTEE_CMD_UEFI_QUERY_VARIABLE_INFO.
 * @length:     The length of this request, i.e. the size of this struct in
 *              bytes.
 * @attributes: The storage attributes to query the info for.
 */
struct qctee_req_uefi_query_variable_info {
	u32 command_id;
	u32 length;
	u32 attributes;
} __packed;

/**
 * struct qctee_rsp_uefi_query_variable_info - Response for the
 * GetNextVariableName command.
 * @command_id:        The ID of the command. Must be
 *                     %QCTEE_CMD_UEFI_QUERY_VARIABLE_INFO.
 * @length:            The length of this response, i.e. the size of this
 *                     struct in bytes.
 * @status:            Status of this command.
 * @_pad:              Padding.
 * @storage_space:     Full storage space size, in bytes.
 * @remaining_space:   Free storage space available, in bytes.
 * @max_variable_size: Maximum variable data size, in bytes.
 */
struct qctee_rsp_uefi_query_variable_info {
	u32 command_id;
	u32 length;
	u32 status;
	u32 _pad;
	u64 storage_space;
	u64 remaining_space;
	u64 max_variable_size;
} __packed;


/* -- UEFI app interface. --------------------------------------------------- */

struct qcuefi_client {
	struct device *dev;
	struct kobject *kobj;
	struct efivars efivars;
	struct qctee_dma dma;
	u32 app_id;
};

static efi_status_t qctee_uefi_status_to_efi(u32 status)
{
	u64 category = status & 0xf0000000;
	u64 code = status & 0x0fffffff;

	return category << (BITS_PER_LONG - 32) | code;
}

static efi_status_t qctee_uefi_get_variable(struct qcuefi_client *qcuefi, const efi_char16_t *name,
					    const efi_guid_t *guid, u32 *attributes,
					    unsigned long *data_size, void *data)
{
	struct qctee_req_uefi_get_variable *req_data;
	struct qctee_rsp_uefi_get_variable *rsp_data;
	struct qctee_dma dma_req;
	struct qctee_dma dma_rsp;
	unsigned long name_size = utf16_strsize(name);
	unsigned long buffer_size = *data_size;
	unsigned long size;
	efi_status_t efi_status;
	int status;

	/* Validation: We need a name and GUID. */
	if (!name || !guid)
		return EFI_INVALID_PARAMETER;

	/* Validation: We need a buffer if the buffer_size is nonzero. */
	if (buffer_size && !data)
		return EFI_INVALID_PARAMETER;

	/* Compute required size (upper limit with alignments). */
	size = sizeof(*req_data) + sizeof(*guid) + name_size  /* Inputs. */
	       + sizeof(*rsp_data) + buffer_size              /* Outputs. */
	       + 2 * (QCTEE_DMA_ALIGNMENT - 1)                /* Input parameter alignments. */
	       + 1 * (QCTEE_DMA_ALIGNMENT - 1);               /* Output parameter alignments. */

	/* Make sure we have enough DMA memory. */
	status = qctee_dma_realloc(qcuefi->dev, &qcuefi->dma, size, GFP_KERNEL);
	if (status)
		return EFI_OUT_OF_RESOURCES;

	/* Align request struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_req, 0);
	req_data = dma_req.virt;

	/* Set up request data. */
	req_data->command_id = QCTEE_CMD_UEFI_GET_VARIABLE;
	req_data->data_size = buffer_size;
	req_data->name_offset = sizeof(*req_data);
	req_data->name_size = name_size;
	req_data->guid_offset = QCTEE_DMA_ALIGN(req_data->name_offset + name_size);
	req_data->guid_size = sizeof(*guid);
	req_data->length = req_data->guid_offset + req_data->guid_size;

	dma_req.size = req_data->length;

	/* Copy request parameters. */
	utf16_copy_to_buf(dma_req.virt + req_data->name_offset, name, name_size);
	memcpy(dma_req.virt + req_data->guid_offset, guid, req_data->guid_size);

	/* Align response struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_rsp, req_data->length);
	rsp_data = dma_rsp.virt;

	/* Perform SCM call. */
	status = qctee_app_send(qcuefi->dev, qcuefi->app_id, &dma_req, &dma_rsp);

	/* Check for errors and validate. */
	if (status)
		return EFI_DEVICE_ERROR;

	if (rsp_data->command_id != QCTEE_CMD_UEFI_GET_VARIABLE)
		return EFI_DEVICE_ERROR;

	if (rsp_data->length < sizeof(*rsp_data) || rsp_data->length > dma_rsp.size)
		return EFI_DEVICE_ERROR;

	if (rsp_data->status) {
		dev_dbg(qcuefi->dev, "%s: uefisecapp error: 0x%x\n", __func__, rsp_data->status);
		efi_status = qctee_uefi_status_to_efi(rsp_data->status);

		/* Update size and attributes in case buffer is too small. */
		if (efi_status == EFI_BUFFER_TOO_SMALL) {
			*data_size = rsp_data->data_size;
			if (attributes)
				*attributes = rsp_data->attributes;
		}

		return efi_status;
	}

	if (rsp_data->data_offset + rsp_data->data_size > rsp_data->length)
		return EFI_DEVICE_ERROR;

	/* Set attributes and data size even if buffer is too small. */
	*data_size = rsp_data->data_size;
	if (attributes)
		*attributes = rsp_data->attributes;

	/*
	 * If we have a buffer size of zero and no buffer, just return
	 * attributes and required size.
	 */
	if (buffer_size == 0 && !data)
		return EFI_SUCCESS;

	/* Validate output buffer size. */
	if (buffer_size < rsp_data->data_size)
		return EFI_BUFFER_TOO_SMALL;

	/* Copy to output buffer. Note: We're guaranteed to have one at this point. */
	memcpy(data, dma_rsp.virt + rsp_data->data_offset, rsp_data->data_size);
	return EFI_SUCCESS;
}

static efi_status_t qctee_uefi_set_variable(struct qcuefi_client *qcuefi, const efi_char16_t *name,
					    const efi_guid_t *guid, u32 attributes,
					    unsigned long data_size, const void *data)
{
	struct qctee_req_uefi_set_variable *req_data;
	struct qctee_rsp_uefi_set_variable *rsp_data;
	struct qctee_dma dma_req;
	struct qctee_dma dma_rsp;
	unsigned long name_size = utf16_strsize(name);
	unsigned long size;
	int status;

	/* Validate inputs. */
	if (!name || !guid)
		return EFI_INVALID_PARAMETER;

	/*
	 * Make sure we have some data if data_size is nonzero. Note: Using a
	 * size of zero is valid and deletes the variable.
	 */
	if (data_size && !data)
		return EFI_INVALID_PARAMETER;

	/* Compute required size (upper limit with alignments). */
	size = sizeof(*req_data) + name_size + sizeof(*guid) + data_size  /* Inputs. */
	       + sizeof(*rsp_data)                            /* Outputs. */
	       + 2 * (QCTEE_DMA_ALIGNMENT - 1)                /* Input parameter alignments. */
	       + 1 * (QCTEE_DMA_ALIGNMENT - 1);               /* Output parameter alignments. */

	/* Make sure we have enough DMA memory. */
	status = qctee_dma_realloc(qcuefi->dev, &qcuefi->dma, size, GFP_KERNEL);
	if (status)
		return EFI_OUT_OF_RESOURCES;

	/* Align request struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_req, 0);
	req_data = dma_req.virt;

	/* Set up request data. */
	req_data->command_id = QCTEE_CMD_UEFI_SET_VARIABLE;
	req_data->attributes = attributes;
	req_data->name_offset = sizeof(*req_data);
	req_data->name_size = name_size;
	req_data->guid_offset = QCTEE_DMA_ALIGN(req_data->name_offset + name_size);
	req_data->guid_size = sizeof(*guid);
	req_data->data_offset = req_data->guid_offset + req_data->guid_size;
	req_data->data_size = data_size;
	req_data->length = req_data->data_offset + data_size;

	/* Copy request parameters. */
	utf16_copy_to_buf(dma_req.virt + req_data->name_offset, name, req_data->name_size);
	memcpy(dma_req.virt + req_data->guid_offset, guid, req_data->guid_size);

	if (data_size)
		memcpy(dma_req.virt + req_data->data_offset, data, req_data->data_size);

	/* Align response struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_rsp, req_data->length);
	rsp_data = dma_rsp.virt;

	/* Perform SCM call. */
	dma_req.size = req_data->length;
	dma_rsp.size = sizeof(*rsp_data);

	status = qctee_app_send(qcuefi->dev, qcuefi->app_id, &dma_req, &dma_rsp);

	/* Check for errors and validate. */
	if (status)
		return EFI_DEVICE_ERROR;

	if (rsp_data->command_id != QCTEE_CMD_UEFI_SET_VARIABLE)
		return EFI_DEVICE_ERROR;

	if (rsp_data->length < sizeof(*rsp_data) || rsp_data->length > dma_rsp.size)
		return EFI_DEVICE_ERROR;

	if (rsp_data->status) {
		dev_dbg(qcuefi->dev, "%s: uefisecapp error: 0x%x\n", __func__, rsp_data->status);
		return qctee_uefi_status_to_efi(rsp_data->status);
	}

	return EFI_SUCCESS;
}

static efi_status_t qctee_uefi_get_next_variable(struct qcuefi_client *qcuefi,
						 unsigned long *name_size, efi_char16_t *name,
						 efi_guid_t *guid)
{
	struct qctee_req_uefi_get_next_variable *req_data;
	struct qctee_rsp_uefi_get_next_variable *rsp_data;
	struct qctee_dma dma_req;
	struct qctee_dma dma_rsp;
	unsigned long size;
	efi_status_t efi_status;
	int status;

	/* We need some buffers. */
	if (!name_size || !name || !guid)
		return EFI_INVALID_PARAMETER;

	/* There needs to be at least a single null-character. */
	if (*name_size == 0)
		return EFI_INVALID_PARAMETER;

	/* Compute required size (upper limit with alignments). */
	size = sizeof(*req_data) + sizeof(*guid) + *name_size    /* Inputs. */
	       + sizeof(*rsp_data) + sizeof(*guid) + *name_size  /* Outputs. */
	       + 2 * (QCTEE_DMA_ALIGNMENT - 1)                   /* Input parameter alignments. */
	       + 1 * (QCTEE_DMA_ALIGNMENT - 1);                  /* Output parameter alignments. */

	/* Make sure we have enough DMA memory. */
	status = qctee_dma_realloc(qcuefi->dev, &qcuefi->dma, size, GFP_KERNEL);
	if (status)
		return EFI_OUT_OF_RESOURCES;

	/* Align request struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_req, 0);
	req_data = dma_req.virt;

	/* Set up request data. */
	req_data->command_id = QCTEE_CMD_UEFI_GET_NEXT_VARIABLE;
	req_data->guid_offset = QCTEE_DMA_ALIGN(sizeof(*req_data));
	req_data->guid_size = sizeof(*guid);
	req_data->name_offset = req_data->guid_offset + req_data->guid_size;
	req_data->name_size = *name_size;
	req_data->length = req_data->name_offset + req_data->name_size;

	dma_req.size = req_data->length;

	/* Copy request parameters. */
	memcpy(dma_req.virt + req_data->guid_offset, guid, req_data->guid_size);
	utf16_copy_to_buf(dma_req.virt + req_data->name_offset, name, *name_size);

	/* Align response struct. */
	qctee_dma_aligned(&qcuefi->dma, &dma_rsp, req_data->length);
	rsp_data = dma_rsp.virt;

	/* Perform SCM call. */
	status = qctee_app_send(qcuefi->dev, qcuefi->app_id, &dma_req, &dma_rsp);

	/* Check for errors and validate. */
	if (status)
		return EFI_DEVICE_ERROR;

	if (rsp_data->command_id != QCTEE_CMD_UEFI_GET_NEXT_VARIABLE)
		return EFI_DEVICE_ERROR;

	if (rsp_data->length < sizeof(*rsp_data) || rsp_data->length > dma_rsp.size)
		return EFI_DEVICE_ERROR;

	if (rsp_data->status) {
		dev_dbg(qcuefi->dev, "%s: uefisecapp error: 0x%x\n", __func__, rsp_data->status);
		efi_status = qctee_uefi_status_to_efi(rsp_data->status);

		/* Update size with required size in case buffer is too small. */
		if (efi_status == EFI_BUFFER_TOO_SMALL)
			*name_size = rsp_data->name_size;

		return efi_status;
	}

	if (rsp_data->name_offset + rsp_data->name_size > rsp_data->length)
		return EFI_DEVICE_ERROR;

	if (rsp_data->guid_offset + rsp_data->guid_size > rsp_data->length)
		return EFI_DEVICE_ERROR;

	if (rsp_data->name_size > *name_size) {
		*name_size = rsp_data->name_size;
		return EFI_BUFFER_TOO_SMALL;
	}

	if (rsp_data->guid_size != sizeof(*guid))
		return EFI_DEVICE_ERROR;

	/* Copy response fields. */
	memcpy(guid, dma_rsp.virt + rsp_data->guid_offset, rsp_data->guid_size);
	utf16_copy_to_buf(name, dma_rsp.virt + rsp_data->name_offset, rsp_data->name_size);
	*name_size = rsp_data->name_size;

	return 0;
}


/* -- Global efivar interface. ---------------------------------------------- */

static struct qcuefi_client *__qcuefi;
static DEFINE_MUTEX(__qcuefi_lock);

static int qcuefi_set_reference(struct qcuefi_client *qcuefi)
{
	mutex_lock(&__qcuefi_lock);

	if (qcuefi && __qcuefi) {
		mutex_unlock(&__qcuefi_lock);
		return -EEXIST;
	}

	__qcuefi = qcuefi;

	mutex_unlock(&__qcuefi_lock);
	return 0;
}

static struct qcuefi_client *qcuefi_acquire(void)
{
	mutex_lock(&__qcuefi_lock);
	return __qcuefi;
}

static void qcuefi_release(void)
{
	mutex_unlock(&__qcuefi_lock);
}

static efi_status_t qcuefi_get_variable(efi_char16_t *name, efi_guid_t *vendor, u32 *attr,
					unsigned long *data_size, void *data)
{
	struct qcuefi_client *qcuefi;
	efi_status_t status;

	qcuefi = qcuefi_acquire();
	if (!qcuefi)
		return EFI_NOT_READY;

	status = qctee_uefi_get_variable(qcuefi, name, vendor, attr, data_size, data);

	qcuefi_release();
	return status;
}

static efi_status_t qcuefi_set_variable(efi_char16_t *name, efi_guid_t *vendor,
					u32 attr, unsigned long data_size, void *data)
{
	struct qcuefi_client *qcuefi;
	efi_status_t status;

	qcuefi = qcuefi_acquire();
	if (!qcuefi)
		return EFI_NOT_READY;

	status = qctee_uefi_set_variable(qcuefi, name, vendor, attr, data_size, data);

	qcuefi_release();
	return status;
}

static efi_status_t qcuefi_get_next_variable(unsigned long *name_size, efi_char16_t *name,
					     efi_guid_t *vendor)
{
	struct qcuefi_client *qcuefi;
	efi_status_t status;

	qcuefi = qcuefi_acquire();
	if (!qcuefi)
		return EFI_NOT_READY;

	status = qctee_uefi_get_next_variable(qcuefi, name_size, name, vendor);

	qcuefi_release();
	return status;
}

static const struct efivar_operations qcom_efivar_ops = {
	.get_variable = qcuefi_get_variable,
	.set_variable = qcuefi_set_variable,
	.get_next_variable = qcuefi_get_next_variable,
};


/* -- Driver setup. --------------------------------------------------------- */

static int qcom_uefisecapp_probe(struct platform_device *pdev)
{
	struct qcuefi_client *qcuefi;
	int status;

	/* Defer until SCM is available. */
	if (!qcom_scm_is_available())
		return -EPROBE_DEFER;

	/* Allocate driver data. */
	qcuefi = devm_kzalloc(&pdev->dev, sizeof(*qcuefi), GFP_KERNEL);
	if (!qcuefi)
		return -ENOMEM;

	qcuefi->dev = &pdev->dev;

	/* Get application id for uefisecapp. */
	status = qctee_app_get_id(&pdev->dev, QCTEE_UEFISEC_APP_NAME, &qcuefi->app_id);
	if (status) {
		dev_err(&pdev->dev, "failed to query app ID: %d\n", status);
		return status;
	}

	/* Set up DMA. One page should be plenty to start with. */
	if (dma_set_mask(&pdev->dev, DMA_BIT_MASK(64))) {
		dev_warn(&pdev->dev, "no suitable DMA available\n");
		return -EFAULT;
	}

	status = qctee_dma_alloc(&pdev->dev, &qcuefi->dma, PAGE_SIZE, GFP_KERNEL);
	if (status)
		return status;

	/* Set up kobject for efivars interface. */
	qcuefi->kobj = kobject_create_and_add("qcom_tee_uefisecapp", firmware_kobj);
	if (!qcuefi->kobj) {
		status = -ENOMEM;
		goto err_kobj;
	}

	/* Register global reference. */
	platform_set_drvdata(pdev, qcuefi);
	status = qcuefi_set_reference(qcuefi);
	if (status)
		goto err_ref;

	/* Register efivar ops. */
	status = efivars_register(&qcuefi->efivars, &qcom_efivar_ops, qcuefi->kobj);
	if (status)
		goto err_register;

	return 0;

err_register:
	qcuefi_set_reference(NULL);
err_ref:
	kobject_put(qcuefi->kobj);
err_kobj:
	qctee_dma_free(qcuefi->dev, &qcuefi->dma);
	return status;
}

static int qcom_uefisecapp_remove(struct platform_device *pdev)
{
	struct qcuefi_client *qcuefi = platform_get_drvdata(pdev);

	/* Unregister efivar ops. */
	efivars_unregister(&qcuefi->efivars);

	/* Block on pending calls and unregister global reference. */
	qcuefi_set_reference(NULL);

	/* Free remaining resources. */
	kobject_put(qcuefi->kobj);
	qctee_dma_free(qcuefi->dev, &qcuefi->dma);

	return 0;
}

static const struct of_device_id qcom_uefisecapp_dt_match[] = {
	{ .compatible = "qcom,tee-uefisecapp", },
	{ }
};
MODULE_DEVICE_TABLE(of, qcom_uefisecapp_dt_match);

static struct platform_driver qcom_uefisecapp_driver = {
	.probe = qcom_uefisecapp_probe,
	.remove = qcom_uefisecapp_remove,
	.driver = {
		.name = "qcom_tee_uefisecapp",
		.of_match_table = qcom_uefisecapp_dt_match,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};
module_platform_driver(qcom_uefisecapp_driver);

MODULE_AUTHOR("Maximilian Luz <luzmaximilian@gmail.com>");
MODULE_DESCRIPTION("Client driver for Qualcomm TrEE/TZ UEFI Secure App");
MODULE_LICENSE("GPL");
