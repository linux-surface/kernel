// SPDX-License-Identifier: GPL-2.0
/*
 * Author: Yun Liu <liuyun@loongson.cn>
 *         Huacai Chen <chenhuacai@loongson.cn>
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/efi.h>
#include <asm/efi.h>
#include <asm/addrspace.h>
#include "efistub.h"

typedef void __noreturn (*kernel_entry_t)(bool efi, unsigned long fdt);

extern int kernel_asize;
extern int kernel_fsize;
extern int kernel_offset;
extern kernel_entry_t kernel_entry;

static efi_guid_t screen_info_guid = LINUX_EFI_LARCH_SCREEN_INFO_TABLE_GUID;

struct screen_info *alloc_screen_info(void)
{
	efi_status_t status;
	struct screen_info *si;

	status = efi_bs_call(allocate_pool,
			EFI_RUNTIME_SERVICES_DATA, sizeof(*si), (void **)&si);
	if (status != EFI_SUCCESS)
		return NULL;

	status = efi_bs_call(install_configuration_table, &screen_info_guid, si);
	if (status == EFI_SUCCESS)
		return si;

	efi_bs_call(free_pool, si);

	return NULL;
}

void free_screen_info(struct screen_info *si)
{
	if (!si)
		return;

	efi_bs_call(install_configuration_table, &screen_info_guid, NULL);
	efi_bs_call(free_pool, si);
}

efi_status_t check_platform_features(void)
{
	/* Config Direct Mapping */
	csr_writeq(CSR_DMW0_INIT, LOONGARCH_CSR_DMWIN0);
	csr_writeq(CSR_DMW1_INIT, LOONGARCH_CSR_DMWIN1);

	return EFI_SUCCESS;
}

efi_status_t handle_kernel_image(unsigned long *image_addr,
				 unsigned long *image_size,
				 unsigned long *reserve_addr,
				 unsigned long *reserve_size,
				 efi_loaded_image_t *image)
{
	efi_status_t status;
	unsigned long kernel_addr = 0;

	kernel_addr = (unsigned long)&kernel_offset - kernel_offset;

	status = efi_relocate_kernel(&kernel_addr, kernel_fsize, kernel_asize,
				     PHYSADDR(VMLINUX_LOAD_ADDRESS), SZ_2M, 0x0);

	*image_addr = kernel_addr;
	*image_size = kernel_asize;

	return status;
}

void __noreturn efi_enter_kernel(unsigned long entrypoint, unsigned long fdt, unsigned long fdt_size)
{
	kernel_entry_t real_kernel_entry;

	real_kernel_entry = (kernel_entry_t)
		((unsigned long)&kernel_entry - entrypoint + VMLINUX_LOAD_ADDRESS);

	real_kernel_entry(true, fdt);
}
