/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_HRESET_H

/**
 * HRESET - History reset. Available since binutils v2.36.
 *
 * Request the processor to reset the history of task classification on the
 * current logical processor. The history components to be
 * reset are specified in %eax. Only bits specified in CPUID(0x20).EBX
 * and enabled in the IA32_HRESET_ENABLE MSR can be selected.
 *
 * The assembly code looks like:
 *
 *	hreset %eax
 *
 * The corresponding machine code looks like:
 *
 *	F3 0F 3A F0 ModRM Imm
 *
 * The value of ModRM is 0xc0 to specify %eax register addressing.
 * The ignored immediate operand is set to 0.
 *
 * The instruction is documented in the Intel SDM.
 */

#define __ASM_HRESET  ".byte 0xf3, 0xf, 0x3a, 0xf0, 0xc0, 0x0"

void reset_hardware_history(void);

#endif /* _ASM_X86_HRESET_H */
