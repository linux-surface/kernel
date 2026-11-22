// SPDX-License-Identifier: GPL-2.0
/*
 * camss-vfe-170.c
 *
 * Qualcomm MSM Camera Subsystem - VFE (Video Front End) Module v170
 *
 * Copyright (C) 2020-2021 Linaro Ltd.
 */

#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>

#include "camss.h"
#include "camss-vfe.h"

#define VFE_GLOBAL_RESET_CMD			(0x018)
#define		GLOBAL_RESET_CMD_CORE		BIT(0)
#define		GLOBAL_RESET_CMD_CAMIF		BIT(1)
#define		GLOBAL_RESET_CMD_BUS		BIT(2)
#define		GLOBAL_RESET_CMD_BUS_BDG	BIT(3)
#define		GLOBAL_RESET_CMD_REGISTER	BIT(4)
#define		GLOBAL_RESET_CMD_PM		BIT(5)
#define		GLOBAL_RESET_CMD_BUS_MISR	BIT(6)
#define		GLOBAL_RESET_CMD_TESTGEN	BIT(7)
#define		GLOBAL_RESET_CMD_DSP		BIT(8)
#define		GLOBAL_RESET_CMD_IDLE_CGC	BIT(9)
#define		GLOBAL_RESET_CMD_RDI0		BIT(10)
#define		GLOBAL_RESET_CMD_RDI1		BIT(11)
#define		GLOBAL_RESET_CMD_RDI2		BIT(12)
#define		GLOBAL_RESET_CMD_RDI3		BIT(13)
#define		GLOBAL_RESET_CMD_VFE_DOMAIN	BIT(30)
#define		GLOBAL_RESET_CMD_RESET_BYPASS	BIT(31)

#define VFE_CORE_CFG				(0x050)
#define		CFG_PIXEL_PATTERN_YCBYCR	(0x4)
#define		CFG_PIXEL_PATTERN_YCRYCB	(0x5)
#define		CFG_PIXEL_PATTERN_CBYCRY	(0x6)
#define		CFG_PIXEL_PATTERN_CRYCBY	(0x7)
#define		CFG_COMPOSITE_REG_UPDATE_EN	BIT(4)

#define VFE_IRQ_CMD				(0x058)
#define		CMD_GLOBAL_CLEAR		BIT(0)

#define VFE_IRQ_MASK_0					(0x05c)
#define		MASK_0_CAMIF_SOF			BIT(0)
#define		MASK_0_CAMIF_EOF			BIT(1)
#define		MASK_0_RDI_REG_UPDATE(n)		BIT((n) + 5)
#define		MASK_0_IMAGE_MASTER_n_PING_PONG(n)	BIT((n) + 8)
#define		MASK_0_IMAGE_COMPOSITE_DONE_n(n)	BIT((n) + 25)
#define		MASK_0_RESET_ACK			BIT(31)

#define VFE_IRQ_MASK_1					(0x060)
#define		MASK_1_CAMIF_ERROR			BIT(0)
#define		MASK_1_VIOLATION			BIT(7)
#define		MASK_1_BUS_BDG_HALT_ACK			BIT(8)
#define		MASK_1_IMAGE_MASTER_n_BUS_OVERFLOW(n)	BIT((n) + 9)
#define		MASK_1_RDI_SOF(n)			BIT((n) + 29)

#define VFE_IRQ_CLEAR_0					(0x064)
#define VFE_IRQ_CLEAR_1					(0x068)

#define VFE_IRQ_STATUS_0				(0x06c)
#define		STATUS_0_CAMIF_SOF			BIT(0)
#define		STATUS_0_RDI_REG_UPDATE(n)		BIT((n) + 5)
#define		STATUS_0_IMAGE_MASTER_PING_PONG(n)	BIT((n) + 8)
#define		STATUS_0_IMAGE_COMPOSITE_DONE(n)	BIT((n) + 25)
#define		STATUS_0_RESET_ACK			BIT(31)

#define VFE_IRQ_STATUS_1				(0x070)
#define		STATUS_1_VIOLATION			BIT(7)
#define		STATUS_1_BUS_BDG_HALT_ACK		BIT(8)
#define		STATUS_1_RDI_SOF(n)			BIT((n) + 27)

#define VFE_VIOLATION_STATUS			(0x07c)

#define VFE_CAMIF_CMD				(0x478)
#define		CMD_CLEAR_CAMIF_STATUS		BIT(2)

#define VFE_CAMIF_CFG				(0x47c)
#define		CFG_VSYNC_SYNC_EDGE		(0)
#define			VSYNC_ACTIVE_HIGH	(0)
#define			VSYNC_ACTIVE_LOW	(1)
#define		CFG_HSYNC_SYNC_EDGE		(1)
#define			HSYNC_ACTIVE_HIGH	(0)
#define			HSYNC_ACTIVE_LOW	(1)
#define		CFG_VFE_SUBSAMPLE_ENABLE	BIT(4)
#define		CFG_BUS_SUBSAMPLE_ENABLE	BIT(5)
#define		CFG_VFE_OUTPUT_EN		BIT(6)
#define		CFG_BUS_OUTPUT_EN		BIT(7)
#define		CFG_BINNING_EN			BIT(9)
#define		CFG_FRAME_BASED_EN		BIT(10)
#define		CFG_RAW_CROP_EN			BIT(22)

#define VFE_REG_UPDATE_CMD			(0x4ac)
#define		REG_UPDATE_RDI(n)		BIT(1 + (n))

#define VFE_BUS_IRQ_MASK(n)		(0x2044 + (n) * 4)
#define VFE_BUS_IRQ_CLEAR(n)		(0x2050 + (n) * 4)
#define VFE_BUS_IRQ_STATUS(n)		(0x205c + (n) * 4)
#define		STATUS0_COMP_RESET_DONE		BIT(0)
#define		STATUS0_COMP_REG_UPDATE0_DONE	BIT(1)
#define		STATUS0_COMP_REG_UPDATE1_DONE	BIT(2)
#define		STATUS0_COMP_REG_UPDATE2_DONE	BIT(3)
#define		STATUS0_COMP_REG_UPDATE3_DONE	BIT(4)
#define		STATUS0_COMP_REG_UPDATE_DONE(n)	BIT((n) + 1)
#define		STATUS0_COMP0_BUF_DONE		BIT(5)
#define		STATUS0_COMP1_BUF_DONE		BIT(6)
#define		STATUS0_COMP2_BUF_DONE		BIT(7)
#define		STATUS0_COMP3_BUF_DONE		BIT(8)
#define		STATUS0_COMP4_BUF_DONE		BIT(9)
#define		STATUS0_COMP5_BUF_DONE		BIT(10)
#define		STATUS0_COMP_BUF_DONE(n)	BIT((n) + 5)
#define		STATUS0_COMP_ERROR		BIT(11)
#define		STATUS0_COMP_OVERWRITE		BIT(12)
#define		STATUS0_OVERFLOW		BIT(13)
#define		STATUS0_VIOLATION		BIT(14)
#define		STATUS0_BUS_ERROR_MASK		(STATUS0_COMP_ERROR | \
						 STATUS0_COMP_OVERWRITE | \
						 STATUS0_OVERFLOW | \
						 STATUS0_VIOLATION)
/* WM_CLIENT_BUF_DONE defined for buffers 0:23 on Full VFE175, 0:3 on VFE Lite */
#define		STATUS1_WM_CLIENT_BUF_DONE(n)		BIT(n)
#define		STATUS1_EARLY_DONE			BIT(24)
#define		STATUS2_DUAL_COMP0_BUF_DONE		BIT(0)
#define		STATUS2_DUAL_COMP1_BUF_DONE		BIT(1)
#define		STATUS2_DUAL_COMP2_BUF_DONE		BIT(2)
#define		STATUS2_DUAL_COMP3_BUF_DONE		BIT(3)
#define		STATUS2_DUAL_COMP4_BUF_DONE		BIT(4)
#define		STATUS2_DUAL_COMP5_BUF_DONE		BIT(5)
#define		STATUS2_DUAL_COMP_BUF_DONE(n)		BIT(n)
#define		STATUS2_DUAL_COMP_ERROR			BIT(6)
#define		STATUS2_DUAL_COMP_OVERWRITE		BIT(7)

#define VFE_BUS_IRQ_CLEAR_GLOBAL		(0x2068)

#define VFE_BUS_WM_DEBUG_STATUS_CFG		(0x226c)
#define		DEBUG_STATUS_CFG_STATUS0(n)	BIT(n)
#define		DEBUG_STATUS_CFG_STATUS1(n)	BIT(8 + (n))

#define VFE_BUS_WM_ADDR_SYNC_FRAME_HEADER	(0x2080)

#define VFE_BUS_WM_ADDR_SYNC_NO_SYNC		(0x2084)
#define		BUS_VER2_MAX_CLIENTS		(20)
#define		BUS_VER2_LITE_MAX_CLIENTS	(4)
#define		WM_ADDR_NO_SYNC_DEFAULT_VAL \
				((1 << BUS_VER2_MAX_CLIENTS) - 1)
#define		WM_ADDR_NO_SYNC_LITE_VAL \
				((1 << BUS_VER2_LITE_MAX_CLIENTS) - 1)

#define VFE_BUS_WM_CGC_OVERRIDE			(0x200c)
#define		WM_CGC_OVERRIDE_ALL		(0xFFFFF)

#define VFE_BUS_WM_TEST_BUS_CTRL		(0x211c)

#define VFE_BUS_WM_STATUS0(n)			(0x2200 + (n) * 0x100)
#define VFE_BUS_WM_STATUS1(n)			(0x2204 + (n) * 0x100)
#define VFE_BUS_WM_CFG(n)			(0x2208 + (n) * 0x100)
#define		WM_CFG_EN			(0)
#define		WM_CFG_MODE			(1)
#define			MODE_QCOM_PLAIN	(0)
#define			MODE_MIPI_RAW	(1)
#define		WM_CFG_VIRTUALFRAME		(2)
#define VFE_BUS_WM_HEADER_ADDR(n)		(0x220c + (n) * 0x100)
#define VFE_BUS_WM_HEADER_CFG(n)		(0x2210 + (n) * 0x100)
#define VFE_BUS_WM_IMAGE_ADDR(n)		(0x2214 + (n) * 0x100)
#define VFE_BUS_WM_IMAGE_ADDR_OFFSET(n)		(0x2218 + (n) * 0x100)
#define VFE_BUS_WM_BUFFER_WIDTH_CFG(n)		(0x221c + (n) * 0x100)
#define		WM_BUFFER_DEFAULT_WIDTH		(0xFF01)

#define VFE_BUS_WM_BUFFER_HEIGHT_CFG(n)		(0x2220 + (n) * 0x100)
#define VFE_BUS_WM_PACKER_CFG(n)		(0x2224 + (n) * 0x100)

#define VFE_BUS_WM_STRIDE(n)			(0x2228 + (n) * 0x100)
#define		WM_STRIDE_DEFAULT_STRIDE	(0xFF01)

#define VFE_BUS_WM_IRQ_SUBSAMPLE_PERIOD(n)	(0x2248 + (n) * 0x100)
#define VFE_BUS_WM_IRQ_SUBSAMPLE_PATTERN(n)	(0x224c + (n) * 0x100)
#define VFE_BUS_WM_FRAMEDROP_PERIOD(n)		(0x2250 + (n) * 0x100)
#define VFE_BUS_WM_FRAMEDROP_PATTERN(n)		(0x2254 + (n) * 0x100)
#define VFE_BUS_WM_FRAME_INC(n)			(0x2258 + (n) * 0x100)
#define VFE_BUS_WM_BURST_LIMIT(n)		(0x225c + (n) * 0x100)

static inline void vfe_reg_set(struct vfe_device *vfe, u32 reg, u32 set_bits)
{
	u32 bits = readl_relaxed(vfe->base + reg);

	writel_relaxed(bits | set_bits, vfe->base + reg);
}

static void vfe_global_reset(struct vfe_device *vfe)
{
	u32 reset_bits;

	if (vfe_is_lite(vfe)) {
		reset_bits = GLOBAL_RESET_CMD_CORE	|
			     GLOBAL_RESET_CMD_BUS	|
			     GLOBAL_RESET_CMD_REGISTER	|
			     GLOBAL_RESET_CMD_IDLE_CGC	|
			     GLOBAL_RESET_CMD_RDI0	|
			     GLOBAL_RESET_CMD_RDI1	|
			     GLOBAL_RESET_CMD_RDI2	|
			     GLOBAL_RESET_CMD_RDI3;
	} else {
		reset_bits = GLOBAL_RESET_CMD_CORE	|
			     GLOBAL_RESET_CMD_CAMIF	|
			     GLOBAL_RESET_CMD_BUS	|
			     GLOBAL_RESET_CMD_BUS_BDG	|
			     GLOBAL_RESET_CMD_REGISTER	|
			     GLOBAL_RESET_CMD_TESTGEN	|
			     GLOBAL_RESET_CMD_DSP	|
			     GLOBAL_RESET_CMD_IDLE_CGC	|
			     GLOBAL_RESET_CMD_RDI0	|
			     GLOBAL_RESET_CMD_RDI1	|
			     GLOBAL_RESET_CMD_RDI2	|
			     GLOBAL_RESET_CMD_RDI3;
	}

	writel_relaxed(BIT(31), vfe->base + VFE_IRQ_MASK_0);

	/* Make sure IRQ mask has been written before resetting */
	wmb();

	writel_relaxed(reset_bits, vfe->base + VFE_GLOBAL_RESET_CMD);
}

static void vfe_wm_start(struct vfe_device *vfe, u8 wm, struct vfe_line *line)
{
	struct v4l2_pix_format_mplane *pix =
		&line->video_out.active_fmt.fmt.pix_mp;
	u32 stride = pix->plane_fmt[0].bytesperline ?
		     pix->plane_fmt[0].bytesperline : pix->width;
	u32 height = pix->height;
	u32 val;

	/* Set Debug Registers (Full VFE only; VFE Lite does not have 0x226c) */
	if (!vfe_is_lite(vfe)) {
		val = DEBUG_STATUS_CFG_STATUS0(1) |
		      DEBUG_STATUS_CFG_STATUS0(7);
		writel_relaxed(val, vfe->base + VFE_BUS_WM_DEBUG_STATUS_CFG);
	}

	/* BUS_WM_INPUT_IF_ADDR_SYNC_FRAME_HEADER */
	writel_relaxed(0, vfe->base + VFE_BUS_WM_ADDR_SYNC_FRAME_HEADER);

	/* no clock gating at bus input */
	val = WM_CGC_OVERRIDE_ALL;
	writel_relaxed(val, vfe->base + VFE_BUS_WM_CGC_OVERRIDE);

	writel_relaxed(0x0, vfe->base + VFE_BUS_WM_TEST_BUS_CTRL);

	/* if addr_no_sync has default value then config the addr no sync reg */
	val = vfe_is_lite(vfe) ? WM_ADDR_NO_SYNC_LITE_VAL :
				 WM_ADDR_NO_SYNC_DEFAULT_VAL;
	writel_relaxed(val, vfe->base + VFE_BUS_WM_ADDR_SYNC_NO_SYNC);

	writel_relaxed(0xf, vfe->base + VFE_BUS_WM_BURST_LIMIT(wm));
	writel_relaxed(stride * height, vfe->base + VFE_BUS_WM_FRAME_INC(wm));

	/* Qualcomm RDI bus defaults: width and stride = 0xFF01, height = 0, packer = 0 */
	writel_relaxed(WM_BUFFER_DEFAULT_WIDTH,
		       vfe->base + VFE_BUS_WM_BUFFER_WIDTH_CFG(wm));
	writel_relaxed(0, vfe->base + VFE_BUS_WM_BUFFER_HEIGHT_CFG(wm));
	writel_relaxed(0, vfe->base + VFE_BUS_WM_PACKER_CFG(wm));
	writel_relaxed(WM_STRIDE_DEFAULT_STRIDE,
		       vfe->base + VFE_BUS_WM_STRIDE(wm));

	/* No dropped frames, one IRQ per frame */
	writel_relaxed(0, vfe->base + VFE_BUS_WM_FRAMEDROP_PERIOD(wm));
	writel_relaxed(1, vfe->base + VFE_BUS_WM_FRAMEDROP_PATTERN(wm));
	writel_relaxed(0, vfe->base + VFE_BUS_WM_IRQ_SUBSAMPLE_PERIOD(wm));
	writel_relaxed(1, vfe->base + VFE_BUS_WM_IRQ_SUBSAMPLE_PATTERN(wm));

	/*
	 * Subscribe only to WM_CLIENT_BUF_DONE(wm) in Bus IRQ Mask 1 (keeping
	 * Bus IRQ Mask 0 for hardware error reporting) so vfe_buf_done() fires
	 * once per frame. Defer enabling WM_CFG until vfe_wm_update() writes
	 * the first buffer IOVA into the 2-deep IMAGE_ADDR FIFO.
	 */
	val = readl_relaxed(vfe->base + VFE_BUS_IRQ_MASK(0));
	val |= STATUS0_BUS_ERROR_MASK;
	writel_relaxed(val, vfe->base + VFE_BUS_IRQ_MASK(0));

	val = readl_relaxed(vfe->base + VFE_BUS_IRQ_MASK(1));
	val |= STATUS1_WM_CLIENT_BUF_DONE(wm);
	writel_relaxed(val, vfe->base + VFE_BUS_IRQ_MASK(1));

	/* Ensure WM configuration writes complete before buffer enqueue */
	wmb();
}

static void vfe_wm_stop(struct vfe_device *vfe, u8 wm)
{
	u32 val;

	/* Unsubscribe WM IRQ in Bus IRQ Mask 1 */
	val = readl_relaxed(vfe->base + VFE_BUS_IRQ_MASK(1));
	val &= ~STATUS1_WM_CLIENT_BUF_DONE(wm);
	writel_relaxed(val, vfe->base + VFE_BUS_IRQ_MASK(1));
	/* Ensure IRQ mask update completes before disabling WM */
	wmb();

	/* Disable WM */
	writel_relaxed(0, vfe->base + VFE_BUS_WM_CFG(wm));
	/* Ensure WM disable write reaches hardware */
	wmb();
}

static void vfe_wm_update(struct vfe_device *vfe, u8 wm, u32 addr,
			  struct vfe_line *line)
{
	struct v4l2_pix_format_mplane *pix =
		&line->video_out.active_fmt.fmt.pix_mp;
	u32 stride = pix->plane_fmt[0].bytesperline;
	u32 dummy_iova = (u32)vfe->camss->dummy_buf_iova;

	if (!addr)
		addr = dummy_iova;

	writel_relaxed(addr, vfe->base + VFE_BUS_WM_IMAGE_ADDR(wm));
	writel_relaxed(addr == dummy_iova ? 0 : (stride * pix->height),
		       vfe->base + VFE_BUS_WM_FRAME_INC(wm));
	/* Ensure IMAGE_ADDR and FRAME_INC land before enabling WM_CFG */
	wmb();
	writel_relaxed((1 << WM_CFG_EN) | (MODE_MIPI_RAW << WM_CFG_MODE),
		       vfe->base + VFE_BUS_WM_CFG(wm));
	/* Ensure WM enable write reaches hardware before REG_UPDATE */
	wmb();
}

static void vfe_reg_update(struct vfe_device *vfe, enum vfe_line_id line_id)
{
	vfe->reg_update |= REG_UPDATE_RDI(line_id);

	/* Enforce ordering between previous reg writes and reg update */
	wmb();

	writel_relaxed(vfe->reg_update, vfe->base + VFE_REG_UPDATE_CMD);

	/* Enforce ordering between reg update and subsequent reg writes */
	wmb();
}

static inline void vfe_reg_update_clear(struct vfe_device *vfe,
					enum vfe_line_id line_id)
{
	vfe->reg_update &= ~REG_UPDATE_RDI(line_id);
}

static void vfe_enable_irq_common(struct vfe_device *vfe)
{
	/*
	 * Bit 31: STATUS_0_RESET_ACK
	 * Bits 27-30: RDI0-3 SOF
	 * Bits 4, 7, 9: BUS_TOP_IRQ (routes VFE_BUS_IRQ_STATUS[0..2] to top IRQ)
	 * Bits 5-8: RDI0-3 REG_UPDATE
	 */
	writel_relaxed(STATUS_0_RESET_ACK | 0x780001e0 | BIT(4) | BIT(7) | BIT(9),
		       vfe->base + VFE_IRQ_MASK_0);
	writel_relaxed(MASK_1_CAMIF_ERROR | MASK_1_VIOLATION |
		       MASK_1_BUS_BDG_HALT_ACK,
		       vfe->base + VFE_IRQ_MASK_1);

	/*
	 * VFE_CORE_CFG (0x050): keep 0 so local SOF latches registers
	 * (BIT(4) selects extern_reg_update slave mode).
	 */
	writel_relaxed(0, vfe->base + VFE_CORE_CFG);

	/* Override clock gating for bus bridge (VFE TOP 0x3C) */
	writel_relaxed(0xffffffff, vfe->base + 0x03c);
	/* Ensure core/bridge configuration lands before bus IRQ masks */
	wmb();

	/* Enable bus error IRQs only */
	writel_relaxed(STATUS0_BUS_ERROR_MASK, vfe->base + VFE_BUS_IRQ_MASK(0));
	writel_relaxed(0, vfe->base + VFE_BUS_IRQ_MASK(1));
	writel_relaxed(STATUS2_DUAL_COMP_ERROR, vfe->base + VFE_BUS_IRQ_MASK(2));
}

static void vfe_isr_halt_ack(struct vfe_device *vfe)
{
	complete(&vfe->halt_complete);
}

static void vfe_isr_read(struct vfe_device *vfe, u32 *status0, u32 *status1)
{
	*status0 = readl_relaxed(vfe->base + VFE_IRQ_STATUS_0);
	*status1 = readl_relaxed(vfe->base + VFE_IRQ_STATUS_1);

	writel_relaxed(*status0, vfe->base + VFE_IRQ_CLEAR_0);
	writel_relaxed(*status1, vfe->base + VFE_IRQ_CLEAR_1);

	/* Enforce ordering between IRQ Clear and Global IRQ Clear */
	wmb();
	writel_relaxed(CMD_GLOBAL_CLEAR, vfe->base + VFE_IRQ_CMD);
}

static void vfe_violation_read(struct vfe_device *vfe)
{
	u32 violation = readl_relaxed(vfe->base + VFE_VIOLATION_STATUS);

	pr_err_ratelimited("VFE: violation = 0x%08x\n", violation);
}

/*
 * vfe_isr - VFE module interrupt handler
 * @irq: Interrupt line
 * @dev: VFE device
 *
 * Return IRQ_HANDLED on success
 */
static irqreturn_t vfe_isr(int irq, void *dev)
{
	struct vfe_device *vfe = dev;
	u32 status0, status1, vfe_bus_status[VFE_LINE_NUM_MAX];
	int i, wm;

	status0 = readl_relaxed(vfe->base + VFE_IRQ_STATUS_0);
	status1 = readl_relaxed(vfe->base + VFE_IRQ_STATUS_1);

	writel_relaxed(status0, vfe->base + VFE_IRQ_CLEAR_0);
	writel_relaxed(status1, vfe->base + VFE_IRQ_CLEAR_1);

	for (i = 0; i < 3; i++) {
		vfe_bus_status[i] = readl_relaxed(vfe->base + VFE_BUS_IRQ_STATUS(i));
		writel_relaxed(vfe_bus_status[i], vfe->base + VFE_BUS_IRQ_CLEAR(i));
	}

	/* Enforce ordering between IRQ reading and interpretation */
	wmb();

	writel_relaxed(CMD_GLOBAL_CLEAR, vfe->base + VFE_IRQ_CMD);
	writel_relaxed(1, vfe->base + VFE_BUS_IRQ_CLEAR_GLOBAL);

	if (vfe_bus_status[0] & STATUS0_BUS_ERROR_MASK)
		dev_err_ratelimited(vfe->camss->dev,
				    "vfe%d bus error: bus0=0x%08x st0=0x%08x st1=0x%08x\n",
				    vfe->id, vfe_bus_status[0], status0, status1);

	if (status0 & STATUS_0_RESET_ACK)
		vfe->isr_ops.reset_ack(vfe);

	if (status1 & STATUS_1_VIOLATION)
		vfe_violation_read(vfe);

	for (i = VFE_LINE_RDI0; i < vfe->res->line_num; i++)
		if (status0 & STATUS_0_RDI_REG_UPDATE(i))
			vfe->isr_ops.reg_update(vfe, i);

	for (i = VFE_LINE_RDI0; i < vfe->res->line_num; i++)
		if ((status1 & STATUS_1_RDI_SOF(i)) ||
		    (status0 & BIT(27 + i)))
			vfe->isr_ops.sof(vfe, i);

	for (i = 0; i < MSM_VFE_COMPOSITE_IRQ_NUM; i++)
		if (vfe_bus_status[0] & STATUS0_COMP_BUF_DONE(i))
			vfe->isr_ops.comp_done(vfe, i);

	for (wm = 0; wm < MSM_VFE_IMAGE_MASTERS_NUM; wm++)
		if (vfe_bus_status[1] & STATUS1_WM_CLIENT_BUF_DONE(wm))
			vfe->isr_ops.wm_done(vfe, wm);

	return IRQ_HANDLED;
}

/*
 * vfe_halt - Mask and clear pending interrupts on VFE module
 * @vfe: VFE device
 *
 * Return 0 on success or a negative error code otherwise
 */
static int vfe_halt(struct vfe_device *vfe)
{
	writel_relaxed(0, vfe->base + VFE_IRQ_MASK_0);
	writel_relaxed(0, vfe->base + VFE_IRQ_MASK_1);
	writel_relaxed(~0u, vfe->base + VFE_IRQ_CLEAR_0);
	writel_relaxed(~0u, vfe->base + VFE_IRQ_CLEAR_1);
	writel_relaxed(CMD_GLOBAL_CLEAR, vfe->base + VFE_IRQ_CMD);

	writel_relaxed(0, vfe->base + VFE_BUS_IRQ_MASK(0));
	writel_relaxed(0, vfe->base + VFE_BUS_IRQ_MASK(1));
	writel_relaxed(0, vfe->base + VFE_BUS_IRQ_MASK(2));
	writel_relaxed(~0u, vfe->base + VFE_BUS_IRQ_CLEAR(0));
	writel_relaxed(~0u, vfe->base + VFE_BUS_IRQ_CLEAR(1));
	writel_relaxed(~0u, vfe->base + VFE_BUS_IRQ_CLEAR(2));
	writel_relaxed(1, vfe->base + VFE_BUS_IRQ_CLEAR_GLOBAL);
	vfe->reg_update = 0;
	/* Ensure IRQ mask/clear writes reach hardware before halt completes */
	wmb();

	return 0;
}

/*
 * vfe_enable - Enable streaming on VFE line
 * @line: VFE line
 *
 * Return 0 on success or a negative error code otherwise
 */
static int vfe_enable(struct vfe_line *line)
{
	struct vfe_device *vfe = to_vfe(line);
	int ret;

	mutex_lock(&vfe->stream_lock);

	if (!vfe->stream_count)
		vfe_enable_irq_common(vfe);

	vfe->stream_count++;

	mutex_unlock(&vfe->stream_lock);

	ret = vfe_get_output_v2(line);
	if (ret < 0)
		goto error_get_output;

	ret = vfe_enable_output_v2(line);
	if (ret < 0)
		goto error_enable_output;

	vfe->was_streaming = 1;

	return 0;

error_enable_output:
	vfe_put_output(line);

error_get_output:
	mutex_lock(&vfe->stream_lock);

	vfe->stream_count--;

	mutex_unlock(&vfe->stream_lock);

	return ret;
}

/*
 * vfe_isr_sof - Process start of frame interrupt
 * @vfe: VFE Device
 * @line_id: VFE line
 */
static void vfe_isr_sof(struct vfe_device *vfe, enum vfe_line_id line_id)
{
	/* nop */
}

/*
 * vfe_isr_reg_update - Process reg update interrupt
 * @vfe: VFE Device
 * @line_id: VFE line
 */
static void vfe_isr_reg_update(struct vfe_device *vfe, enum vfe_line_id line_id)
{
	struct vfe_output *output;
	unsigned long flags;

	spin_lock_irqsave(&vfe->output_lock, flags);
	vfe->res->hw_ops->reg_update_clear(vfe, line_id);

	output = &vfe->line[line_id].output;

	if (output->wait_reg_update) {
		output->wait_reg_update = 0;
		complete(&output->reg_update);
	}

	spin_unlock_irqrestore(&vfe->output_lock, flags);
}

/*
 * vfe_isr_wm_done - Process write master done interrupt
 * @vfe: VFE Device
 * @wm: Write master id
 */
static void vfe_isr_wm_done(struct vfe_device *vfe, u8 wm)
{
	vfe_buf_done(vfe, wm);
}

static const struct vfe_isr_ops vfe_isr_ops_170 = {
	.reset_ack = vfe_isr_reset_ack,
	.halt_ack = vfe_isr_halt_ack,
	.reg_update = vfe_isr_reg_update,
	.sof = vfe_isr_sof,
	.comp_done = vfe_isr_comp_done,
	.wm_done = vfe_isr_wm_done,
};

static const struct camss_video_ops vfe_video_ops_170 = {
	.queue_buffer = vfe_queue_buffer_v2,
	.flush_buffers = vfe_flush_buffers,
};

static void vfe_subdev_init(struct device *dev, struct vfe_device *vfe)
{
	vfe->isr_ops = vfe_isr_ops_170;
	vfe->video_ops = vfe_video_ops_170;
}

const struct vfe_hw_ops vfe_ops_170 = {
	.global_reset = vfe_global_reset,
	.hw_version = vfe_hw_version,
	.isr_read = vfe_isr_read,
	.isr = vfe_isr,
	.pm_domain_off = vfe_pm_domain_off,
	.pm_domain_on = vfe_pm_domain_on,
	.reg_update_clear = vfe_reg_update_clear,
	.reg_update = vfe_reg_update,
	.subdev_init = vfe_subdev_init,
	.vfe_disable = vfe_disable,
	.vfe_enable = vfe_enable,
	.vfe_halt = vfe_halt,
	.violation_read = vfe_violation_read,
	.vfe_wm_start = vfe_wm_start,
	.vfe_wm_stop = vfe_wm_stop,
	.vfe_wm_update = vfe_wm_update,
};
