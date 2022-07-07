// SPDX-License-Identifier: GPL-2.0-only
/*
 * NXP MU worked as MSI controller
 *
 * Copyright (c) 2018 Pengutronix, Oleksij Rempel <o.rempel@pengutronix.de>
 * Copyright 2022 NXP
 *	Frank Li <Frank.Li@nxp.com>
 *	Peng Fan <peng.fan@nxp.com>
 *
 * Based on drivers/mailbox/imx-mailbox.c
 */
#include <linux/clk.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/of_irq.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/spinlock.h>
#include <linux/dma-iommu.h>
#include <linux/pm_runtime.h>
#include <linux/pm_domain.h>


#define IMX_MU_CHANS            4

enum imx_mu_chan_type {
	IMX_MU_TYPE_TX,         /* Tx */
	IMX_MU_TYPE_RX,         /* Rx */
	IMX_MU_TYPE_TXDB,       /* Tx doorbell */
	IMX_MU_TYPE_RXDB,       /* Rx doorbell */
};

enum imx_mu_xcr {
	IMX_MU_GIER,
	IMX_MU_GCR,
	IMX_MU_TCR,
	IMX_MU_RCR,
	IMX_MU_xCR_MAX,
};

enum imx_mu_xsr {
	IMX_MU_SR,
	IMX_MU_GSR,
	IMX_MU_TSR,
	IMX_MU_RSR,
};

enum imx_mu_type {
	IMX_MU_V1,
	IMX_MU_V2,
	IMX_MU_V2_S4 = BIT(15),
};

/* Receive Interrupt Enable */
#define IMX_MU_xCR_RIEn(type, x) (type & IMX_MU_V2 ? BIT(x) : BIT(24 + (3 - (x))))
#define IMX_MU_xSR_RFn(type, x) (type & IMX_MU_V2 ? BIT(x) : BIT(24 + (3 - (x))))

struct imx_mu_dcfg {
	enum imx_mu_type type;
	u32     xTR;            /* Transmit Register0 */
	u32     xRR;            /* Receive Register0 */
	u32     xSR[4];         /* Status Registers */
	u32     xCR[4];         /* Control Registers */
};

struct imx_mu_msi {
	spinlock_t		lock;
	struct platform_device	*pdev;
	struct irq_domain	*parent;
	struct irq_domain	*msi_domain;
	void __iomem		*regs;
	phys_addr_t		msiir_addr;
	struct imx_mu_dcfg	*cfg;
	u32			msir_num;
	struct imx_mu_msir	*msir;
	u32			irqs_num;
	unsigned long		used;
	u32			gic_irq;
	struct clk              *clk;
	struct device		*pd_a;
	struct device		*pd_b;
	struct device_link	*pd_link_a;
	struct device_link	*pd_link_b;
};

static void imx_mu_write(struct imx_mu_msi *msi_data, u32 val, u32 offs)
{
	iowrite32(val, msi_data->regs + offs);
}

static u32 imx_mu_read(struct imx_mu_msi *msi_data, u32 offs)
{
	return ioread32(msi_data->regs + offs);
}

static u32 imx_mu_xcr_rmw(struct imx_mu_msi *msi_data, enum imx_mu_xcr type, u32 set, u32 clr)
{
	unsigned long flags;
	u32 val;

	spin_lock_irqsave(&msi_data->lock, flags);
	val = imx_mu_read(msi_data, msi_data->cfg->xCR[type]);
	val &= ~clr;
	val |= set;
	imx_mu_write(msi_data, val, msi_data->cfg->xCR[type]);
	spin_unlock_irqrestore(&msi_data->lock, flags);

	return val;
}

static void imx_mu_msi_mask_irq(struct irq_data *data)
{
	struct imx_mu_msi *msi_data = irq_data_get_irq_chip_data(data->parent_data);

	pci_msi_mask_irq(data);
	imx_mu_xcr_rmw(msi_data, IMX_MU_RCR, 0, IMX_MU_xCR_RIEn(msi_data->cfg->type, data->hwirq));
}

static void imx_mu_msi_unmask_irq(struct irq_data *data)
{
	struct imx_mu_msi *msi_data = irq_data_get_irq_chip_data(data->parent_data);

	pci_msi_unmask_irq(data);
	imx_mu_xcr_rmw(msi_data, IMX_MU_RCR, IMX_MU_xCR_RIEn(msi_data->cfg->type, data->hwirq), 0);
}

static struct irq_chip imx_mu_msi_irq_chip = {
	.name = "MU-MSI",
	.irq_mask       = imx_mu_msi_mask_irq,
	.irq_unmask     = imx_mu_msi_unmask_irq,
};

static struct msi_domain_ops its_pmsi_ops = {
};

static struct msi_domain_info imx_mu_msi_domain_info = {
	.flags	= (MSI_FLAG_USE_DEF_DOM_OPS |
		   MSI_FLAG_USE_DEF_CHIP_OPS |
		   MSI_FLAG_PCI_MSIX),
	.ops	= &its_pmsi_ops,
	.chip	= &imx_mu_msi_irq_chip,
};

static void imx_mu_msi_compose_msg(struct irq_data *data, struct msi_msg *msg)
{
	struct imx_mu_msi *msi_data = irq_data_get_irq_chip_data(data);

	msg->address_hi = upper_32_bits(msi_data->msiir_addr);
	msg->address_lo = lower_32_bits(msi_data->msiir_addr + 4 * data->hwirq);
	msg->data = data->hwirq;

	iommu_dma_compose_msi_msg(irq_data_get_msi_desc(data), msg);
}

static int imx_mu_msi_set_affinity(struct irq_data *irq_data,
				   const struct cpumask *mask, bool force)

{
	return IRQ_SET_MASK_OK;
}

static struct irq_chip imx_mu_msi_parent_chip = {
	.name			= "MU",
	.irq_compose_msi_msg	= imx_mu_msi_compose_msg,
	.irq_set_affinity = imx_mu_msi_set_affinity,
};

static int imx_mu_msi_domain_irq_alloc(struct irq_domain *domain,
					unsigned int virq,
					unsigned int nr_irqs,
					void *args)
{
	struct imx_mu_msi *msi_data = domain->host_data;
	msi_alloc_info_t *info = args;
	int pos, err = 0;

	pm_runtime_get_sync(&msi_data->pdev->dev);

	WARN_ON(nr_irqs != 1);

	spin_lock(&msi_data->lock);
	pos = find_first_zero_bit(&msi_data->used, msi_data->irqs_num);
	if (pos < msi_data->irqs_num)
		__set_bit(pos, &msi_data->used);
	else
		err = -ENOSPC;
	spin_unlock(&msi_data->lock);

	if (err)
		return err;

	err = iommu_dma_prepare_msi(info->desc, msi_data->msiir_addr + pos * 4);
	if (err)
		return err;

	irq_domain_set_info(domain, virq, pos,
			    &imx_mu_msi_parent_chip, msi_data,
			    handle_simple_irq, NULL, NULL);
	return 0;
}

static void imx_mu_msi_domain_irq_free(struct irq_domain *domain,
				       unsigned int virq, unsigned int nr_irqs)
{
	struct irq_data *d = irq_domain_get_irq_data(domain, virq);
	struct imx_mu_msi *msi_data = irq_data_get_irq_chip_data(d);
	int pos;

	pos = d->hwirq;
	if (pos < 0 || pos >= msi_data->irqs_num) {
		pr_err("failed to teardown msi. Invalid hwirq %d\n", pos);
		return;
	}

	spin_lock(&msi_data->lock);
	__clear_bit(pos, &msi_data->used);
	spin_unlock(&msi_data->lock);

	pm_runtime_put(&msi_data->pdev->dev);
}

static const struct irq_domain_ops imx_mu_msi_domain_ops = {
	.alloc	= imx_mu_msi_domain_irq_alloc,
	.free	= imx_mu_msi_domain_irq_free,
};

static void imx_mu_msi_irq_handler(struct irq_desc *desc)
{
	struct imx_mu_msi *msi_data = irq_desc_get_handler_data(desc);
	u32 status;
	int i;

	status = imx_mu_read(msi_data, msi_data->cfg->xSR[IMX_MU_RSR]);

	chained_irq_enter(irq_desc_get_chip(desc), desc);
	for (i = 0; i < IMX_MU_CHANS; i++) {
		if (status & IMX_MU_xSR_RFn(msi_data->cfg->type, i)) {
			imx_mu_read(msi_data, msi_data->cfg->xRR + i * 4);
			generic_handle_domain_irq(msi_data->parent, i);
		}
	}
	chained_irq_exit(irq_desc_get_chip(desc), desc);
}

static int imx_mu_msi_domains_init(struct imx_mu_msi *msi_data)
{
	/* Initialize MSI domain parent */
	msi_data->parent = irq_domain_add_linear(NULL,
						 msi_data->irqs_num,
						 &imx_mu_msi_domain_ops,
						 msi_data);
	if (!msi_data->parent) {
		dev_err(&msi_data->pdev->dev, "failed to create IRQ domain\n");
		return -ENOMEM;
	}

	msi_data->msi_domain = platform_msi_create_irq_domain(
				of_node_to_fwnode(msi_data->pdev->dev.of_node),
				&imx_mu_msi_domain_info,
				msi_data->parent);

	if (!msi_data->msi_domain) {
		dev_err(&msi_data->pdev->dev, "failed to create MSI domain\n");
		irq_domain_remove(msi_data->parent);
		return -ENOMEM;
	}

	return 0;
}

static int imx_mu_msi_teardown_hwirq(struct imx_mu_msi *msi_data)
{
	if (msi_data->gic_irq > 0)
		irq_set_chained_handler_and_data(msi_data->gic_irq, NULL, NULL);

	return 0;
}

static const struct imx_mu_dcfg imx_mu_cfg_imx6sx = {
	.xTR    = 0x0,
	.xRR    = 0x10,
	.xSR    = {0x20, 0x20, 0x20, 0x20},
	.xCR    = {0x24, 0x24, 0x24, 0x24},
};

static const struct imx_mu_dcfg imx_mu_cfg_imx7ulp = {
	.xTR    = 0x20,
	.xRR    = 0x40,
	.xSR    = {0x60, 0x60, 0x60, 0x60},
	.xCR    = {0x64, 0x64, 0x64, 0x64},
};

static const struct imx_mu_dcfg imx_mu_cfg_imx8ulp = {
	.type   = IMX_MU_V2,
	.xTR    = 0x200,
	.xRR    = 0x280,
	.xSR    = {0xC, 0x118, 0x124, 0x12C},
	.xCR    = {0x110, 0x114, 0x120, 0x128},
};

static const struct imx_mu_dcfg imx_mu_cfg_imx8ulp_s4 = {
	.type   = IMX_MU_V2 | IMX_MU_V2_S4,
	.xTR    = 0x200,
	.xRR    = 0x280,
	.xSR    = {0xC, 0x118, 0x124, 0x12C},
	.xCR    = {0x110, 0x114, 0x120, 0x128},
};

static const struct of_device_id imx_mu_msi_ids[] = {
	{ .compatible = "fsl,imx7ulp-mu-msi", .data = &imx_mu_cfg_imx7ulp },
	{ .compatible = "fsl,imx6sx-mu-msi", .data = &imx_mu_cfg_imx6sx },
	{ .compatible = "fsl,imx8ulp-mu-msi", .data = &imx_mu_cfg_imx8ulp },
	{ .compatible = "fsl,imx8ulp-mu-msi-s4", .data = &imx_mu_cfg_imx8ulp_s4 },
	{ },
};

MODULE_DEVICE_TABLE(of, imx_mu_msi_ids);

static int imx_mu_msi_probe(struct platform_device *pdev)
{
	const struct of_device_id *match;
	struct imx_mu_msi *msi_data, *priv;
	struct device *dev = &pdev->dev;
	struct resource *res;
	int ret;

	match = of_match_device(imx_mu_msi_ids, &pdev->dev);
	if (!match)
		return -ENODEV;

	priv = msi_data = devm_kzalloc(&pdev->dev, sizeof(*msi_data), GFP_KERNEL);
	if (!msi_data)
		return -ENOMEM;

	msi_data->cfg = (struct imx_mu_dcfg *) match->data;

	msi_data->regs = devm_platform_ioremap_resource_byname(pdev, "a");
	if (IS_ERR(msi_data->regs)) {
		dev_err(&pdev->dev, "failed to initialize 'regs'\n");
		return PTR_ERR(msi_data->regs);
	}

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "b");
	if (!res)
		return -EIO;

	msi_data->msiir_addr = res->start + msi_data->cfg->xTR;

	msi_data->pdev = pdev;
	msi_data->irqs_num = IMX_MU_CHANS;

	msi_data->gic_irq = platform_get_irq(msi_data->pdev, 0);
	if (msi_data->gic_irq <= 0)
		return -ENODEV;

	platform_set_drvdata(pdev, msi_data);

	msi_data->clk = devm_clk_get(dev, NULL);
	if (IS_ERR(msi_data->clk)) {
		if (PTR_ERR(msi_data->clk) != -ENOENT)
			return PTR_ERR(msi_data->clk);

		msi_data->clk = NULL;
	}

	ret = clk_prepare_enable(msi_data->clk);
	if (ret) {
		dev_err(dev, "Failed to enable clock\n");
		return ret;
	}

	priv->pd_a = dev_pm_domain_attach_by_name(dev, "a");
	if (IS_ERR(priv->pd_a))
		return PTR_ERR(priv->pd_a);

	priv->pd_link_a = device_link_add(dev, priv->pd_a,
			DL_FLAG_STATELESS |
			DL_FLAG_PM_RUNTIME |
			DL_FLAG_RPM_ACTIVE);

	if (!priv->pd_link_a) {
		dev_err(dev, "Failed to add device_link to mu a.\n");
		return -EINVAL;
	}

	priv->pd_b = dev_pm_domain_attach_by_name(dev, "b");
	if (IS_ERR(priv->pd_b))
		return PTR_ERR(priv->pd_b);

	priv->pd_link_b = device_link_add(dev, priv->pd_b,
			DL_FLAG_STATELESS |
			DL_FLAG_PM_RUNTIME |
			DL_FLAG_RPM_ACTIVE);

	if (!priv->pd_link_b) {
		dev_err(dev, "Failed to add device_link to mu a.\n");
		return -EINVAL;
	}

	ret = imx_mu_msi_domains_init(msi_data);
	if (ret)
		return ret;

	irq_set_chained_handler_and_data(msi_data->gic_irq,
					 imx_mu_msi_irq_handler,
					 msi_data);

	pm_runtime_enable(dev);

	ret = pm_runtime_get_sync(dev);
	if (ret < 0) {
		pm_runtime_put_noidle(dev);
		goto disable_runtime_pm;
	}

	ret = pm_runtime_put_sync(dev);
	if (ret < 0)
		goto disable_runtime_pm;

	clk_disable_unprepare(msi_data->clk);

	return 0;

disable_runtime_pm:
	pm_runtime_disable(dev);
	clk_disable_unprepare(msi_data->clk);

	return ret;
}

static int __maybe_unused imx_mu_runtime_suspend(struct device *dev)
{
	struct imx_mu_msi *priv = dev_get_drvdata(dev);

	clk_disable_unprepare(priv->clk);

	return 0;
}

static int __maybe_unused imx_mu_runtime_resume(struct device *dev)
{
	struct imx_mu_msi *priv = dev_get_drvdata(dev);
	int ret;

	ret = clk_prepare_enable(priv->clk);
	if (ret)
		dev_err(dev, "failed to enable clock\n");

	return ret;
}

static const struct dev_pm_ops imx_mu_pm_ops = {
	SET_RUNTIME_PM_OPS(imx_mu_runtime_suspend,
			   imx_mu_runtime_resume, NULL)
};

static int imx_mu_msi_remove(struct platform_device *pdev)
{
	struct imx_mu_msi *msi_data = platform_get_drvdata(pdev);

	imx_mu_msi_teardown_hwirq(msi_data);

	irq_domain_remove(msi_data->msi_domain);
	irq_domain_remove(msi_data->parent);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

static struct platform_driver imx_mu_msi_driver = {
	.driver = {
		.name = "imx-mu-msi",
		.of_match_table = imx_mu_msi_ids,
		.pm = &imx_mu_pm_ops,
	},
	.probe = imx_mu_msi_probe,
	.remove = imx_mu_msi_remove,
};

module_platform_driver(imx_mu_msi_driver);

MODULE_AUTHOR("Frank Li <Frank.Li@nxp.com>");
MODULE_DESCRIPTION("Freescale Layerscape SCFG MSI controller driver");
MODULE_LICENSE("GPL");
