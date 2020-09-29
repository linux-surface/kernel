/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for PCIe quirks.
 */

#include "pcie.h"

/* quirks */
#define QUIRK_FW_RST_D3COLD	BIT(0)

void mwifiex_initialize_quirks(struct pcie_service_card *card);
int mwifiex_pcie_reset_d3cold_quirk(struct pci_dev *pdev);
