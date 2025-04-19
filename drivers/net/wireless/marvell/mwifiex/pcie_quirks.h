/* SPDX-License-Identifier: GPL-2.0-only */
/* NXP Wireless LAN device driver: PCIE and platform specific quirks */

#include "pcie.h"

#define QUIRK_FW_RST_D3COLD	BIT(0)
#define QUIRK_DO_FLR_ON_BRIDGE	BIT(1)
#define QUIRK_NO_BRIDGE_D3	BIT(2)

void mwifiex_initialize_quirks(struct pcie_service_card *card);
int mwifiex_pcie_reset_d3cold_quirk(struct pci_dev *pdev);
