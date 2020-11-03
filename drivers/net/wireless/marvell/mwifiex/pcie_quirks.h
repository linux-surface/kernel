/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Header file for PCIe quirks.
 */

#include "pcie.h"

/* quirks */
#define QUIRK_FW_RST_D3COLD	BIT(0)
/* Surface 3 and Surface Pro 3 have the same _DSM method but need to
 * be handled differently. Currently, only S3 is supported.
 */
#define QUIRK_FW_RST_WSID_S3	BIT(1)
#define QUIRK_NO_BRIDGE_D3	BIT(2)
#define QUIRK_DO_FLR_ON_BRIDGE	BIT(3)

void mwifiex_initialize_quirks(struct pcie_service_card *card);
int mwifiex_pcie_reset_d3cold_quirk(struct pci_dev *pdev);
int mwifiex_pcie_reset_wsid_quirk(struct pci_dev *pdev);
