/*
 * NXP Wireless LAN device driver: PCIE and platform specific quirks
 *
 * This software file (the "File") is distributed by NXP
 * under the terms of the GNU General Public License Version 2, June 1991
 * (the "License").  You may use, redistribute and/or modify this File in
 * accordance with the terms and conditions of the License, a copy of which
 * is available by writing to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 * this warranty disclaimer.
 */

#include "pcie.h"

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
