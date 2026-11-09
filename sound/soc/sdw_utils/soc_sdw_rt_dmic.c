// SPDX-License-Identifier: GPL-2.0-only
// This file incorporates work covered by the following copyright notice:
// Copyright (c) 2024 Intel Corporation
// Copyright (c) 2024 Advanced Micro Devices, Inc.

/*
 * soc_sdw_rt_dmic - Helpers to handle Realtek SDW DMIC from generic machine driver
 */

#include <linux/device.h>
#include <linux/errno.h>
#include <sound/soc.h>
#include <sound/soc-acpi.h>
#include <sound/soc_sdw_utils.h>

int asoc_sdw_rt_dmic_rtd_init(struct snd_soc_pcm_runtime *rtd, struct snd_soc_dai *dai)
{
	struct snd_soc_card *card = rtd->card;
	struct snd_soc_component *component;
	char *mic_name;

	component = dai->component;

	/*
	 * Some codecs use a different name in card->components than
	 * component->name_prefix.
	 * rt715-sdca (aka rt714) is one such case.
	 * rt1320-1 is another: the SDCA mic function on a single RT1320
	 * uses name_prefix "rt1320-1" (instance suffix), but UCM expects
	 * "rt1320-dmic" following the naming convention for standalone mic
	 * functions (rt712-dmic, rt713-dmic).
	 */
	if (!strcmp(component->name_prefix, "rt714"))
		mic_name = devm_kasprintf(card->dev, GFP_KERNEL, "rt715-sdca");
	else if (!strcmp(component->name_prefix, "rt1320-1"))
		mic_name = devm_kasprintf(card->dev, GFP_KERNEL, "rt1320-dmic");
	else
		mic_name = devm_kasprintf(card->dev, GFP_KERNEL, "%s", component->name_prefix);
	if (!mic_name)
		return -ENOMEM;

	card->components = devm_kasprintf(card->dev, GFP_KERNEL,
					  "%s mic:%s", card->components,
					  mic_name);
	if (!card->components)
		return -ENOMEM;

	dev_dbg(card->dev, "card->components: %s\n", card->components);

	return 0;
}
EXPORT_SYMBOL_NS(asoc_sdw_rt_dmic_rtd_init, "SND_SOC_SDW_UTILS");
