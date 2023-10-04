/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Landlock LSM - Network management and hooks
 *
 * Copyright © 2022-2023 Huawei Tech. Co., Ltd.
 */

#ifndef _SECURITY_LANDLOCK_NET_H
#define _SECURITY_LANDLOCK_NET_H

#include "common.h"
#include "ruleset.h"
#include "setup.h"

#if IS_ENABLED(CONFIG_INET)
__init void landlock_add_net_hooks(void);

int landlock_append_net_rule(struct landlock_ruleset *const ruleset,
			     const u16 port, access_mask_t access_rights);

int landlock_add_rule_net_service(struct landlock_ruleset *ruleset,
				  const void __user *const rule_attr);
#else /* IS_ENABLED(CONFIG_INET) */
static inline void landlock_add_net_hooks(void)
{
}

static inline int
landlock_add_rule_net_service(struct landlock_ruleset *ruleset,
			      const void __user *const rule_attr)
{
	return -EAFNOSUPPORT;
}
#endif /* IS_ENABLED(CONFIG_INET) */

#endif /* _SECURITY_LANDLOCK_NET_H */
