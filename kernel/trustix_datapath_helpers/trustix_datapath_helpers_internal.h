/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TRUSTIX_DATAPATH_HELPERS_INTERNAL_H
#define TRUSTIX_DATAPATH_HELPERS_INTERNAL_H

#include <linux/types.h>

int trustix_datapath_helpers_register(void);
void trustix_datapath_helpers_unregister(void);
void trustix_datapath_helpers_disable_panic_risk_params(void);
__u64 trustix_datapath_helpers_feature_mask(void);

#endif /* TRUSTIX_DATAPATH_HELPERS_INTERNAL_H */
