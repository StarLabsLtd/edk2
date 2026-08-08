/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_BINDING_H_
#define CDK2_CON_SPLITTER_BINDING_H_

#include <cdk2/con_splitter.h>

#define CDK2_CON_SPLITTER_OPEN_BY_DRIVER 0x10U
typedef EFI_STATUS cdk2_split_binding_open_fn(void *, void *, const EFI_GUID *,
	UINT32, void **);
typedef EFI_STATUS cdk2_split_binding_close_fn(void *, void *, const EFI_GUID *);
typedef EFI_STATUS cdk2_split_binding_device_fn(void *, void *);
struct cdk2_split_binding_ops {
	cdk2_split_binding_open_fn *open;
	cdk2_split_binding_close_fn *close;
	cdk2_split_binding_device_fn *admit;
	cdk2_split_binding_device_fn *remove;
};
struct cdk2_split_binding_instance {
	void *controller, *interface;
	BOOLEAN active;
};
struct cdk2_split_binding {
	const struct cdk2_split_binding_ops *ops;
	void *context;
	const EFI_GUID *protocol;
	struct cdk2_split_binding_instance instances[CDK2_CON_SPLITTER_MAX_INPUTS];
};
EFI_STATUS cdk2_split_binding_supported(struct cdk2_split_binding *binding,
	void *controller);
EFI_STATUS cdk2_split_binding_start(struct cdk2_split_binding *binding,
	void *controller);
EFI_STATUS cdk2_split_binding_stop(struct cdk2_split_binding *binding,
	void *controller);

#endif
