/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_OUTPUT_DRIVER_H_
#define CDK2_GRAPHICS_OUTPUT_DRIVER_H_

#include <cdk2/graphics_output.h>

struct cdk2_gop_mode {
	uint32_t max_mode, mode;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	size_t size_of_info;
	uint64_t framebuffer_base;
	size_t framebuffer_size;
};

struct cdk2_gop;
typedef uint64_t CDK2_MS_ABI
cdk2_gop_query_fn(struct cdk2_gop *, uint32_t, size_t *,
		  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **);
typedef uint64_t CDK2_MS_ABI cdk2_gop_set_fn(struct cdk2_gop *, uint32_t);
typedef uint64_t CDK2_MS_ABI cdk2_gop_blt_fn(struct cdk2_gop *,
					     struct cdk2_blt_pixel *,
					     enum cdk2_blt_operation, size_t,
					     size_t, size_t, size_t, size_t,
					     size_t, size_t);
struct cdk2_gop {
	cdk2_gop_query_fn *query_mode;
	cdk2_gop_set_fn *set_mode;
	cdk2_gop_blt_fn *blt;
	struct cdk2_gop_mode *mode;
};

struct cdk2_graphics_pci_info {
	uint16_t vendor_id, device_id, subsystem_vendor_id, subsystem_id;
	uint8_t revision_id, bar_index;
	uint64_t bar_base, bar_size;
};

struct cdk2_graphics_device_info {
	uint16_t vendor_id, device_id, subsystem_vendor_id, subsystem_id;
	uint8_t revision_id, bar_index;
};

typedef uint64_t CDK2_MS_ABI cdk2_graphics_open_fn(void *, const EFI_GUID *,
						   void **, void *, void *,
						   uint32_t);
typedef uint64_t CDK2_MS_ABI cdk2_graphics_close_fn(void *, const EFI_GUID *,
						    void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_graphics_install_fn(void **, const EFI_GUID *,
						      void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_graphics_uninstall_fn(void *,
							const EFI_GUID *,
							void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_graphics_event_fn(uint32_t, size_t, void *,
						    void *, const EFI_GUID *,
						    void **);
typedef uint64_t CDK2_MS_ABI cdk2_graphics_close_event_fn(void *);
typedef uint64_t CDK2_MS_ABI
cdk2_graphics_pci_info_fn(void *, struct cdk2_graphics_pci_info *);
typedef void *CDK2_MS_ABI cdk2_graphics_alloc_fn(size_t);
typedef void CDK2_MS_ABI cdk2_graphics_free_fn(void *);

struct cdk2_graphics_services {
	cdk2_graphics_open_fn *open;
	cdk2_graphics_close_fn *close;
	cdk2_graphics_install_fn *install;
	cdk2_graphics_uninstall_fn *uninstall;
	cdk2_graphics_event_fn *create_event_ex;
	cdk2_graphics_close_event_fn *close_event;
	cdk2_graphics_pci_info_fn *pci_info;
	cdk2_graphics_alloc_fn *allocate;
	cdk2_graphics_free_fn *free;
};

struct cdk2_graphics_adr_path {
	uint8_t type, subtype;
	uint16_t length;
	uint32_t adr;
	uint8_t end_type, end_subtype;
	uint16_t end_length;
};

struct cdk2_graphics_child {
	struct cdk2_graphics_output graphics;
	struct cdk2_gop gop;
	struct cdk2_gop_mode mode;
	struct cdk2_graphics_adr_path path;
	struct cdk2_graphics_services *services;
	void *controller, *driver, *handle, *ready_event, *pci;
	uint8_t started;
};

uint64_t
cdk2_graphics_supported(struct cdk2_graphics_services *services, void *driver,
			void *controller,
			const struct cdk2_graphics_device_info *expected);
uint64_t cdk2_graphics_start(struct cdk2_graphics_child *child,
			     struct cdk2_graphics_services *services,
			     void *driver, void *controller,
			     const EFI_PEI_GRAPHICS_INFO_HOB *hob,
			     const struct cdk2_graphics_device_info *expected);
uint64_t cdk2_graphics_stop(struct cdk2_graphics_child *child);
void CDK2_MS_ABI cdk2_graphics_ready_to_boot(void *event, void *context);

#endif
