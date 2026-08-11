/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/terminal_driver.h>

#include <string.h>

struct boot_services_view {
	uint8_t before_create[80];
	cdk2_terminal_event_fn *create_event;
	uint8_t before_close_event[24];
	cdk2_terminal_close_event_fn *close_event;
	uint8_t before_open[160];
	cdk2_terminal_open_fn *open_protocol;
	cdk2_terminal_close_fn *close_protocol;
	uint8_t before_install[32];
	cdk2_terminal_install_fn *install_protocols;
	cdk2_terminal_uninstall_fn *uninstall_protocols;
};

struct table_header {
	uint64_t signature;
	uint32_t revision, header_size, crc32, reserved;
};
struct system_table_view {
	struct table_header header;
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct boot_services_view *boot;
};

struct driver_binding;
typedef uint64_t CDK2_MS_ABI binding_supported_fn(struct driver_binding *,
						  void *, void *);
typedef uint64_t CDK2_MS_ABI binding_stop_fn(struct driver_binding *, void *,
					     size_t, void **);
struct driver_binding {
	binding_supported_fn *supported;
	binding_supported_fn *start;
	binding_stop_fn *stop;
	uint32_t version, pad;
	void *image_handle, *binding_handle;
};

struct component_name;
typedef uint64_t CDK2_MS_ABI driver_name_fn(struct component_name *, char *,
					    uint16_t **);
typedef uint64_t CDK2_MS_ABI controller_name_fn(struct component_name *, void *,
						void *, char *, uint16_t **);
struct component_name {
	driver_name_fn *get_driver_name;
	controller_name_fn *get_controller_name;
	char *languages;
};

static const EFI_GUID driver_binding_guid = {
	0x18a031ab,
	0xb443,
	0x4d1a,
	{0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71}};
static const EFI_GUID component_name_guid = {
	0x107a772c,
	0xd5e1,
	0x11d4,
	{0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};
static const EFI_GUID component_name2_guid = {
	0x6a7a5cff,
	0xe8d9,
	0x4f70,
	{0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14}};

static struct cdk2_terminal_services services;
static struct cdk2_terminal_child children[8];
static struct driver_binding binding;
static void *driver_handle;
static uint16_t driver_name[] = {'T', 'e', 'r', 'm', 'i', 'n', 'a', 'l',
				 ' ', 'D', 'r', 'i', 'v', 'e', 'r', 0};
static uint16_t controller_name[] = {'S', 'e', 'r', 'i', 'a', 'l', ' ', 'T',
				     'e', 'r', 'm', 'i', 'n', 'a', 'l', 0};

static uint64_t CDK2_MS_ABI supported(struct driver_binding *self,
				      void *controller, void *remaining)
{
	(void)remaining;
	return cdk2_terminal_supported(&services, self->binding_handle,
				       controller);
}

static uint64_t CDK2_MS_ABI start(struct driver_binding *self, void *controller,
				  void *remaining)
{
	size_t i;
	(void)remaining;
	for (i = 0; i < ARRAY_SIZE(children); i++)
		if (!children[i].started)
			return cdk2_terminal_start(
				&children[i], &services, self->binding_handle,
				controller, CDK2_TERMINAL_VT_UTF8);
	return EFI_OUT_OF_RESOURCES;
}

static uint64_t CDK2_MS_ABI stop(struct driver_binding *self, void *controller,
				 size_t number_of_children,
				 void **child_handles)
{
	size_t i, stopped = 0;
	(void)self;
	for (i = 0; i < ARRAY_SIZE(children); i++) {
		if (!children[i].started ||
		    children[i].controller != controller)
			continue;
		if (number_of_children != 0 &&
		    (child_handles == NULL ||
		     children[i].handle != child_handles[0]))
			continue;
		if (cdk2_terminal_stop(&children[i]) != EFI_SUCCESS)
			return EFI_DEVICE_ERROR;
		stopped++;
		if (number_of_children != 0)
			break;
	}
	return stopped == 0 ? EFI_NOT_FOUND : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI get_driver_name(struct component_name *self,
					    char *language, uint16_t **name)
{
	(void)self;
	if (language == NULL || name == NULL || language[0] != 'e' ||
	    language[1] != 'n' ||
	    !((language[2] == '\0') ||
	      (language[2] == 'g' && language[3] == '\0')))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI get_controller_name(struct component_name *self,
						void *controller, void *child,
						char *language, uint16_t **name)
{
	size_t i;
	(void)self;
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	for (i = 0; i < ARRAY_SIZE(children); i++)
		if (children[i].started &&
		    children[i].controller == controller &&
		    (child == NULL || children[i].handle == child)) {
			*name = controller_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

static struct component_name name = {get_driver_name, get_controller_name,
				     "eng"};
static struct component_name name2 = {get_driver_name, get_controller_name,
				      "en"};

uint64_t CDK2_MS_ABI cdk2_terminal_driver_entry(void *image_handle,
						void *system_table)
{
	struct system_table_view *table = system_table;
	uint64_t status;

	if (table == NULL || table->boot == NULL)
		return EFI_INVALID_PARAMETER;
	services.open_protocol = table->boot->open_protocol;
	services.close_protocol = table->boot->close_protocol;
	services.install_protocols = table->boot->install_protocols;
	services.uninstall_protocols = table->boot->uninstall_protocols;
	services.create_event = table->boot->create_event;
	services.close_event = table->boot->close_event;
	binding = (struct driver_binding){
		supported, start, stop, 0xa, 0, image_handle, image_handle};
	driver_handle = image_handle;
	status = services.install_protocols(
		&driver_handle, &driver_binding_guid, &binding,
		&component_name_guid, &name, &component_name2_guid, &name2,
		NULL);
	return status;
}
