/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/modules/sio_bus/entry.c"

static struct driver_binding *published;
static struct pci_io mock_pci;
static UINT8 parent_path[] = {0x7f, 0xff, 4, 0};
static int installs, relations, fail_allocate;
static int same_guid(const struct guid *a, const struct guid *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}
static EFI_STATUS CDK2_MS_ABI mock_allocate(UINT32 type, UINTN size,
					    void **buffer)
{
	(void)type;
	if (fail_allocate)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_free(void *buffer)
{
	free(buffer);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_open(void *handle,
					const struct guid *protocol,
					void **interface, void *agent,
					void *controller, UINT32 attributes)
{
	(void)handle;
	(void)agent;
	(void)controller;
	if (same_guid(protocol, &pci_io_guid)) {
		if (attributes == 0x08U)
			relations++;
		if (interface != NULL)
			*interface = &mock_pci;
	} else if (same_guid(protocol, &device_path_guid) && interface != NULL)
		*interface = parent_path;
	else
		return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_close(void *handle,
					 const struct guid *protocol,
					 void *agent, void *controller)
{
	(void)handle;
	(void)agent;
	(void)controller;
	if (same_guid(protocol, &pci_io_guid) && relations != 0)
		relations--;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_install(void **handle,
					   const struct guid *protocol,
					   void *interface, ...)
{
	if (same_guid(protocol, &driver_binding_guid))
		published = interface;
	else {
		*handle = (void *)(UINTN)(++installs);
	}
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_uninstall(void *handle,
					     const struct guid *protocol,
					     void *interface, ...)
{
	(void)handle;
	(void)protocol;
	(void)interface;
	installs--;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_read(struct pci_io *pci, UINT32 width,
					UINT32 offset, UINTN count,
					void *buffer)
{
	UINT8 *bytes = buffer;
	(void)pci;
	(void)width;
	(void)offset;
	(void)count;
	memset(bytes, 0, 64);
	bytes[0] = 0x86;
	bytes[1] = 0x80;
	bytes[4] = 3;
	bytes[0x0a] = 1;
	bytes[0x0b] = 6;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_location(struct pci_io *pci, UINTN * segment,
						    UINTN * bus_no,
						    UINTN * device,
						    UINTN * function)
{
	(void)pci;
	*segment = *bus_no = *device = *function = 0;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_attributes(struct pci_io *pci,
					      UINT32 operation,
						      UINT64 attributes,
						      UINT64 * result)
{
	(void)pci;
	(void)attributes;
	if (result != NULL)
		*result = operation == 4 ? CDK2_SIO_PCI_ISA_IO : 0x55U;
	return EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "sio entry: %s\n", message);
	return !condition;
}

int main(void)
{
	struct boot_services services = {0};
	struct system_table system = {{0}, &services};
	void *handles[3];
	int failures = 0;
	UINTN index;
	services.allocate_pool = mock_allocate;
	services.free_pool = mock_free;
	services.open_protocol = mock_open;
	services.close_protocol = mock_close;
	services.install_multiple = mock_install;
	services.uninstall_multiple = mock_uninstall;
	mock_pci.pci.read = mock_read;
	mock_pci.get_location = mock_location;
	mock_pci.attributes = mock_attributes;
	failures +=
		expect(cdk2_sio_bus_entry((void *)1, &system) == EFI_SUCCESS &&
			       published != NULL,
		       "DriverBinding publication");
	failures += expect(published->supported(published, (void *)2, NULL) ==
				   EFI_SUCCESS,
			   "PCI ISA controller discovery");
	failures += expect(published->start(published, (void *)2, NULL) ==
					   EFI_SUCCESS &&
				   installs == 3 && relations == 3,
			   "child protocol and relationship publication");
	for (index = 0; index < 3; index++)
		handles[index] = bus.children[index].handle;
	failures += expect(published->stop(published, (void *)2, 3, handles) ==
					   EFI_SUCCESS &&
				   published->stop(published, (void *)2, 0,
						   NULL) == EFI_SUCCESS &&
				   installs == 0 && relations == 0,
			   "reverse child and parent teardown");
	fail_allocate = 1;
	failures += expect(published->start(published, (void *)2, NULL) ==
					   EFI_OUT_OF_RESOURCES &&
				   !bus.pci_open && installs == 0,
			   "allocation failure rollback");
	return failures != 0;
}
