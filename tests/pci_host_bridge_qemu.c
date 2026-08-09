/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>
#include <cdk2/pcd.h>

struct table_header { UINT64 signature; UINT32 revision, size, crc, reserved; };
struct system_table_view {
	struct table_header header;
	UINT16 *vendor;
	UINT32 revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
	UINTN table_count;
	void *tables;
};

struct resource_protocol_view {
	void *notify;
	EFI_STATUS (CDK2_MS_ABI *next)(void *, void **);
};

#pragma pack(push, 1)
struct root_path_view {
	UINT8 type, subtype;
	UINT16 length;
	UINT32 hid, uid;
	UINT8 end_type, end_subtype;
	UINT16 end_length;
};
#pragma pack(pop)

static const EFI_GUID resource_protocol_guid = {
	0xcf8034be, 0x6768, 0x4d8b, { 0xb7, 0x39, 0x7c, 0xce, 0x68, 0x3a, 0x9f, 0xbe }
};
static const EFI_GUID root_io_protocol_guid = {
	0x2f707ebb, 0x4a1a, 0x11d4, { 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID device_path_protocol_guid = {
	0x09576e91, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};

static UINT8 port_read(UINT16 port)
{
	UINT8 value;

	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void serial_write(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++),
			"Nd"((UINT16)0x3f8));
	}
}

EFI_STATUS CDK2_MS_ABI pci_host_bridge_qemu_entry(void *image, void *table)
{
	struct system_table_view *system = table;
	struct resource_protocol_view *host = NULL;
	struct cdk2_pci_root_io *root_io;
	struct root_path_view *path;
	void *root = NULL, *configuration;
	uint64_t supports, attributes, pci_address = 0;
	UINT16 vendor;
	UINTN descriptors;
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot == NULL ||
	    system->boot->locate_protocol == NULL || system->boot->handle_protocol == NULL)
		goto bad;
	status = system->boot->locate_protocol(&resource_protocol_guid, NULL,
		(void **)&host);
	if (EFI_ERROR(status) || host == NULL || host->next == NULL)
		goto bad;
	status = host->next(host, &root);
	if (EFI_ERROR(status) || root == NULL)
		goto bad;
	status = system->boot->handle_protocol(root, &root_io_protocol_guid,
		(void **)&root_io);
	if (EFI_ERROR(status) || root_io == NULL || root_io->pci.read == NULL ||
	    root_io->get_attributes == NULL || root_io->configuration == NULL)
		goto bad;
	status = system->boot->handle_protocol(root, &device_path_protocol_guid,
		(void **)&path);
	if (EFI_ERROR(status) || path == NULL || path->type != 2 || path->subtype != 1 ||
	    path->length != 12 || path->end_type != 0x7f || path->end_subtype != 0xff ||
	    path->end_length != 4)
		goto bad;
	serial_write("CDK2_PCI_HOST_BRIDGE_PROTOCOLS_OK\r\n");
	status = root_io->get_attributes(root_io, &supports, &attributes);
	if (EFI_ERROR(status) || (attributes & ~supports) != 0)
		goto bad;
	serial_write("CDK2_PCI_HOST_BRIDGE_ATTRIBUTES_OK\r\n");
	status = root_io->configuration(root_io, &configuration);
	if (EFI_ERROR(status) || configuration == NULL)
		goto bad;
	for (descriptors = 0; descriptors <= CDK2_PCI_ROOT_BRIDGE_APERTURES;
	     descriptors++) {
		UINT8 descriptor = *((UINT8 *)configuration + descriptors * 46U);

		if (descriptor == 0x79)
			break;
		if (descriptor != 0x8a)
			goto bad;
	}
	if (descriptors == 0 || descriptors > CDK2_PCI_ROOT_BRIDGE_APERTURES)
		goto bad;
	serial_write("CDK2_PCI_HOST_BRIDGE_CONFIGURATION_OK\r\n");
	status = root_io->pci.read(root_io, CDK2_PCI_UINT16, pci_address, 1, &vendor);
	if (EFI_ERROR(status) || vendor != 0x8086U)
		goto bad;
	serial_write("CDK2_PCI_HOST_BRIDGE_PCI_CONFIG_OK\r\n");
	serial_write("CDK2_PCI_HOST_BRIDGE_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	serial_write("CDK2_PCI_HOST_BRIDGE_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
