/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/security_router.h>
#include <cdk2/tcg2_entry.h>
#include <cdk2/tcg2_service.h>
#include <industry_standard/tpm2_acpi.h>

#define EVT_NOTIFY_SIGNAL 0x00000200U
#define EVT_SIGNAL_EXIT_BOOT_SERVICES 0x00000201U
#define TPL_CALLBACK 8U
#define TPM_BASE 0xfed40000ULL
#define TPM_INTF_CAPABILITY 0x14U
#define TPM_INTF_ID 0x30U
#define LOG_CAPACITY (64U * 1024U)

typedef EFI_STATUS CDK2_MS_ABI allocate_pages_fn(UINT32, EFI_MEMORY_TYPE,
	UINTN, EFI_PHYSICAL_ADDRESS *);
typedef EFI_STATUS CDK2_MS_ABI free_pages_fn(EFI_PHYSICAL_ADDRESS, UINTN);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(EFI_MEMORY_TYPE, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI register_protocol_notify_fn(
	const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_config_fn(const EFI_GUID *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI stall_fn(UINTN);
typedef EFI_STATUS CDK2_MS_ABI get_variable_fn(const CHAR16 *, const EFI_GUID *,
	UINT32 *, UINTN *, void *);

struct boot_services_view {
	UINT8 header[40];
	allocate_pages_fn *allocate_pages;
	free_pages_fn *free_pages;
	UINT8 before_allocate_pool[8];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	create_event_fn *create_event;
	UINT8 before_close_event[24];
	close_event_fn *close_event;
	UINT8 before_register_protocol_notify[48];
	register_protocol_notify_fn *register_protocol_notify;
	UINT8 before_install_config[16];
	install_config_fn *install_configuration_table;
	UINT8 before_stall[48];
	stall_fn *stall;
	UINT8 before_locate_protocol[64];
	locate_protocol_fn *locate_protocol;
	install_multiple_fn *install_multiple;
};

struct runtime_services_view {
	UINT8 before_get_variable[72];
	get_variable_fn *get_variable;
};

struct config_table { EFI_GUID guid; void *table; };
struct system_table_view {
	UINT8 before_runtime[88];
	struct runtime_services_view *runtime;
	struct boot_services_view *boot;
	UINTN table_count;
	struct config_table *tables;
};

typedef char allocate_pages_offset_check[
	OFFSET_OF(struct boot_services_view, allocate_pages) == 40 ? 1 : -1];
typedef char free_pages_offset_check[
	OFFSET_OF(struct boot_services_view, free_pages) == 48 ? 1 : -1];
typedef char close_event_offset_check[
	OFFSET_OF(struct boot_services_view, close_event) == 112 ? 1 : -1];
typedef char install_config_offset_check[
	OFFSET_OF(struct boot_services_view, install_configuration_table) == 192 ? 1 : -1];
typedef char locate_protocol_offset_check[
	OFFSET_OF(struct boot_services_view, locate_protocol) == 320 ? 1 : -1];

static const EFI_GUID variable_write_arch_guid = {
	0x6441f818, 0x6362, 0x4e44,
	{ 0xb5, 0x70, 0x7d, 0xba, 0x31, 0xdd, 0x24, 0x53 }
};
static const EFI_GUID security_router_guid = {
	0x3159cc63, 0x8e41, 0x4cb8,
	{ 0x86, 0x02, 0x9e, 0x3c, 0x63, 0x22, 0x44, 0x31 }
};
static const EFI_GUID acpi20_table_guid = {
	0x8868e871, 0xe4f1, 0x11d3,
	{ 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 }
};
static const EFI_GUID global_variable_guid = {
	0x8be4df61, 0x93ca, 0x11d2,
	{ 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c }
};
static const EFI_GUID image_security_database_guid = {
	0xd719b2cb, 0x3d3a, 0x4596,
	{ 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f }
};
static const CHAR16 secure_boot[] = { 'S', 'e', 'c', 'u', 'r', 'e', 'B', 'o', 'o', 't', 0 };
static const CHAR16 pk[] = { 'P', 'K', 0 };
static const CHAR16 kek[] = { 'K', 'E', 'K', 0 };
static const CHAR16 db[] = { 'd', 'b', 0 };
static const CHAR16 dbx[] = { 'd', 'b', 'x', 0 };

static struct cdk2_tcg2_service service;
static struct boot_services_view *boot_services;
static struct runtime_services_view *runtime_services;
static struct cdk2_security_router *security_router;
static void *protocol_handle;
static struct cdk2_tpm2_io tpm_io;

static EFI_STATUS CDK2_MS_ABI measure_image(const void *file,
	const void *file_buffer, UINTN file_size, BOOLEAN boot_policy, void *context);
static void CDK2_MS_ABI variable_write_ready(void *event, void *context);
static void CDK2_MS_ABI exit_boot_services(void *event, void *context);

static BOOLEAN guid_equal(const EFI_GUID *left, const EFI_GUID *right)
{
	const UINT8 *a = (const UINT8 *)left;
	const UINT8 *b = (const UINT8 *)right;
	UINTN index;
	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}

static UINT64 find_tpm_base(const struct system_table_view *system)
{
	const EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *rsdp = NULL;
	const EFI_ACPI_DESCRIPTION_HEADER *xsdt;
	const EFI_ACPI_DESCRIPTION_HEADER *header;
	const EFI_TPM2_ACPI_TABLE *tpm2;
	const UINT64 *entries;
	UINTN count;
	UINTN index;

	for (index = 0; index < system->table_count; index++)
		if (guid_equal(&system->tables[index].guid, &acpi20_table_guid))
			rsdp = system->tables[index].table;
	if (rsdp == NULL || rsdp->signature !=
	    EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE ||
	    rsdp->xsdt_address == 0)
		return 0;
	xsdt = (const void *)(UINTN)rsdp->xsdt_address;
	if (xsdt->signature != EFI_ACPI_3_0_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE ||
	    xsdt->length < sizeof(*xsdt))
		return 0;
	entries = (const UINT64 *)(xsdt + 1);
	count = (xsdt->length - sizeof(*xsdt)) / sizeof(*entries);
	for (index = 0; index < count; index++) {
		header = (const void *)(UINTN)entries[index];
		if (header->signature != SIGNATURE_32('T', 'P', 'M', '2') ||
		    header->length < sizeof(*tpm2))
			continue;
		tpm2 = (const EFI_TPM2_ACPI_TABLE *)header;
		if (tpm2->start_method == 6)
			return TPM_BASE;
		if (tpm2->address_of_control_area >= 0x40)
			return tpm2->address_of_control_area - 0x40;
	}
	return 0;
}

static UINT8 mmio_read8(void *context, UINT64 address)
{
	(void)context;
	return *(volatile UINT8 *)(UINTN)address;
}

static UINT32 mmio_read32(void *context, UINT64 address)
{
	(void)context;
	return *(volatile UINT32 *)(UINTN)address;
}

static UINT64 mmio_read64(void *context, UINT64 address)
{
	(void)context;
	return *(volatile UINT64 *)(UINTN)address;
}

static void mmio_write8(void *context, UINT64 address, UINT8 value)
{
	(void)context;
	*(volatile UINT8 *)(UINTN)address = value;
}

static void mmio_write32(void *context, UINT64 address, UINT32 value)
{
	(void)context;
	*(volatile UINT32 *)(UINTN)address = value;
}

static void mmio_write64(void *context, UINT64 address, UINT64 value)
{
	(void)context;
	*(volatile UINT64 *)(UINTN)address = value;
}

static void tpm_stall(void *context, UINT32 microseconds)
{
	(void)context;
	boot_services->stall(microseconds);
}

static EFI_STATUS allocate_log(void *context, EFI_MEMORY_TYPE type, UINT32 size,
	void **buffer, cdk2_physical_address_ptr address)
{
	EFI_STATUS status;
	(void)context;
	*address = 0;
	status = boot_services->allocate_pages(0, type,
		(size + 4095U) / 4096U, address);
	if (!EFI_ERROR(status))
		*buffer = (void *)(UINTN)*address;
	return status;
}

static EFI_STATUS free_log(void *context, EFI_PHYSICAL_ADDRESS address, UINT32 size)
{
	(void)context;
	return boot_services->free_pages(address, (size + 4095U) / 4096U);
}

static EFI_STATUS install_protocol(void *context, cdk2_const_guid_ptr guid,
	void *interface)
{
	(void)context;
	return boot_services->install_multiple(&protocol_handle, guid, interface, NULL);
}

static EFI_STATUS install_config(void *context, cdk2_const_guid_ptr guid,
	void *table)
{
	(void)context;
	return boot_services->install_configuration_table(guid, table);
}

static EFI_STATUS register_security(void *context)
{
	(void)context;
	return security_router->register_handler(measure_image, NULL);
}

static EFI_STATUS unregister_security(void *context)
{
	(void)context;
	return security_router->unregister_handler(measure_image, NULL);
}

static EFI_STATUS create_variable_event(void *context, void **event)
{
	(void)context;
	return boot_services->create_event(EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
		variable_write_ready, NULL, event);
}

static EFI_STATUS register_variable_notify(void *context, void *event)
{
	void *registration;
	(void)context;
	return boot_services->register_protocol_notify(&variable_write_arch_guid,
		event, &registration);
}

static EFI_STATUS create_exit_event(void *context, void **event)
{
	(void)context;
	return boot_services->create_event(EVT_SIGNAL_EXIT_BOOT_SERVICES,
		TPL_CALLBACK, exit_boot_services, NULL, event);
}

static EFI_STATUS close_event(void *context, void *event)
{
	(void)context;
	return boot_services->close_event(event);
}

static void release_service(void *context, struct cdk2_tcg2_service *instance)
{
	(void)context;
	cdk2_tcg2_service_release(instance);
}

static const struct cdk2_tcg2_entry_ops entry_ops = {
	.register_security = register_security,
	.unregister_security = unregister_security,
	.create_variable_event = create_variable_event,
	.register_variable_notify = register_variable_notify,
	.create_exit_event = create_exit_event,
	.close_event = close_event,
	.install_config = install_config,
	.install_protocol = install_protocol,
	.release_service = release_service,
};

static EFI_STATUS CDK2_MS_ABI measure_image(const void *file,
	const void *file_buffer, UINTN file_size, BOOLEAN boot_policy, void *context)
{
	struct image_event {
		UINT64 image_location;
		UINT64 image_length;
		UINT64 image_link_time;
		UINT64 device_path_length;
		UINT8 device_path[768];
	} event = {0};
	const UINT8 *node = file;
	UINT32 path_size = 0;
	UINT16 node_size;
	UINT32 index;
	UINT32 code;
	EFI_STATUS status;
	(void)context;
	if (file == NULL || file_buffer == NULL || file_size == 0 ||
	    file_size > MAX_UINT32)
		return EFI_SUCCESS;
	do {
		if (path_size + 4 > sizeof(event.device_path))
			return EFI_SUCCESS;
		node_size = (UINT16)node[path_size + 2] |
			(UINT16)node[path_size + 3] << 8;
		if (node_size < 4 || node_size > sizeof(event.device_path) - path_size)
			return EFI_SUCCESS;
		path_size += node_size;
	} while (node[path_size - node_size] != 0x7f);
	event.image_location = (UINT64)(UINTN)file_buffer;
	event.image_length = file_size;
	event.device_path_length = path_size;
	for (index = 0; index < path_size; index++)
		event.device_path[index] = node[index];
	status = cdk2_tcg2_measure_image(&service, 4,
		boot_policy ? EV_EFI_BOOT_SERVICES_APPLICATION :
		EV_EFI_BOOT_SERVICES_DRIVER, file_buffer, (UINT32)file_size,
		&event, OFFSET_OF(struct image_event, device_path) + path_size, &code);
	/* A measurement failure must not become an image-authentication failure. */
	(void)status;
	return EFI_SUCCESS;
}

static void measure_variable(const CHAR16 *name, UINT32 name_bytes,
	const EFI_GUID *guid, UINT32 event_type)
{
	UINTN size = 0;
	void *data;
	UINT32 code;

	if (runtime_services->get_variable(name, guid, NULL, &size, NULL) !=
	    EFI_BUFFER_TOO_SMALL || size > MAX_UINT32)
		return;
	if (EFI_ERROR(boot_services->allocate_pool(efi_boot_services_data, size, &data)))
		return;
	if (!EFI_ERROR(runtime_services->get_variable(name, guid, NULL, &size, data)))
		cdk2_tcg2_measure_boot_variable(&service, 7, event_type, guid,
			name, name_bytes, data, (UINT32)size, &code);
	boot_services->free_pool(data);
}

static void CDK2_MS_ABI variable_write_ready(void *event, void *context)
{
	(void)event;
	(void)context;
	measure_variable(secure_boot, sizeof(secure_boot), &global_variable_guid,
		EV_EFI_VARIABLE_DRIVER_CONFIG);
	measure_variable(pk, sizeof(pk), &global_variable_guid,
		EV_EFI_VARIABLE_AUTHORITY);
	measure_variable(kek, sizeof(kek), &global_variable_guid,
		EV_EFI_VARIABLE_AUTHORITY);
	measure_variable(db, sizeof(db), &image_security_database_guid,
		EV_EFI_VARIABLE_AUTHORITY);
	measure_variable(dbx, sizeof(dbx), &image_security_database_guid,
		EV_EFI_VARIABLE_AUTHORITY);
}

static void CDK2_MS_ABI exit_boot_services(void *event, void *context)
{
	UINT32 code;
	(void)event;
	(void)context;
	cdk2_tcg2_exit_boot_services(&service, FALSE, FALSE, &code);
	cdk2_tcg2_exit_boot_services(&service, TRUE, TRUE, &code);
	security_router->unregister_handler(measure_image, NULL);
}

EFI_STATUS CDK2_MS_ABI cdk2_tcg2_entry(void *image,
	struct system_table_view *system)
{
	struct cdk2_tpm2_transport transport;
	enum cdk2_tpm2_interface interface;
	EFI_STATUS status;
	UINT64 tpm_base;

	(void)image;
	if (system == NULL || system->boot == NULL || system->runtime == NULL)
		return EFI_INVALID_PARAMETER;
	boot_services = system->boot;
	runtime_services = system->runtime;
	tpm_base = find_tpm_base(system);
	if (tpm_base == 0)
		return EFI_NOT_FOUND;
	interface = cdk2_tpm2_detect_interface(mmio_read32(NULL, tpm_base + TPM_INTF_ID),
		mmio_read32(NULL, tpm_base + TPM_INTF_CAPABILITY));
	if (interface == CDK2_TPM2_INTERFACE_INVALID &&
	    mmio_read8(NULL, tpm_base) != MAX_UINT8)
		interface = CDK2_TPM2_INTERFACE_TIS;
	if (interface == CDK2_TPM2_INTERFACE_INVALID)
		return EFI_NOT_FOUND;
	tpm_io = (struct cdk2_tpm2_io){ NULL, mmio_read8, mmio_read32, mmio_read64,
		mmio_write8, mmio_write32, mmio_write64, tpm_stall };
	transport = (struct cdk2_tpm2_transport){ interface, tpm_base, 2000000U, &tpm_io };
	status = cdk2_tcg2_service_init(&service, &transport, NULL, allocate_log, free_log,
		NULL, NULL, LOG_CAPACITY, LOG_CAPACITY);
	if (EFI_ERROR(status))
		return status;
	status = boot_services->locate_protocol(&security_router_guid, NULL,
		(void **)&security_router);
	if (EFI_ERROR(status)) {
		cdk2_tcg2_service_release(&service);
		return status;
	}
	return cdk2_tcg2_entry_publish(&service, NULL, &entry_ops);
}
