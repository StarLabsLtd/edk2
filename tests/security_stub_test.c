/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../src/modules/security_stub/security_stub.c"

static unsigned int install_calls;
static const struct efi_guid *installed_security2_guid;
static const struct efi_guid *installed_security_guid;
static void *installed_security2;
static void *installed_security;
static const struct efi_guid *installed_router_guid;
static void *installed_router;
static unsigned int routed_calls;

static efi_status_t CDK2_MS_ABI mock_install(efi_handle_t *handle,
					const struct efi_guid *first_guid,
					void *first_interface, ...)
{
	__builtin_ms_va_list arguments;

	(void)handle;
	__builtin_ms_va_start(arguments, first_interface);
	installed_security2_guid = first_guid;
	installed_security2 = first_interface;
	installed_security_guid = __builtin_va_arg(arguments, const struct efi_guid *);
	installed_security = __builtin_va_arg(arguments, void *);
	installed_router_guid = __builtin_va_arg(arguments, const struct efi_guid *);
	installed_router = __builtin_va_arg(arguments, void *);
	__builtin_ms_va_end(arguments);
	install_calls++;
	return 0x55;
}

static EFI_STATUS CDK2_MS_ABI routed(const void *file, const void *buffer,
	UINTN size, BOOLEAN boot_policy, void *context)
{
	(void)file;
	(void)buffer;
	(void)size;
	(void)boot_policy;
	(void)context;
	routed_calls++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (condition)
		return 0;
	fprintf(stderr, "security_stub_test: %s\n", message);
	return 1;
}

int main(void)
{
	struct boot_services_install_view boot_services;
	struct efi_system_table system_table;
	int failed = 0;

	memset(&boot_services, 0, sizeof(boot_services));
	memset(&system_table, 0, sizeof(system_table));
	failed |= expect(security_stub_initialize(NULL, NULL) == 2,
			 "NULL system table accepted");
	failed |= expect(security_stub_initialize(NULL, &system_table) == 2,
			 "NULL boot services accepted");
	system_table.boot_services = &boot_services;
	failed |= expect(security_stub_initialize(NULL, &system_table) == 3,
			 "missing installer accepted");
	boot_services.install_multiple = mock_install;
	failed |= expect(security_stub_initialize(NULL, &system_table) == 0x55,
			 "installer status not propagated");
	failed |= expect(install_calls == 1, "installer call count is wrong");
	failed |= expect(installed_security2_guid == &security2_guid &&
			 installed_security_guid == &security_guid,
			 "architectural protocol GUIDs are wrong");
	failed |= expect(installed_security2 == &security2 &&
			 installed_security == &security,
			 "architectural protocol interfaces are wrong");
	failed |= expect(installed_router_guid ==
			 (const struct efi_guid *)&cdk2_security_router_guid &&
			 installed_router == &router, "measurement router was not installed");
	failed |= expect(authenticate(NULL, 0, NULL) == EFI_SUCCESS,
			 "Security callback rejected empty policy");
	failed |= expect(authenticate2(NULL, NULL, NULL, 0, 0) == EFI_SUCCESS,
			 "Security2 callback rejected empty policy");
	failed |= expect(router.register_handler(routed, NULL) == EFI_SUCCESS &&
			 authenticate2(NULL, NULL, "image", 5, 1) == EFI_SUCCESS &&
			 routed_calls == 1 &&
			 router.unregister_handler(routed, NULL) == EFI_SUCCESS &&
			 authenticate2(NULL, NULL, "image", 5, 1) == EFI_SUCCESS &&
			 routed_calls == 1, "image measurement routing failed");
	return failed;
}
