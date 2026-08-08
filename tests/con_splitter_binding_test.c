/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_splitter_binding.h>
#include <stdio.h>

#define TEST_ACCESS_DENIED EFIERR(15)
#define TEST_WRITE_PROTECTED EFIERR(8)

static UINTN opens, closes, admits, removes;
static UINTN publishes, unpublishes, fail_publish;
static EFI_STATUS injected;
static EFI_STATUS open_protocol(void *context, void *controller,
	const EFI_GUID *protocol, UINT32 attributes, void **interface)
{
	(void)context; (void)protocol;
	if (controller == NULL || attributes != CDK2_CON_SPLITTER_OPEN_BY_DRIVER)
		return EFI_INVALID_PARAMETER;
	opens++; *interface = controller; return EFI_SUCCESS;
}
static EFI_STATUS close_protocol(void *context, void *controller,
	const EFI_GUID *protocol)
{
	(void)context; (void)controller; (void)protocol; closes++;
	return injected == TEST_ACCESS_DENIED ? injected : EFI_SUCCESS;
}
static EFI_STATUS admit(void *context, void *interface)
{
	(void)context; (void)interface; admits++;
	return injected == EFI_DEVICE_ERROR ? injected : EFI_SUCCESS;
}
static EFI_STATUS remove_device(void *context, void *interface)
{
	(void)context; (void)interface; removes++;
	return injected == TEST_WRITE_PROTECTED ? injected : EFI_SUCCESS;
}
static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "con splitter binding test: %s\n", message);
	return !condition;
}
static EFI_STATUS publish(void *context, void **handle, void *driver,
	void *component, void *component2)
{
	(void)context; (void)driver; (void)component; (void)component2;
	publishes++; *handle = (void *)publishes;
	return publishes == fail_publish ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS unpublish(void *context, void *handle, void *driver,
	void *component, void *component2)
{
	(void)context; (void)driver; (void)component; (void)component2;
	if (handle == NULL)
		return EFI_INVALID_PARAMETER;
	unpublishes++; return EFI_SUCCESS;
}

int main(void)
{
	static const EFI_GUID protocol = { 1U, 2U, 3U, { 4U } };
	static const struct cdk2_split_binding_ops ops = {
		open_protocol, close_protocol, admit, remove_device
	};
	struct cdk2_split_binding binding = { &ops, NULL, &protocol, { { 0 } } };
	struct cdk2_split_publication publications[5] = { 0 };
	UINTN index;
	int failures = 0;

	failures += expect(cdk2_split_binding_supported(&binding, (void *)1) ==
		EFI_SUCCESS && opens == 1U && closes == 1U,
		"Supported did not symmetrically probe ownership");
	injected = EFI_DEVICE_ERROR;
	failures += expect(cdk2_split_binding_start(&binding, (void *)1) ==
		EFI_DEVICE_ERROR && closes == 2U,
		"failed admission did not release ownership");
	injected = EFI_SUCCESS;
	failures += expect(cdk2_split_binding_start(&binding, (void *)1) == EFI_SUCCESS &&
		cdk2_split_binding_start(&binding, (void *)2) == EFI_SUCCESS,
		"independent controllers were not admitted");
	injected = TEST_WRITE_PROTECTED;
	failures += expect(cdk2_split_binding_stop(&binding, (void *)1) ==
		TEST_WRITE_PROTECTED && binding.instances[0].active,
		"remove failure lost protocol ownership");
	injected = TEST_ACCESS_DENIED;
	failures += expect(cdk2_split_binding_stop(&binding, (void *)2) ==
		TEST_ACCESS_DENIED && binding.instances[1].active && admits == 4U,
		"close failure did not restore aggregate membership");
	injected = EFI_SUCCESS;
	failures += expect(cdk2_split_binding_stop(&binding, (void *)1) == EFI_SUCCESS &&
		!binding.instances[0].active, "successful Stop retained ownership");
	for (index = 0; index < 5U; index++)
		cdk2_split_publication_prepare(&publications[index], &binding, (void *)8);
	fail_publish = 4U;
	failures += expect(cdk2_split_publications_install(publications, 5U, publish,
		unpublish, NULL) == EFI_DEVICE_ERROR && unpublishes == 3U,
		"partial DriverBinding/ComponentName publication was not rolled back");
	return failures == 0 ? 0 : 1;
}
