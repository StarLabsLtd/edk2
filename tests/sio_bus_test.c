/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/sio_bus.h>
#include <cdk2/sio_bus_binding.h>
#include <stdio.h>
#include <string.h>

static int expect(int c, const char *m)
{
	if (!c)
		fprintf(stderr, "sio test: %s\n", m);
	return c ? 0 : 1;
}
struct mock {
	int calls, fail_at, installs, relations, closes;
	UINT64 attrs;
};
static EFI_STATUS tick(struct mock *m)
{
	m->calls++;
	return m->calls == m->fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS parent(void *c, void *h)
{
	(void)h;
	return tick(c);
}
static EFI_STATUS close_parent(void *c, void *h)
{
	(void)h;
	((struct mock *)c)->closes++;
	return EFI_SUCCESS;
}
static EFI_STATUS info(void *c, void *h, struct cdk2_sio_pci_info *i)
{
	(void)h;
	if (EFI_ERROR(tick(c)))
		return EFI_DEVICE_ERROR;
	*i = (struct cdk2_sio_pci_info){0x8086, 3, 6, 1, 0};
	return EFI_SUCCESS;
}
static EFI_STATUS attr(void *c, void *h, UINT64 a, UINT64 *v)
{
	(void)h;
	(void)a;
	if (EFI_ERROR(tick(c)))
		return EFI_DEVICE_ERROR;
	if (v)
		*v = ((struct mock *)c)->attrs;
	return EFI_SUCCESS;
}
static EFI_STATUS child(void *c, void *h, struct cdk2_sio_child *x, UINTN i)
{
	struct mock *m = c;
	(void)h;
	if (EFI_ERROR(tick(m)))
		return EFI_DEVICE_ERROR;
	x->handle = (void *)(i + 1);
	m->installs++;
	return EFI_SUCCESS;
}
static EFI_STATUS unchild(void *c, void *h, struct cdk2_sio_child *x, UINTN i)
{
	(void)h;
	(void)x;
	(void)i;
	((struct mock *)c)->installs--;
	return EFI_SUCCESS;
}
static EFI_STATUS relate(void *c, void *h, struct cdk2_sio_child *x, UINTN i)
{
	struct mock *m = c;
	(void)h;
	(void)x;
	(void)i;
	if (EFI_ERROR(tick(m)))
		return EFI_DEVICE_ERROR;
	m->relations++;
	return EFI_SUCCESS;
}
static EFI_STATUS unrelate(void *c, void *h, struct cdk2_sio_child *x, UINTN i)
{
	(void)h;
	(void)x;
	(void)i;
	((struct mock *)c)->relations--;
	return EFI_SUCCESS;
}
static const struct cdk2_sio_binding_ops ops = {
	parent, close_parent, parent, close_parent, info,   attr,    attr,
	attr,	attr,	      child,  unchild,	    relate, unrelate};
int main(void)
{
	struct cdk2_sio sio;
	struct cdk2_sio_resource *resource, bad;
	uint8_t value = 0;
	int failures = 0;
	size_t index;
	for (index = 0; index < 3; index++) {
		cdk2_sio_init(&sio, index);
		failures += expect(
			sio.get_resources(&sio, (void **)&resource) ==
					EFI_SUCCESS &&
				resource->base ==
					cdk2_sio_devices[index].io_base &&
				resource->end_tag == 0x79,
			"fixed ACPI resource returned");
		bad = *resource;
		bad.base++;
		failures += expect(sio.set_resources(&sio, &bad) ==
					   CDK2_SIO_ACCESS_DENIED,
				   "resource relocation denied");
	}
	failures += expect(sio.register_access(&sio, 0, 1, 0, &value) ==
				   EFI_SUCCESS,
			   "configuration access accepted");
	failures += expect(sio.modify(&sio, NULL, 1) == EFI_INVALID_PARAMETER,
			   "invalid modify table rejected");
	{
		struct mock mock = {0, 0, 0, 0, 0, CDK2_SIO_PCI_ISA_IO};
		struct cdk2_sio_binding binding = {.ops = &ops,
						   .context = &mock};
		void *handles[3];
		failures += expect(cdk2_sio_binding_supported(
					   &binding, (void *)9) == EFI_SUCCESS,
				   "ISA bridge admitted");
		mock.calls = 0;
		failures += expect(
			cdk2_sio_binding_start(&binding, (void *)9) ==
					EFI_SUCCESS &&
				mock.installs == 3 && mock.relations == 3,
			"three children published");
		for (index = 0; index < 3; index++)
			handles[index] = binding.children[index].handle;
		failures +=
			expect(cdk2_sio_binding_stop(&binding, 3, handles) ==
					       EFI_SUCCESS &&
				       binding.child_count == 0,
			       "selected children stopped");
		failures += expect(cdk2_sio_binding_stop(&binding, 0, NULL) ==
						   EFI_SUCCESS &&
					   mock.installs == 0 &&
					   mock.relations == 0,
				   "parent ownership restored");
	}
	for (index = 1; index <= 12; index++) {
		struct mock mock = {0, (int)index, 0,
				    0, 0,	   CDK2_SIO_PCI_ISA_IO_16};
		struct cdk2_sio_binding binding = {.ops = &ops,
						   .context = &mock};
		EFI_STATUS status = cdk2_sio_binding_start(&binding, (void *)9);
		if (EFI_ERROR(status))
			failures += expect(!binding.pci_open &&
						   mock.installs == 0 &&
						   mock.relations == 0,
					   "fault rollback leaked ownership");
		else {
			void *handles[3];
			for (size_t j = 0; j < 3; j++)
				handles[j] = binding.children[j].handle;
			(void)cdk2_sio_binding_stop(&binding, 3, handles);
			(void)cdk2_sio_binding_stop(&binding, 0, NULL);
		}
	}
	return failures == 0 ? 0 : 1;
}
