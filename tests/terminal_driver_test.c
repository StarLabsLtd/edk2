/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/terminal_driver.h>

#include <stdio.h>
#include <string.h>

static unsigned int calls, fail_call, closes, uninstalls, close_events;
static uint8_t bytes[256];
static size_t byte_count;
static struct cdk2_serial_io serial;
static void (CDK2_MS_ABI * wait_notify)(void *, void *);
static void *wait_context;

static uint64_t CDK2_MS_ABI mock_read(void *self, size_t size, size_t *read,
				      void *data)
{
	(void)self;
	if (size == 0)
		return EFI_INVALID_PARAMETER;
	*(uint8_t *)data = 'Q';
	*read = 1;
	return EFI_SUCCESS;
}

static uint64_t maybe_fail(void)
{
	calls++;
	return calls == fail_call ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_write(void *self, size_t size, size_t *written,
				       const void *data)
{
	(void)self;
	memcpy(bytes + byte_count, data, size);
	byte_count += size;
	*written = size;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_open(void *handle, const EFI_GUID *guid,
				      void **interface, void *agent,
				      void *controller, uint32_t attributes)
{
	uint64_t status = maybe_fail();
	(void)handle;
	(void)guid;
	(void)agent;
	(void)controller;
	(void)attributes;
	if (status == EFI_SUCCESS)
		*interface = &serial;
	return status;
}

static uint64_t CDK2_MS_ABI mock_close(void *handle, const EFI_GUID *guid,
				       void *agent, void *controller)
{
	(void)handle;
	(void)guid;
	(void)agent;
	(void)controller;
	closes++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_install(void **handle, const EFI_GUID *guid,
					 void *interface, ...)
{
	uint64_t status = maybe_fail();
	(void)guid;
	(void)interface;
	if (status == EFI_SUCCESS)
		*handle = (void *)2;
	return status;
}

static uint64_t CDK2_MS_ABI mock_uninstall(void *handle, const EFI_GUID *guid,
					   void *interface, ...)
{
	(void)handle;
	(void)guid;
	(void)interface;
	uninstalls++;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_event(uint32_t type, size_t tpl, void *notify,
				       void *context, void **event)
{
	uint64_t status = maybe_fail();
	(void)type;
	(void)tpl;
	wait_notify = notify;
	wait_context = context;
	if (status == EFI_SUCCESS)
		*event = (void *)(size_t)(calls + 10);
	return status;
}

static uint64_t CDK2_MS_ABI mock_close_event(void *event)
{
	(void)event;
	close_events++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "terminal driver test: %s\n", message);
	return condition ? 0 : 1;
}

static void reset(void)
{
	calls = fail_call = closes = uninstalls = close_events = byte_count = 0;
	memset(&serial, 0, sizeof(serial));
	serial.write = mock_write;
	serial.read = mock_read;
	wait_notify = NULL;
	wait_context = NULL;
}

int main(void)
{
	struct cdk2_terminal_services services = {
		mock_open,	mock_close, mock_install,
		mock_uninstall, mock_event, mock_close_event};
	struct cdk2_terminal_child child;
	struct cdk2_terminal_key key = {0, 'x', 0, 0};
	void *notify_handle;
	static const uint16_t hello[] = {'O', 'K', 0};
	int failures = 0;
	unsigned int stage;

	for (stage = 1; stage <= 5; stage++) {
		reset();
		fail_call = stage;
		failures += expect(cdk2_terminal_start(&child, &services,
						       (void *)1, (void *)3,
						       CDK2_TERMINAL_VT_UTF8) ==
					   EFI_OUT_OF_RESOURCES,
				   "injected start failure returned");
		failures +=
			expect(!child.started, "failed start not published");
		if (stage >= 2)
			failures += expect(closes != 0,
					   "parent ownership rolled back");
	}
	reset();
	failures += expect(cdk2_terminal_supported(&services, (void *)1,
						   (void *)3) == EFI_SUCCESS,
			   "serial parent supported");
	reset();
	failures += expect(
		cdk2_terminal_start(&child, &services, (void *)1, (void *)3,
				    CDK2_TERMINAL_VT_UTF8) == EFI_SUCCESS &&
			child.started,
		"child started");
	failures += expect(child.path.type == 3 && child.path.subtype == 10 &&
				   child.path.length == 20 &&
				   child.path.end_type == 0x7f,
			   "vendor terminal device path published");
	failures +=
		expect(child.output.output_string(&child.output, hello) ==
				       EFI_SUCCESS &&
			       byte_count == 2 && memcmp(bytes, "OK", 2) == 0,
		       "text output reaches serial");
	failures += expect(child.input_ex.register_key_notify(
				   &child.input_ex, &key, (void *)mock_write,
				   &notify_handle) == EFI_SUCCESS &&
				   notify_handle != NULL,
			   "key notification registered");
	wait_notify(NULL, wait_context);
	failures += expect(child.input.read_key_stroke(&child.input, &key) ==
					   EFI_SUCCESS &&
				   key.unicode_char == 'Q',
			   "wait event polls Serial I/O into input queue");
	failures +=
		expect(child.input_ex.unregister_key_notify(
			       &child.input_ex, notify_handle) == EFI_SUCCESS,
		       "key notification removed");
	failures += expect(cdk2_terminal_stop(&child) == EFI_SUCCESS &&
				   !child.started && uninstalls == 1 &&
				   close_events == 2 && closes == 2,
			   "stop unpublishes child and releases parent");
	return failures == 0 ? 0 : 1;
}
