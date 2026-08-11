/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/terminal_driver.h>

#include <stddef.h>
#include <string.h>

#define OPEN_GET_PROTOCOL 2U
#define OPEN_BY_DRIVER 0x10U
#define OPEN_BY_CHILD 8U
#define EVT_NOTIFY_WAIT 0x100U
#define TPL_NOTIFY 16U
#define TERMINAL_NOT_STARTED ((1ULL << 63) | 19ULL)

static const EFI_GUID serial_guid = {
	0xbb25cf6f,
	0xf1d4,
	0x11d2,
	{0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd}};
static const EFI_GUID device_path_guid = {
	0x09576e91,
	0x6d3f,
	0x11d2,
	{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID text_in_guid = {
	0x387477c1,
	0x69c7,
	0x11d2,
	{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID text_in_ex_guid = {
	0xdd9e7534,
	0x7762,
	0x4698,
	{0x8c, 0x14, 0xf5, 0x85, 0x17, 0xa6, 0x25, 0xaa}};
static const EFI_GUID text_out_guid = {
	0x387477c2,
	0x69c7,
	0x11d2,
	{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static const EFI_GUID terminal_guids[] = {
	{0xe0c14753,
	 0xf9be,
	 0x11d2,
	 {0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}},
	{0xdfa66065,
	 0xb419,
	 0x11d3,
	 {0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}},
	{0x7baec70b,
	 0x57e0,
	 0x4c76,
	 {0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43}},
	{0xad15a0d6,
	 0x8bec,
	 0x4acf,
	 {0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88}}};

static struct cdk2_terminal_child *from_input(void *interface)
{
	return (struct cdk2_terminal_child
			*)((uint8_t *)interface -
			   offsetof(struct cdk2_terminal_child, input));
}

static struct cdk2_terminal_child *from_input_ex(void *interface)
{
	return (struct cdk2_terminal_child
			*)((uint8_t *)interface -
			   offsetof(struct cdk2_terminal_child, input_ex));
}

static struct cdk2_terminal_child *from_output(void *interface)
{
	return (struct cdk2_terminal_child
			*)((uint8_t *)interface -
			   offsetof(struct cdk2_terminal_child, output));
}

static uint64_t CDK2_MS_ABI input_reset(void *interface, uint8_t verification)
{
	struct cdk2_terminal_child *child = from_input(interface);

	(void)verification;
	child->terminal.head = child->terminal.tail = 0;
	child->terminal.escape_length = child->terminal.utf8_needed = 0;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI input_ex_reset(void *interface,
					   uint8_t verification)
{
	return input_reset(&from_input_ex(interface)->input, verification);
}

static uint64_t CDK2_MS_ABI input_read(void *interface,
				       struct cdk2_terminal_key *key)
{
	return cdk2_terminal_read_key(&from_input(interface)->terminal, key);
}

static uint64_t CDK2_MS_ABI input_ex_read(void *interface,
					  struct cdk2_terminal_key *key)
{
	struct cdk2_terminal_child *child = from_input_ex(interface);
	uint64_t status = cdk2_terminal_read_key(&child->terminal, key);
	size_t i;

	if (status != EFI_SUCCESS)
		return status;
	for (i = 0;
	     i < ARRAY_SIZE(child->notifications);
	     i++)
		if (child->notifications[i].callback != NULL &&
		    memcmp(&child->notifications[i].key, key, sizeof(*key)) ==
			    0) {
			void(CDK2_MS_ABI *
			     callback)(struct cdk2_terminal_key *) =
				child->notifications[i].callback;
			callback(key);
		}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI set_state(void *interface, uint8_t *toggle)
{
	(void)interface;
	return toggle == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI register_notify(void *interface,
					    struct cdk2_terminal_key *key,
					    void *callback, void **handle)
{
	struct cdk2_terminal_child *child = from_input_ex(interface);
	size_t i, empty = 16;

	if (key == NULL || callback == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (i = 0; i < 16; i++) {
		if (child->notifications[i].callback == callback &&
		    memcmp(&child->notifications[i].key, key, sizeof(*key)) ==
			    0) {
			*handle = child->notifications[i].handle;
			return EFI_SUCCESS;
		}
		if (empty == 16 && child->notifications[i].callback == NULL)
			empty = i;
	}
	if (empty == 16)
		return EFI_OUT_OF_RESOURCES;
	child->notifications[empty].key = *key;
	child->notifications[empty].callback = callback;
	child->notifications[empty].handle = &child->notifications[empty];
	*handle = child->notifications[empty].handle;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI unregister_notify(void *interface, void *handle)
{
	struct cdk2_terminal_child *child = from_input_ex(interface);
	size_t i;

	for (i = 0; i < 16; i++)
		if (child->notifications[i].handle == handle &&
		    child->notifications[i].callback != NULL) {
			memset(&child->notifications[i], 0,
			       sizeof(child->notifications[i]));
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

static uint64_t CDK2_MS_ABI output_reset(void *interface, uint8_t verification)
{
	struct cdk2_terminal_child *child = from_output(interface);
	static const uint16_t reset[] = {0x1b, '[', '0', 'm', 0x1b,
					 '[',  '2', 'J', 0};

	(void)verification;
	child->mode.mode = child->mode.attribute = child->mode.cursor_column =
		child->mode.cursor_row = 0;
	child->mode.cursor_visible = 1;
	return cdk2_terminal_output(&child->terminal, reset);
}

static uint64_t CDK2_MS_ABI output_string(void *interface, const uint16_t *text)
{
	return cdk2_terminal_output(&from_output(interface)->terminal, text);
}

static uint64_t CDK2_MS_ABI test_string(void *interface, const uint16_t *text)
{
	struct cdk2_terminal_child *child = from_output(interface);
	(void)child;
	if (text == NULL)
		return EFI_INVALID_PARAMETER;
	for (; *text != 0; text++)
		if (child->terminal.type != CDK2_TERMINAL_VT_UTF8 &&
		    *text > 0x7f)
			return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI query_mode(void *interface, size_t mode,
				       size_t *columns, size_t *rows)
{
	(void)interface;
	if (columns == NULL || rows == NULL || mode > 2)
		return EFI_INVALID_PARAMETER;
	*columns = mode == 2 ? 100 : 80;
	*rows = mode == 1 ? 50 : mode == 2 ? 31 : 25;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI clear_screen(void *interface);

static uint64_t CDK2_MS_ABI set_mode(void *interface, size_t mode)
{
	struct cdk2_terminal_child *child = from_output(interface);
	if (mode >= (size_t)child->mode.max_mode)
		return EFI_UNSUPPORTED;
	child->mode.mode = (int32_t)mode;
	child->mode.cursor_column = child->mode.cursor_row = 0;
	return clear_screen(interface);
}

static size_t append_decimal(uint16_t *text, size_t offset, size_t value)
{
	uint16_t reverse[24];
	size_t count = 0;
	do {
		reverse[count++] = (uint16_t)('0' + value % 10);
		value /= 10;
	} while (value != 0);
	while (count != 0)
		text[offset++] = reverse[--count];
	return offset;
}

static uint64_t CDK2_MS_ABI set_attribute(void *interface, size_t attribute)
{
	struct cdk2_terminal_child *child = from_output(interface);
	uint16_t command[16] = {0x1b, '[', '0', ';', '3'};
	size_t offset = 5;
	if (attribute > 0x7f)
		return EFI_UNSUPPORTED;
	child->mode.attribute = (int32_t)attribute;
	command[offset++] = (uint16_t)('0' + (attribute & 7));
	command[offset++] = 'm';
	return cdk2_terminal_output(&child->terminal, command);
}

static uint64_t CDK2_MS_ABI clear_screen(void *interface)
{
	static const uint16_t clear[] = {0x1b, '[', '2', 'J',
					 0x1b, '[', 'H', 0};
	struct cdk2_terminal_child *child = from_output(interface);
	child->mode.cursor_column = child->mode.cursor_row = 0;
	return cdk2_terminal_output(&child->terminal, clear);
}

static uint64_t CDK2_MS_ABI cursor(void *interface, size_t column, size_t row)
{
	struct cdk2_terminal_child *child = from_output(interface);
	size_t columns, rows;
	uint16_t command[32] = {0x1b, '['};
	size_t offset = 2;
	if (query_mode(interface, child->mode.mode, &columns, &rows) !=
		    EFI_SUCCESS ||
	    column >= columns || row >= rows)
		return EFI_UNSUPPORTED;
	child->mode.cursor_column = (int32_t)column;
	child->mode.cursor_row = (int32_t)row;
	offset = append_decimal(command, offset, row + 1);
	command[offset++] = ';';
	offset = append_decimal(command, offset, column + 1);
	command[offset] = 'H';
	return cdk2_terminal_output(&child->terminal, command);
}

static uint64_t CDK2_MS_ABI enable_cursor(void *interface, uint8_t visible)
{
	struct cdk2_terminal_child *child = from_output(interface);
	uint16_t command[] = {0x1b, '[', '?', '2', '5', 'h', 0};
	child->mode.cursor_visible = visible != 0;
	if (!visible)
		command[5] = 'l';
	return cdk2_terminal_output(&child->terminal, command);
}

static void CDK2_MS_ABI wait_notify(void *event, void *context)
{
	struct cdk2_terminal_child *child = context;
	uint8_t data[32];
	size_t size = sizeof(data);
	(void)event;
	if (child->serial->read != NULL &&
	    child->serial->read(child->serial, sizeof(data), &size, data) ==
		    EFI_SUCCESS)
		(void)cdk2_terminal_input(&child->terminal, data, size);
}

uint64_t cdk2_terminal_supported(struct cdk2_terminal_services *services,
				 void *driver, void *controller)
{
	void *serial = NULL;
	if (services == NULL || services->open_protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return services->open_protocol(controller, &serial_guid, &serial,
				       driver, controller, OPEN_GET_PROTOCOL);
}

uint64_t cdk2_terminal_start(struct cdk2_terminal_child *child,
			     struct cdk2_terminal_services *services,
			     void *driver, void *controller,
			     enum cdk2_terminal_type type)
{
	uint64_t status;

	if (child == NULL || services == NULL || type > CDK2_TERMINAL_VT_UTF8)
		return EFI_INVALID_PARAMETER;
	memset(child, 0, sizeof(*child));
	child->services = services;
	child->driver = driver;
	child->controller = controller;
	status = services->open_protocol(controller, &serial_guid,
					 (void **)&child->serial, driver,
					 controller, OPEN_BY_DRIVER);
	if (status != EFI_SUCCESS)
		return status;
	cdk2_terminal_init(&child->terminal, type, child->serial,
			   child->serial->write);
	child->mode.max_mode = 3;
	child->mode.cursor_visible = 1;
	child->input =
		(struct cdk2_simple_text_input){input_reset, input_read, NULL};
	child->input_ex = (struct cdk2_simple_text_input_ex){
		input_ex_reset, input_ex_read,	 NULL,
		set_state,	register_notify, unregister_notify};
	child->output = (struct cdk2_simple_text_output){
		output_reset,  output_string, test_string,  query_mode,
		set_mode,      set_attribute, clear_screen, cursor,
		enable_cursor, &child->mode};
	child->path = (struct cdk2_terminal_device_path){
		3, 10, 20, terminal_guids[type], 0x7f, 0xff, 4};
	status = services->create_event(EVT_NOTIFY_WAIT, TPL_NOTIFY,
					wait_notify, child, &child->wait_key);
	if (status != EFI_SUCCESS)
		goto close_parent;
	status =
		services->create_event(EVT_NOTIFY_WAIT, TPL_NOTIFY, wait_notify,
				       child, &child->wait_key_ex);
	if (status != EFI_SUCCESS)
		goto close_wait;
	child->input.wait_for_key = child->wait_key;
	child->input_ex.wait_for_key_ex = child->wait_key_ex;
	status = services->install_protocols(
		&child->handle, &device_path_guid, &child->path, &text_in_guid,
		&child->input, &text_in_ex_guid, &child->input_ex,
		&text_out_guid, &child->output, NULL);
	if (status != EFI_SUCCESS)
		goto close_wait_ex;
	status = services->open_protocol(controller, &serial_guid,
					 (void **)&child->serial, driver,
					 child->handle, OPEN_BY_CHILD);
	if (status != EFI_SUCCESS)
		goto uninstall;
	child->started = 1;
	return EFI_SUCCESS;
uninstall:
	(void)services->uninstall_protocols(
		child->handle, &device_path_guid, &child->path, &text_in_guid,
		&child->input, &text_in_ex_guid, &child->input_ex,
		&text_out_guid, &child->output, NULL);
close_wait_ex:
	(void)services->close_event(child->wait_key_ex);
close_wait:
	(void)services->close_event(child->wait_key);
close_parent:
	(void)services->close_protocol(controller, &serial_guid, driver,
				       controller);
	return status;
}

uint64_t cdk2_terminal_stop(struct cdk2_terminal_child *child)
{
	uint64_t status;
	if (child == NULL || !child->started)
		return TERMINAL_NOT_STARTED;
	status = child->services->uninstall_protocols(
		child->handle, &device_path_guid, &child->path, &text_in_guid,
		&child->input, &text_in_ex_guid, &child->input_ex,
		&text_out_guid, &child->output, NULL);
	if (status != EFI_SUCCESS)
		return status;
	(void)child->services->close_protocol(child->controller, &serial_guid,
					      child->driver, child->handle);
	(void)child->services->close_event(child->wait_key_ex);
	(void)child->services->close_event(child->wait_key);
	(void)child->services->close_protocol(child->controller, &serial_guid,
					      child->driver, child->controller);
	child->started = 0;
	return EFI_SUCCESS;
}
