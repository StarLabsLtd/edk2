/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/terminal.h>

#include <string.h>

#define TERMINAL_DEVICE_ERROR ((1ULL << 63) | 7ULL)

static uint64_t enqueue(struct cdk2_terminal *terminal, uint16_t scan,
			uint16_t unicode)
{
	size_t next = (terminal->tail + 1) % CDK2_TERMINAL_QUEUE;

	if (next == terminal->head)
		return EFI_OUT_OF_RESOURCES;
	terminal->queue[terminal->tail] =
		(struct cdk2_terminal_key){scan, unicode, 0, 0};
	terminal->tail = next;
	return EFI_SUCCESS;
}

void cdk2_terminal_init(struct cdk2_terminal *terminal,
			enum cdk2_terminal_type type, void *serial,
			cdk2_terminal_write_fn *write)
{
	memset(terminal, 0, sizeof(*terminal));
	terminal->type = type;
	terminal->serial = serial;
	terminal->write = write;
}

static uint16_t sequence_scan(const uint8_t *sequence, size_t length)
{
	struct mapping {
		const char *text;
		uint8_t length;
		uint16_t scan;
	};
	static const struct mapping mappings[] = {
		{"\x1b[A", 3, 1},    {"\x1b[B", 3, 2},	  {"\x1b[C", 3, 3},
		{"\x1b[D", 3, 4},    {"\x1b[H", 3, 5},	  {"\x1b[F", 3, 6},
		{"\x1b[2~", 4, 7},   {"\x1b[3~", 4, 8},	  {"\x1b[5~", 4, 9},
		{"\x1b[6~", 4, 10},  {"\x1bOP", 3, 11},	  {"\x1bOQ", 3, 12},
		{"\x1bOR", 3, 13},   {"\x1bOS", 3, 14},	  {"\x1b[15~", 5, 15},
		{"\x1b[17~", 5, 16}, {"\x1b[18~", 5, 17}, {"\x1b[19~", 5, 18},
		{"\x1b[20~", 5, 19}, {"\x1b[21~", 5, 20}, {"\x1b[23~", 5, 21},
		{"\x1b[24~", 5, 22}};
	size_t i;

	for (i = 0; i < ARRAY_SIZE(mappings); i++)
		if (length == mappings[i].length &&
		    memcmp(sequence, mappings[i].text, length) == 0)
			return mappings[i].scan;
	return 0;
}

static int sequence_complete(const uint8_t *sequence, size_t length)
{
	uint8_t last;

	if (length == 0)
		return 0;
	last = sequence[length - 1];
	return (last >= 'A' && last <= 'Z') || last == '~';
}

static uint64_t utf8_byte(struct cdk2_terminal *terminal, uint8_t byte)
{
	uint32_t minimum;

	if (terminal->utf8_needed == 0) {
		if (byte < 0x80)
			return enqueue(terminal, 0, byte);
		if ((byte & 0xe0) == 0xc0) {
			terminal->utf8_codepoint = byte & 0x1f;
			terminal->utf8_needed = 1;
		} else if ((byte & 0xf0) == 0xe0) {
			terminal->utf8_codepoint = byte & 0x0f;
			terminal->utf8_needed = 2;
		} else if ((byte & 0xf8) == 0xf0) {
			terminal->utf8_codepoint = byte & 7;
			terminal->utf8_needed = 3;
		} else {
			return EFI_INVALID_PARAMETER;
		}
		terminal->utf8_seen = 0;
		return EFI_SUCCESS;
	}
	if ((byte & 0xc0) != 0x80) {
		terminal->utf8_needed = terminal->utf8_seen = 0;
		return EFI_INVALID_PARAMETER;
	}
	terminal->utf8_codepoint =
		(terminal->utf8_codepoint << 6) | (byte & 0x3f);
	terminal->utf8_seen++;
	if (terminal->utf8_seen != terminal->utf8_needed)
		return EFI_SUCCESS;
	minimum = terminal->utf8_needed == 1   ? 0x80
		  : terminal->utf8_needed == 2 ? 0x800
					       : 0x10000;
	terminal->utf8_needed = terminal->utf8_seen = 0;
	if (terminal->utf8_codepoint < minimum ||
	    terminal->utf8_codepoint > 0xffff ||
	    (terminal->utf8_codepoint >= 0xd800 &&
	     terminal->utf8_codepoint <= 0xdfff))
		return EFI_INVALID_PARAMETER;
	return enqueue(terminal, 0, (uint16_t)terminal->utf8_codepoint);
}

uint64_t cdk2_terminal_input(struct cdk2_terminal *terminal,
			     const uint8_t *bytes, size_t length)
{
	size_t i;

	if (terminal == NULL || (bytes == NULL && length != 0))
		return EFI_INVALID_PARAMETER;
	for (i = 0; i < length; i++) {
		uint8_t byte = bytes[i];
		uint64_t status;

		if (terminal->escape_length != 0) {
			uint16_t scan;

			if (terminal->escape_length >=
			    sizeof(terminal->escape)) {
				terminal->escape_length = 0;
				return EFI_INVALID_PARAMETER;
			}
			terminal->escape[terminal->escape_length++] = byte;
			if (!sequence_complete(terminal->escape,
					       terminal->escape_length))
				continue;
			scan = sequence_scan(terminal->escape,
					     terminal->escape_length);
			terminal->escape_length = 0;
			status = scan == 0 ? EFI_INVALID_PARAMETER
					   : enqueue(terminal, scan, 0);
		} else if (byte == 0x1b) {
			terminal->escape[0] = byte;
			terminal->escape_length = 1;
			status = EFI_SUCCESS;
		} else if (terminal->type == CDK2_TERMINAL_VT_UTF8) {
			status = utf8_byte(terminal, byte);
		} else {
			status = enqueue(terminal, 0,
					 byte == 0x7f ? 0x08 : byte);
		}
		if (status != EFI_SUCCESS)
			return status;
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_terminal_read_key(struct cdk2_terminal *terminal,
				struct cdk2_terminal_key *key)
{
	if (terminal == NULL || key == NULL)
		return EFI_INVALID_PARAMETER;
	if (terminal->head == terminal->tail)
		return EFI_NOT_READY;
	*key = terminal->queue[terminal->head];
	terminal->head = (terminal->head + 1) % CDK2_TERMINAL_QUEUE;
	return EFI_SUCCESS;
}

static uint64_t write_bytes(struct cdk2_terminal *terminal, const uint8_t *data,
			    size_t length)
{
	size_t written = 0;
	uint64_t status;

	if (terminal->write == NULL)
		return EFI_NOT_READY;
	status = terminal->write(terminal->serial, length, &written, data);
	return status == EFI_SUCCESS && written == length
		       ? EFI_SUCCESS
		       : TERMINAL_DEVICE_ERROR;
}

uint64_t cdk2_terminal_output(struct cdk2_terminal *terminal,
			      const uint16_t *text)
{
	if (terminal == NULL || text == NULL)
		return EFI_INVALID_PARAMETER;
	while (*text != 0) {
		uint32_t character = *text++;
		uint8_t bytes[3];
		size_t length;

		if (character < 0x80) {
			bytes[0] = (uint8_t)character;
			length = 1;
		} else if (terminal->type != CDK2_TERMINAL_VT_UTF8) {
			bytes[0] = '?';
			length = 1;
		} else if (character < 0x800) {
			bytes[0] = 0xc0 | (uint8_t)(character >> 6);
			bytes[1] = 0x80 | (uint8_t)(character & 0x3f);
			length = 2;
		} else if (character < 0xd800 || character > 0xdfff) {
			bytes[0] = 0xe0 | (uint8_t)(character >> 12);
			bytes[1] = 0x80 | (uint8_t)((character >> 6) & 0x3f);
			bytes[2] = 0x80 | (uint8_t)(character & 0x3f);
			length = 3;
		} else {
			return EFI_INVALID_PARAMETER;
		}
		if (write_bytes(terminal, bytes, length) != EFI_SUCCESS)
			return TERMINAL_DEVICE_ERROR;
	}
	return EFI_SUCCESS;
}
