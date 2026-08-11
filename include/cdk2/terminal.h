/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TERMINAL_H_
#define CDK2_TERMINAL_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_TERMINAL_QUEUE 64U
#define CDK2_TERMINAL_ESCAPE 16U

enum cdk2_terminal_type {
	CDK2_TERMINAL_PC_ANSI,
	CDK2_TERMINAL_VT100,
	CDK2_TERMINAL_VT100_PLUS,
	CDK2_TERMINAL_VT_UTF8,
};

struct cdk2_terminal_key {
	uint16_t scan_code;
	uint16_t unicode_char;
	uint32_t shift_state;
	uint8_t toggle_state;
};

typedef uint64_t CDK2_MS_ABI cdk2_terminal_write_fn(void *, size_t, size_t *,
						    const void *);

struct cdk2_terminal {
	enum cdk2_terminal_type type;
	cdk2_terminal_write_fn *write;
	void *serial;
	struct cdk2_terminal_key queue[CDK2_TERMINAL_QUEUE];
	size_t head, tail;
	uint8_t escape[CDK2_TERMINAL_ESCAPE];
	size_t escape_length;
	uint32_t utf8_codepoint;
	uint8_t utf8_needed, utf8_seen;
};

void cdk2_terminal_init(struct cdk2_terminal *terminal,
			enum cdk2_terminal_type type, void *serial,
			cdk2_terminal_write_fn *write);
uint64_t cdk2_terminal_input(struct cdk2_terminal *terminal,
			     const uint8_t *bytes, size_t length);
uint64_t cdk2_terminal_read_key(struct cdk2_terminal *terminal,
				struct cdk2_terminal_key *key);
uint64_t cdk2_terminal_output(struct cdk2_terminal *terminal,
			      const uint16_t *text);

#endif
