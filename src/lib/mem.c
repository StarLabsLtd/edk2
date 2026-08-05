/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Minimal freestanding memory helpers for compiler-generated calls.
 */

#include <stddef.h>

void *memset(void *destination, int value, size_t length)
{
	unsigned char *bytes;
	size_t index;

	bytes = destination;
	for (index = 0; index < length; index++) {
		bytes[index] = (unsigned char)value;
	}

	return destination;
}

void *memcpy(void *destination, const void *source, size_t length)
{
	unsigned char *destination_bytes;
	const unsigned char *source_bytes;
	size_t index;

	destination_bytes = destination;
	source_bytes = source;
	for (index = 0; index < length; index++) {
		destination_bytes[index] = source_bytes[index];
	}

	return destination;
}

void *memmove(void *destination, const void *source, size_t length)
{
	unsigned char *destination_bytes;
	const unsigned char *source_bytes;
	size_t index;

	destination_bytes = destination;
	source_bytes = source;
	if (destination_bytes <= source_bytes) {
		for (index = 0; index < length; index++) {
			destination_bytes[index] = source_bytes[index];
		}
	} else {
		for (index = length; index > 0; index--) {
			destination_bytes[index - 1] = source_bytes[index - 1];
		}
	}

	return destination;
}

int memcmp(const void *left, const void *right, size_t length)
{
	const unsigned char *left_bytes;
	const unsigned char *right_bytes;
	size_t index;

	left_bytes = left;
	right_bytes = right;
	for (index = 0; index < length; index++) {
		if (left_bytes[index] != right_bytes[index]) {
			return (int)left_bytes[index] - (int)right_bytes[index];
		}
	}

	return 0;
}
