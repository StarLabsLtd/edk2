/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/ata_bus.h>

#include <stddef.h>

void *memset(void *destination, int value, size_t size)
{
	unsigned char *bytes = destination;
	while (size-- != 0) *bytes++ = (unsigned char)value;
	return destination;
}
void *memcpy(void *destination, const void *source, size_t size)
{
	unsigned char *out = destination; const unsigned char *in = source;
	while (size-- != 0) *out++ = *in++;
	return destination;
}
void *memmove(void *destination, const void *source, size_t size)
{
	unsigned char *out = destination; const unsigned char *in = source;
	if (out < in) return memcpy(out, in, size);
	while (size-- != 0) out[size] = in[size];
	return destination;
}
int strcmp(const char *left, const char *right)
{
	while (*left != 0 && *left == *right) { left++; right++; }
	return (unsigned char)*left - (unsigned char)*right;
}
