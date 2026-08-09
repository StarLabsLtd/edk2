/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/fat_binding.h>
#include <stdio.h>

static int expect(int ok, const char *message)
{
	if (!ok)
		fprintf(stderr, "FAT protocol ABI test: %s\n", message);
	return !ok;
}

int main(void)
{
	struct cdk2_fat_protocol_volume volume;
	struct cdk2_fat_binding binding = {0};
	struct cdk2_fat_mount mount = {0};
	struct cdk2_fat_file_protocol *file = (void *)1;
	int failures = 0;

	cdk2_fat_protocol_init(&volume, &binding, &mount);
	failures += expect(sizeof(struct cdk2_fat_simple_fs_protocol) == 16U &&
			       volume.protocol.revision == 0x10000ULL,
			   "Simple File System revision or two-slot layout drifted");
	failures += expect(sizeof(struct cdk2_fat_file_protocol) == 120U &&
			       offsetof(struct cdk2_fat_file_protocol, flush_ex) == 112U,
			   "revision-2 EFI_FILE_PROTOCOL is not exactly 15 slots");
	failures += expect(volume.protocol.open_volume(NULL, &file) == EFI_INVALID_PARAMETER &&
			       file == (void *)1,
			   "NULL protocol fault path changed caller ownership");
	failures +=
	    expect(volume.protocol.open_volume(&volume.protocol, NULL) == EFI_INVALID_PARAMETER,
		   "NULL result fault was not rejected");
	failures += expect(cdk2_fat_file_info_guid.data1 == 0x09576e92U &&
			       cdk2_fat_fs_info_guid.data1 == 0x09576e93U &&
			       cdk2_fat_volume_label_info_guid.data1 == 0xdb47d7d3U,
			   "stable202302 information GUID dispatch constants drifted");
	return failures == 0 ? 0 : 1;
}
