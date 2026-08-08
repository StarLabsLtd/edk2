/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <string.h>
#include <cdk2/ftw_pi.h>

static UINT8 admitted_workspace[0x10000];
static const UINT8 admitted_clean_header[32] = {
	0x2b, 0x29, 0x58, 0x9e, 0x68, 0x7c, 0x7d, 0x49,
	0xa0, 0xce, 0x65, 0x00, 0xfd, 0x9f, 0x1b, 0x95,
	0xf5, 0x95, 0x52, 0x00, 0xfe, 0xff, 0xff, 0xff,
	0xe0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

int main(void)
{
	UINT8 workspace[512]; struct cdk2_ftw_journal in = { 0 }, out;
	unsigned index;
	const struct cdk2_ftw_pi_work_header *wh; const struct cdk2_ftw_pi_write_header *h;
	const struct cdk2_ftw_pi_record *r;
	assert(cdk2_ftw_pi_initialize(admitted_workspace,
		sizeof(admitted_workspace))==EFI_SUCCESS);
	assert(!memcmp(admitted_workspace,admitted_clean_header,
		sizeof(admitted_clean_header)));
	assert(cdk2_ftw_pi_initialize(workspace,sizeof(workspace))==EFI_SUCCESS);
	wh=(const void*)workspace;
	assert(wh->signature.data1==0x9e58292b && wh->state==0xfe &&
		wh->write_queue_size==sizeof(workspace)-sizeof(*wh));
	in.magic=CDK2_FTW_MAGIC;in.caller_id.data1=0x1234;in.write_count=1;
	in.private_size=2;in.phase=CDK2_FTW_SPARE_COMPLETE;
	in.records[0]=(struct cdk2_ftw_record){.lba=7,.offset=8,.length=9,
		.relative_offset=-0x1000,.private_size=2,.phase=CDK2_FTW_SPARE_COMPLETE,
		.private_data={0xaa,0xbb}};
	assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
	h=(const void*)(workspace+sizeof(*wh));r=(const void*)(h+1);
	assert(h->state==0xfc&&h->number_of_writes==1&&r->state==0xfd&&
		r->relative_offset==-0x1000&&((const UINT8*)(r+1))[1]==0xbb);
	assert(cdk2_ftw_pi_decode(workspace,sizeof(workspace),&out)==EFI_SUCCESS&&
		out.phase==CDK2_FTW_SPARE_COMPLETE&&out.records[0].lba==7&&
		out.records[0].relative_offset==-0x1000);
	in.records[0].lba=15;
	assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_WRITE_PROTECTED);
	in.records[0].lba=7;
	in.phase=CDK2_FTW_ALLOCATED;in.records[0].phase=CDK2_FTW_DESTINATION_COMPLETE;
	assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
	assert(cdk2_ftw_pi_decode(workspace,sizeof(workspace),&out)==EFI_SUCCESS&&
		out.phase==CDK2_FTW_BATCH_COMPLETE);
	in.phase=CDK2_FTW_BATCH_COMPLETE;
	assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
	assert(h->state==0xf8&&r->state==0xf9);
	assert(cdk2_ftw_pi_decode(workspace,sizeof(workspace),&out)==EFI_SUCCESS&&
		out.phase==CDK2_FTW_EMPTY);
	/* Completed queue entries are skipped; reclaim retains the active entry. */
	for(index=1;index<9;index++){
		in.caller_id.data1=0x2000+index;in.phase=CDK2_FTW_SPARE_COMPLETE;
		in.records[0].phase=CDK2_FTW_SPARE_COMPLETE;
		assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
		in.phase=CDK2_FTW_BATCH_COMPLETE;
		in.records[0].phase=CDK2_FTW_DESTINATION_COMPLETE;
		assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
	}
	in.caller_id.data1=0x3000;in.phase=CDK2_FTW_SPARE_COMPLETE;
	in.records[0].phase=CDK2_FTW_SPARE_COMPLETE;
	assert(cdk2_ftw_pi_encode(workspace,sizeof(workspace),&in)==EFI_SUCCESS);
	assert(cdk2_ftw_pi_decode(workspace,sizeof(workspace),&out)==EFI_SUCCESS&&
		out.caller_id.data1==0x3000&&out.phase==CDK2_FTW_SPARE_COMPLETE);
	workspace[0]^=1;assert(cdk2_ftw_pi_decode(workspace,sizeof(workspace),&out)==EFI_VOLUME_CORRUPTED);
	return 0;
}
