/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/scsi_bus.h>
#include <stdio.h>
static int calls;static void*last_event;
static EFI_STATUS pass(void*c,const UINT8*t,UINT64 l,struct cdk2_scsi_request*r,void*e)
{(void)c;(void)t;(void)l;(void)r;calls++;last_event=e;return EFI_SUCCESS;}
static EFI_STATUS reset(void*c){(void)c;calls++;return EFI_SUCCESS;}
static EFI_STATUS reset_target(void*c,const UINT8*t,UINT64 l){(void)c;(void)t;(void)l;calls++;return EFI_SUCCESS;}
static struct cdk2_scsi_target listed[2]={{{1},2},{{3},4}};static UINTN cursor;
static EFI_STATUS next(void*c,UINT8**t,UINT64*l){(void)c;if(cursor==2)return EFI_NOT_FOUND;
	*t=listed[cursor].id;*l=listed[cursor++].lun;return EFI_SUCCESS;}
static EFI_STATUS build(void*c,const UINT8*t,UINT64 l,void**p){(void)c;(void)t;(void)l;*p=(void*)1;return EFI_SUCCESS;}
static void release(void*c,void*p){(void)c;(void)p;}
static EFI_STATUS publish(void*c,struct cdk2_scsi_device*d,void*p){(void)c;(void)d;(void)p;return EFI_SUCCESS;}
static EFI_STATUS unpublish(void*c,struct cdk2_scsi_device*d,void*p){(void)c;(void)d;(void)p;return EFI_SUCCESS;}
static int ck(int c,const char*m){if(!c)fprintf(stderr,"scsi: %s\n",m);return !c;}
int main(void){struct cdk2_scsi_backend b={.io_align=8,.pass=pass,.reset_bus=reset,
	.reset_target=reset_target,.next=next,.build_path=build,.release_path=release};
	struct cdk2_scsi_target t={{1},7},other={{1},7};struct cdk2_scsi_device d;
	struct cdk2_scsi_device devices[2];void *paths[2];
	struct cdk2_scsi_bus bus={b,devices,paths,2,0,NULL,publish,unpublish};
	UINT8 cdb[16]={0};struct cdk2_scsi_request r={.cdb=cdb,.cdb_length=16};int f=0;
	f+=ck(cdk2_scsi_device_init(&d,&b,&t,0)==EFI_SUCCESS,"init");
	f+=ck(cdk2_scsi_target_equal(&t,&other),"target equality");
	f+=ck(cdk2_scsi_execute(&d,&r,(void*)1)==EFI_SUCCESS&&last_event==NULL,"blocking downgrade");
	d.backend.attributes=1;f+=ck(cdk2_scsi_execute(&d,&r,(void*)1)==EFI_SUCCESS&&last_event==(void*)1,"nonblocking event");
	r.cdb_length=17;f+=ck(cdk2_scsi_execute(&d,&r,NULL)==EFI_INVALID_PARAMETER,"CDB bound");
	f+=ck(cdk2_scsi_reset_bus(&d)==EFI_SUCCESS&&cdk2_scsi_reset_device(&d)==EFI_SUCCESS,"reset delegation");
	f+=ck(cdk2_scsi_enumerate(&bus,NULL)==EFI_SUCCESS&&bus.count==2,"target iteration");
	f+=ck(cdk2_scsi_remove_all(&bus)==EFI_SUCCESS&&bus.count==0,"reverse teardown");return f!=0;}
