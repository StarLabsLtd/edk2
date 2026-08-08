/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include <cdk2/scsi_bus.h>
BOOLEAN cdk2_scsi_target_equal(const struct cdk2_scsi_target *left,
	const struct cdk2_scsi_target *right)
{
	UINTN index;
	if (left == NULL || right == NULL || left->lun != right->lun)
		return FALSE;
	for (index = 0; index < CDK2_SCSI_TARGET_MAX; index++)
		if (left->id[index] != right->id[index])
			return FALSE;
	return TRUE;
}
EFI_STATUS cdk2_scsi_device_init(struct cdk2_scsi_device *device,
	const struct cdk2_scsi_backend *backend,const struct cdk2_scsi_target *target,
	UINT8 device_type)
{ if(device==NULL||backend==NULL||target==NULL||backend->pass==NULL||
	backend->reset_bus==NULL||backend->reset_target==NULL)return EFI_INVALID_PARAMETER;
	device->backend=*backend;device->location=*target;device->device_type=device_type;return EFI_SUCCESS; }
EFI_STATUS cdk2_scsi_get_location(const struct cdk2_scsi_device *device,
	UINT8 **target,UINT64 *lun)
{ if(device==NULL||target==NULL||lun==NULL)return EFI_INVALID_PARAMETER;
	*target=(UINT8 *)device->location.id;*lun=device->location.lun;return EFI_SUCCESS; }
EFI_STATUS cdk2_scsi_reset_bus(struct cdk2_scsi_device *device)
{ return device==NULL?EFI_INVALID_PARAMETER:device->backend.reset_bus(device->backend.interface); }
EFI_STATUS cdk2_scsi_reset_device(struct cdk2_scsi_device *device)
{ return device==NULL?EFI_INVALID_PARAMETER:device->backend.reset_target(device->backend.interface,
	device->location.id,device->location.lun); }
EFI_STATUS cdk2_scsi_execute(struct cdk2_scsi_device *device,
	struct cdk2_scsi_request *request,void *event)
{ if(device==NULL||request==NULL||request->cdb==NULL||request->cdb_length==0U||
	request->cdb_length>16U||request->data_direction>2U||
	(request->in_length!=0U&&request->in_data==NULL)||
	(request->out_length!=0U&&request->out_data==NULL))return EFI_INVALID_PARAMETER;
	if((device->backend.attributes&1U)==0U)event=NULL;
	return device->backend.pass(device->backend.interface,device->location.id,
		device->location.lun,request,event); }
