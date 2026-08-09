/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/fat_binding.h>

#define FAT_ALREADY_STARTED EFIERR(20)
#define FAT_VOLUME_CORRUPTED EFIERR(10)
#define FAT_NO_MEDIA EFIERR(12)
#define FAT_ACCESS_DENIED EFIERR(15)
#define FAT_NOT_STARTED EFIERR(19)

const EFI_GUID cdk2_fat_block_io_guid = { 0x964e5b21U, 0x6459U, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
const EFI_GUID cdk2_fat_disk_io_guid = { 0xce345171U, 0xba0bU, 0x11d2U,
	{ 0x8eU, 0x4fU, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };
const EFI_GUID cdk2_fat_simple_fs_guid = { 0x964e5b22U, 0x6459U, 0x11d2U,
	{ 0x8eU, 0x39U, 0x00U, 0xa0U, 0xc9U, 0x69U, 0x72U, 0x3bU } };

EFI_STATUS cdk2_fat_complete_io(const struct cdk2_fat_binding *binding,
	struct cdk2_fat_io_token *token, EFI_STATUS status)
{
	EFI_STATUS signal_status;
	if (token == NULL)
		return status;
	token->transaction_status = status;
	if (token->event == NULL)
		return status;
	if (binding == NULL || binding->ops == NULL || binding->ops->signal == NULL)
		return EFI_INVALID_PARAMETER;
	signal_status = binding->ops->signal(binding->context, token->event);
	return EFI_ERROR(signal_status) ? signal_status : EFI_SUCCESS;
}

static uint64_t read_disk(void *context, uint64_t offset, size_t size,
	void *buffer)
{
	struct cdk2_fat_mount *mount = context;
	return mount->disk->read_disk(mount->disk, mount->media_id, offset, size,
		buffer);
}

static struct cdk2_fat_mount *find_mount(struct cdk2_fat_binding *binding,
	void *controller)
{
	struct cdk2_fat_mount *mount;
	for (mount = binding->mounts; mount != NULL; mount = mount->next)
		if (mount->controller == controller)
			return mount;
	return NULL;
}

EFI_STATUS cdk2_fat_binding_refresh(struct cdk2_fat_mount *mount)
{
	EFI_STATUS status;
	uint64_t size;
	if (mount == NULL || mount->block == NULL || mount->block->media == NULL ||
	    mount->disk == NULL)
		return EFI_INVALID_PARAMETER;
	if (!mount->block->media->media_present)
		return FAT_NO_MEDIA;
	if (mount->block->media->block_size == 0U ||
	    mount->block->media->last_block == UINT64_MAX)
		return FAT_VOLUME_CORRUPTED;
	size = (mount->block->media->last_block + 1U) *
		mount->block->media->block_size;
	if (size / mount->block->media->block_size !=
	    mount->block->media->last_block + 1U)
		return FAT_VOLUME_CORRUPTED;
	mount->media_id = mount->block->media->media_id;
	status = cdk2_fat_probe(&mount->volume, read_disk, mount, size);
	if (!EFI_ERROR(status)) {
		mount->volume.read_only = mount->block->media->read_only;
		mount->volume.write_protected = mount->block->media->read_only;
	}
	return status;
}

EFI_STATUS cdk2_fat_binding_start(struct cdk2_fat_binding *binding,
	void *controller)
{
	struct cdk2_fat_mount *mount = NULL;
	EFI_STATUS status;
	if (binding == NULL || binding->ops == NULL || controller == NULL ||
	    binding->ops->open == NULL || binding->ops->close == NULL ||
	    binding->ops->publish == NULL || binding->ops->allocate == NULL ||
	    binding->ops->release == NULL)
		return EFI_INVALID_PARAMETER;
	if (find_mount(binding, controller) != NULL)
		return FAT_ALREADY_STARTED;
	status = binding->ops->allocate(binding->context, sizeof(*mount),
		(void **)&mount);
	if (EFI_ERROR(status))
		return status;
	__builtin_memset(mount, 0, sizeof(*mount)); mount->controller = controller;
	status = binding->ops->open(binding->context, controller,
		&cdk2_fat_block_io_guid, (void **)&mount->block);
	if (EFI_ERROR(status))
		goto release;
	status = binding->ops->open(binding->context, controller,
		&cdk2_fat_disk_io_guid, (void **)&mount->disk);
	if (EFI_ERROR(status))
		goto close_retained_block;
	status = cdk2_fat_binding_refresh(mount);
	if (EFI_ERROR(status))
		goto close_disk;
	status = binding->ops->publish(binding->context, controller,
		&cdk2_fat_simple_fs_guid, mount);
	if (EFI_ERROR(status))
		goto close_disk;
	mount->published = 1U; mount->next = binding->mounts;
	binding->mounts = mount;
	return EFI_SUCCESS;
close_disk:
	(void)binding->ops->close(binding->context, controller,
		&cdk2_fat_disk_io_guid);
close_retained_block:
	(void)binding->ops->close(binding->context, controller,
		&cdk2_fat_block_io_guid);
release:
	binding->ops->release(binding->context, mount);
	return status;
}

EFI_STATUS cdk2_fat_binding_stop(struct cdk2_fat_binding *binding,
	void *controller)
{
	struct cdk2_fat_mount **link, *mount;
	EFI_STATUS status;
	if (binding == NULL || binding->ops == NULL)
		return EFI_INVALID_PARAMETER;
	for (link = &binding->mounts; *link != NULL; link = &(*link)->next)
		if ((*link)->controller == controller)
			break;
	if (*link == NULL)
		return FAT_NOT_STARTED;
	mount = *link;
	if (mount->open_handles != 0U)
		return FAT_ACCESS_DENIED;
	status = binding->ops->unpublish(binding->context, controller,
		&cdk2_fat_simple_fs_guid, mount);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->close(binding->context, controller,
		&cdk2_fat_disk_io_guid);
	if (EFI_ERROR(status)) {
		(void)binding->ops->publish(binding->context, controller,
			&cdk2_fat_simple_fs_guid, mount);
		return status;
	}
	status = binding->ops->close(binding->context, controller,
		&cdk2_fat_block_io_guid);
	if (EFI_ERROR(status)) {
		(void)binding->ops->open(binding->context, controller,
			&cdk2_fat_disk_io_guid, (void **)&mount->disk);
		(void)binding->ops->publish(binding->context, controller,
			&cdk2_fat_simple_fs_guid, mount);
		return status;
	}
	*link = mount->next; binding->ops->release(binding->context, mount);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_fat_binding_open_handle(struct cdk2_fat_mount *mount)
{
	EFI_STATUS status;
	if (mount == NULL)
		return EFI_INVALID_PARAMETER;
	if (mount->block->media->media_id != mount->media_id) {
		if (mount->open_handles != 0U)
			return CDK2_FAT_MEDIA_CHANGED;
		status = cdk2_fat_binding_refresh(mount);
		if (EFI_ERROR(status))
			return status;
	}
	mount->open_handles++;
	return EFI_SUCCESS;
}

void cdk2_fat_binding_close_handle(struct cdk2_fat_mount *mount)
{
	if (mount != NULL && mount->open_handles != 0U)
		mount->open_handles--;
}
