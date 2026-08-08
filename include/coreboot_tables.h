/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_COREBOOT_H_
#define CDK2_ABI_COREBOOT_H_

#include <uefi.h>

struct cbuint64 {
	UINT32 lo;
	UINT32 hi;
};

#define CB_HEADER_SIGNATURE 0x4f49424cU

struct cb_header {
	UINT32 signature;
	UINT32 header_bytes;
	UINT32 header_checksum;
	UINT32 table_bytes;
	UINT32 table_checksum;
	UINT32 table_entries;
};

struct cb_record {
	UINT32 tag;
	UINT32 size;
};

#define CB_TAG_MEMORY 0x0001U

struct cb_memory_range {
	struct cbuint64 start;
	struct cbuint64 size;
	UINT32 type;
};

#define CB_MEM_RAM      1U
#define CB_MEM_RESERVED 2U
#define CB_MEM_ACPI     3U
#define CB_MEM_NVS      4U
#define CB_MEM_UNUSABLE 5U
#define CB_MEM_TABLE    16U

struct cb_memory {
	UINT32 tag;
	UINT32 size;
	struct cb_memory_range map[];
};

#define CBMEM_ID_ACPI   SIGNATURE_32('I', 'P', 'C', 'A')
#define CBMEM_ID_SMBIOS SIGNATURE_32('T', 'B', 'M', 'S')

#define DYN_CBMEM_ALIGN_SIZE 4096U
#define IMD_ENTRY_MAGIC      (~0xc0389481U)
#define CBMEM_ENTRY_MAGIC    (~0xc0389479U)

struct cbmem_entry {
	UINT32 magic;
	UINT32 start;
	UINT32 size;
	UINT32 id;
};

struct cbmem_root {
	UINT32 max_entries;
	UINT32 num_entries;
	UINT32 locked;
	UINT32 size;
	struct cbmem_entry entries[];
};

struct imd_entry {
	UINT32 magic;
	UINT32 start_offset;
	UINT32 size;
	UINT32 id;
};

struct imd_root {
	UINT32 max_entries;
	UINT32 num_entries;
	UINT32 flags;
	UINT32 entry_align;
	UINT32 max_offset;
	struct imd_entry entries[];
};

#define CB_TAG_VERSION       0x0004U
#define CB_TAG_EXTRA_VERSION 0x0005U

struct cb_string {
	UINT32 tag;
	UINT32 size;
	UINT8 string[];
};

#define CB_TAG_SERIAL 0x000fU

#define CB_SERIAL_TYPE_IO_MAPPED     1U
#define CB_SERIAL_TYPE_MEMORY_MAPPED 2U

struct cb_serial {
	UINT32 tag;
	UINT32 size;
	UINT32 type;
	UINT32 baseaddr;
	UINT32 baud;
	UINT32 regwidth;
	UINT32 input_hertz;
	UINT32 uart_pci_addr;
};

#define CB_TAG_FORWARD 0x0011U

struct cb_forward {
	UINT32 tag;
	UINT32 size;
	UINT64 forward;
};

#define CB_TAG_FRAMEBUFFER 0x0012U

struct cb_framebuffer {
	UINT32 tag;
	UINT32 size;
	UINT64 physical_address;
	UINT32 x_resolution;
	UINT32 y_resolution;
	UINT32 bytes_per_line;
	UINT8 bits_per_pixel;
	UINT8 red_mask_pos;
	UINT8 red_mask_size;
	UINT8 green_mask_pos;
	UINT8 green_mask_size;
	UINT8 blue_mask_pos;
	UINT8 blue_mask_size;
	UINT8 reserved_mask_pos;
	UINT8 reserved_mask_size;
};

#define CB_TAG_CBMEM_ENTRY 0x0031U

struct cb_cbmem_entry {
	UINT32 tag;
	UINT32 size;
	struct cbuint64 address;
	UINT32 entry_size;
	UINT32 id;
} __packed;

#define CB_TAG_SMMSTOREV2 0x0039U

struct cb_smmstorev2 {
	UINT32 tag;
	UINT32 size;
	UINT32 num_blocks;
	UINT32 block_size;
	UINT32 mmap_addr;
	UINT32 com_buffer;
	UINT32 com_buffer_size;
	UINT8 apm_cmd;
	UINT8 unused[3];
} __packed;

#define CB_TAG_SMRAM 0x004cU

struct cb_smram {
	UINT32 tag;
	UINT32 size;
	UINT64 physical_start;
	UINT64 physical_size;
} __packed;

#define CB_TAG_SMM_REGISTER_INFO 0x004dU
#define CB_TAG_LOCAL_APIC_TIMER_INFO 0x004eU

struct cb_smm_generic_register {
	UINT64 id;
	UINT64 value;
	UINT8 address_space_id;
	UINT8 register_bit_width;
	UINT8 register_bit_offset;
	UINT8 access_size;
	UINT64 address;
} __packed;

struct cb_smm_register_info {
	UINT32 tag;
	UINT32 size;
	UINT16 revision;
	UINT16 reserved;
	UINT32 count;
	struct cb_smm_generic_register registers[];
} __packed;

struct cb_local_apic_timer_info {
	struct cb_record header;
	UINT16 revision;
	UINT16 reserved;
	UINT64 frequency_hz;
} __packed;

#define CB_TAG_TPM_PPI_HANDOFF 0x003aU

enum lb_tmp_ppi_tpm_version {
	LB_TPM_VERSION_UNSPEC = 0,
	LB_TPM_VERSION_TPM_VERSION_1_2,
	LB_TPM_VERSION_TPM_VERSION_2,
};

struct cb_tpm_physical_presence {
	UINT32 tag;
	UINT32 size;
	UINT32 ppi_address;
	UINT8 tpm_version;
	UINT8 ppi_version;
} __packed;

#define CB_TAG_ACPI_RSDP 0x0043U

struct cb_acpi_rsdp {
	UINT32 tag;
	UINT32 size;
	struct cbuint64 rsdp_pointer;
} __packed;

#define CB_TAG_FW_INFO 0x0045U

struct lb_efi_fw_info {
	UINT32 tag;
	UINT32 size;
	UINT8 guid[16];
	UINT32 version;
	UINT32 lowest_supported_version;
	UINT32 fw_size;
} __packed;

#define CB_TAG_CAPSULE 0x0046U

struct cb_range {
	UINT32 tag;
	UINT32 size;
	UINT64 range_start;
	UINT32 range_size;
} __packed;

#define CB_TAG_CFR_ROOT 0x0047U

struct cb_cfr {
	UINT32 tag;
	UINT32 size;
	UINT32 version;
	UINT32 checksum;
};

#define CB_TAG_PAYLOAD_RESOURCE_HANDOFF 0x004bU

#define CB_PAYLOAD_RESOURCE_HANDOFF_REVISION 2U

#define CB_PRH_SECTION_MEMORY_POLICY    1U
#define CB_PRH_SECTION_X86_CACHE_STATE  2U
#define CB_PRH_SECTION_PCI_ROOT_BRIDGES 3U
#define CB_PRH_SECTION_PCI_ASSIGNMENTS  4U
#define CB_PRH_SECTION_BOOT_INTENT      5U
#define CB_PRH_SECTION_RUNTIME_POLICY   6U
#define CB_PRH_SECTION_FRAMEBUFFER      7U

#define CB_PRH_SECTION_FLAG_MANDATORY     0x0001U
#define CB_PRH_SECTION_FLAG_AUTHORITATIVE 0x0002U
#define CB_PRH_SECTION_FLAG_VALID_MASK \
	(CB_PRH_SECTION_FLAG_MANDATORY | CB_PRH_SECTION_FLAG_AUTHORITATIVE)

#define CB_PRH_LIFETIME_COLD_BOOT          0x0000000000000001ULL
#define CB_PRH_LIFETIME_S3_RESUME          0x0000000000000002ULL
#define CB_PRH_LIFETIME_END_OF_DXE         0x0000000000000004ULL
#define CB_PRH_LIFETIME_EXIT_BOOT_SERVICES 0x0000000000000008ULL
#define CB_PRH_LIFETIME_RUNTIME            0x0000000000000010ULL
#define CB_PRH_LIFETIME_VALID_UNTIL_MASK \
	(CB_PRH_LIFETIME_END_OF_DXE | CB_PRH_LIFETIME_EXIT_BOOT_SERVICES | \
	 CB_PRH_LIFETIME_RUNTIME)
#define CB_PRH_LIFETIME_VALID_MASK \
	(CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_S3_RESUME | \
	 CB_PRH_LIFETIME_VALID_UNTIL_MASK)

#define CB_PRH_GCD_MEMORY_TYPE_NON_EXISTENT 0U
#define CB_PRH_GCD_MEMORY_TYPE_RESERVED     1U
#define CB_PRH_GCD_MEMORY_TYPE_SYSTEM       2U
#define CB_PRH_GCD_MEMORY_TYPE_MMIO         3U
#define CB_PRH_GCD_MEMORY_TYPE_PERSISTENT   4U
#define CB_PRH_GCD_MEMORY_TYPE_RELIABLE     5U
#define CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED   6U

#define CB_PRH_MEMORY_CACHE_AUTHORITATIVE      0x00000001U
#define CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE 0x00000002U
#define CB_PRH_MEMORY_GCD_AUTHORITATIVE        0x00000004U
#define CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE   0x00000008U
#define CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD     0x80000000U
#define CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK                                      \
	(CB_PRH_MEMORY_CACHE_AUTHORITATIVE | CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE | \
	 CB_PRH_MEMORY_GCD_AUTHORITATIVE | CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE |     \
	 CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD)

#define CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC 0x00000001U
#define CB_PRH_X86_CACHE_FLAG_S3_VALID    0x00000002U
#define CB_PRH_X86_CACHE_FLAG_FIXED_VALID 0x00000004U
#define CB_PRH_X86_CACHE_FLAG_VALID_MASK                                      \
	(CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC | CB_PRH_X86_CACHE_FLAG_S3_VALID | \
	 CB_PRH_X86_CACHE_FLAG_FIXED_VALID)

#define CB_PRH_PCI_RESOURCE_IO              1U
#define CB_PRH_PCI_RESOURCE_MMIO32          2U
#define CB_PRH_PCI_RESOURCE_MMIO64          3U
#define CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32 4U
#define CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64 5U

#define CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE 0x00000001U
#define CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED       0x80000000U
#define CB_PRH_FRAMEBUFFER_OWNER_FLAG_VALID_MASK \
	(CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE | CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED)

struct cb_payload_resource_section {
	UINT16 type;
	UINT16 flags;
	UINT16 header_length;
	UINT16 entry_size;
	UINT32 entry_count;
	UINT32 offset;
	UINT32 length;
} __packed;

struct cb_payload_resource_handoff {
	UINT32 tag;
	UINT32 size;
	UINT16 revision;
	UINT16 header_length;
	UINT16 section_header_length;
	UINT16 flags;
	UINT32 crc32;
	UINT32 section_count;
	UINT32 producer_stage;
	struct cbuint64 producer_generation;
	struct cbuint64 lifetime_flags;
	struct cb_payload_resource_section sections[];
} __packed;

struct cb_prh_memory_policy_entry {
	struct cbuint64 base;
	struct cbuint64 length;
	struct cbuint64 capabilities;
	struct cbuint64 attributes;
	UINT32 gcd_type;
	UINT32 efi_memory_type;
	UINT32 owner_flags;
	UINT32 reserved;
} __packed;

struct cb_prh_x86_cache_state {
	struct cbuint64 mtrr_default_type_msr;
	struct cbuint64 pat_msr;
	struct cbuint64 fixed_mtrr_crc64;
	UINT32 variable_count;
	UINT32 physical_address_bits;
	UINT32 flags;
	UINT32 reserved;
} __packed;

struct cb_prh_x86_variable_mtrr {
	struct cbuint64 phys_base_msr;
	struct cbuint64 phys_mask_msr;
} __packed;

struct cb_prh_pci_root_bridge_entry {
	UINT16 segment;
	UINT8 bus_start;
	UINT8 bus_end;
	UINT32 flags;
	struct cbuint64 io_base;
	struct cbuint64 io_length;
	struct cbuint64 mem32_base;
	struct cbuint64 mem32_length;
	struct cbuint64 mem64_base;
	struct cbuint64 mem64_length;
	struct cbuint64 pref_mem32_base;
	struct cbuint64 pref_mem32_length;
	struct cbuint64 pref_mem64_base;
	struct cbuint64 pref_mem64_length;
} __packed;

struct cb_prh_pci_assignment_entry {
	UINT16 segment;
	UINT8 bus;
	UINT8 device;
	UINT8 function;
	UINT8 bar;
	UINT8 resource_type;
	UINT8 flags;
	struct cbuint64 base;
	struct cbuint64 length;
	struct cbuint64 attributes;
} __packed;

struct cb_prh_framebuffer_entry {
	struct cbuint64 physical_address;
	struct cbuint64 size;
	UINT32 x_resolution;
	UINT32 y_resolution;
	UINT32 bytes_per_line;
	UINT8 bits_per_pixel;
	UINT8 red_mask_pos;
	UINT8 red_mask_size;
	UINT8 green_mask_pos;
	UINT8 green_mask_size;
	UINT8 blue_mask_pos;
	UINT8 blue_mask_size;
	UINT8 reserved_mask_pos;
	UINT8 reserved_mask_size;
	UINT8 reserved[3];
	UINT32 owner_flags;
} __packed;

#define CB_TAG_BOOT_INFO 0x00a1U

struct cb_boot_info {
	UINT32 tag;
	UINT32 size;
	UINT8 is_disk_capsules_boot;
	UINT8 pad[3];
} __packed;

#define CB_TAG_BOOT_MODE 0x00cdU

enum cb_boot_mode {
	LB_BOOT_MODE_NORMAL,
	LB_BOOT_MODE_LOW_BATTERY,
	LB_BOOT_MODE_LOW_BATTERY_CHARGING,
	LB_BOOT_MODE_OFFMODE_CHARGING,
	LB_BOOT_MODE_RTC_WAKE,
	LB_BOOT_MODE_NO_BATTERY,
	LB_BOOT_MODE_FLASH_UPDATE,
};

struct lb_boot_mode {
	UINT32 tag;
	UINT32 size;
	enum cb_boot_mode boot_mode;
} __packed;

#endif
