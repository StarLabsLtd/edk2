/** @file
  Coreboot PEI module include file.

  Copyright (c) 2014 - 2015, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

/*
 * This file is part of the libpayload project.
 *
 * Copyright (C) 2008 Advanced Micro Devices, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _COREBOOT_PEI_H_INCLUDED_
#define _COREBOOT_PEI_H_INCLUDED_

#if defined (_MSC_VER)
  #pragma warning( disable : 4200 )
#endif

#define DYN_CBMEM_ALIGN_SIZE  (4096)

#define IMD_ENTRY_MAGIC    (~0xC0389481)
#define CBMEM_ENTRY_MAGIC  (~0xC0389479)

struct cbmem_entry {
  UINT32    magic;
  UINT32    start;
  UINT32    size;
  UINT32    id;
};

struct cbmem_root {
  UINT32                max_entries;
  UINT32                num_entries;
  UINT32                locked;
  UINT32                size;
  struct cbmem_entry    entries[0];
};

struct imd_entry {
  UINT32    magic;
  UINT32    start_offset;
  UINT32    size;
  UINT32    id;
};

struct imd_root {
  UINT32              max_entries;
  UINT32              num_entries;
  UINT32              flags;
  UINT32              entry_align;
  UINT32              max_offset;
  struct imd_entry    entries[0];
};

struct cbuint64 {
  UINT32    lo;
  UINT32    hi;
};

#define CB_HEADER_SIGNATURE  0x4F49424C

struct cb_header {
  UINT32    signature;
  UINT32    header_bytes;
  UINT32    header_checksum;
  UINT32    table_bytes;
  UINT32    table_checksum;
  UINT32    table_entries;
};

struct cb_record {
  UINT32    tag;
  UINT32    size;
};

#define CB_TAG_UNUSED  0x0000
#define CB_TAG_MEMORY  0x0001

struct cb_memory_range {
  struct cbuint64    start;
  struct cbuint64    size;
  UINT32             type;
};

#define CB_MEM_RAM          1
#define CB_MEM_RESERVED     2
#define CB_MEM_ACPI         3
#define CB_MEM_NVS          4
#define CB_MEM_UNUSABLE     5
#define CB_MEM_VENDOR_RSVD  6
#define CB_MEM_TABLE        16

struct cb_memory {
  UINT32                    tag;
  UINT32                    size;
  struct cb_memory_range    map[0];
};

#define CB_TAG_MAINBOARD  0x0003

struct cb_mainboard {
  UINT32    tag;
  UINT32    size;
  UINT8     vendor_idx;
  UINT8     part_number_idx;
  UINT8     strings[0];
};

#define CB_TAG_VERSION         0x0004
#define CB_TAG_EXTRA_VERSION   0x0005
#define CB_TAG_BUILD           0x0006
#define CB_TAG_COMPILE_TIME    0x0007
#define CB_TAG_COMPILE_BY      0x0008
#define CB_TAG_COMPILE_HOST    0x0009
#define CB_TAG_COMPILE_DOMAIN  0x000a
#define CB_TAG_COMPILER        0x000b
#define CB_TAG_LINKER          0x000c
#define CB_TAG_ASSEMBLER       0x000d

struct cb_string {
  UINT32    tag;
  UINT32    size;
  UINT8     string[0];
};

#define CB_TAG_SERIAL  0x000f

struct cb_serial {
  UINT32    tag;
  UINT32    size;
  #define CB_SERIAL_TYPE_IO_MAPPED      1
  #define CB_SERIAL_TYPE_MEMORY_MAPPED  2
  UINT32    type;
  UINT32    baseaddr;
  UINT32    baud;
  UINT32    regwidth;

  // Crystal or input frequency to the chip containing the UART.
  // Provide the board specific details to allow the payload to
  // initialize the chip containing the UART and make independent
  // decisions as to which dividers to select and their values
  // to eventually arrive at the desired console baud-rate.
  UINT32    input_hertz;

  // UART PCI address: bus, device, function
  // 1 << 31 - Valid bit, PCI UART in use
  // Bus << 20
  // Device << 15
  // Function << 12
  UINT32    uart_pci_addr;
};

#define CB_TAG_CONSOLE  0x00010

struct cb_console {
  UINT32    tag;
  UINT32    size;
  UINT16    type;
};

#define CB_TAG_CONSOLE_SERIAL8250  0
#define CB_TAG_CONSOLE_VGA         1 // OBSOLETE
#define CB_TAG_CONSOLE_BTEXT       2 // OBSOLETE
#define CB_TAG_CONSOLE_LOGBUF      3
#define CB_TAG_CONSOLE_SROM        4// OBSOLETE
#define CB_TAG_CONSOLE_EHCI        5

#define CB_TAG_FORWARD  0x00011

struct cb_forward {
  UINT32    tag;
  UINT32    size;
  UINT64    forward;
};

struct cb_cbmem_ref {
  UINT32    tag;
  // Field contains size of this struct == 0x0010
  UINT32    size;
  UINT64    cbmem_addr;
};

#define CB_TAG_FRAMEBUFFER  0x0012
struct cb_framebuffer {
  UINT32    tag;
  UINT32    size;

  UINT64    physical_address;
  UINT32    x_resolution;
  UINT32    y_resolution;
  UINT32    bytes_per_line;
  UINT8     bits_per_pixel;
  UINT8     red_mask_pos;
  UINT8     red_mask_size;
  UINT8     green_mask_pos;
  UINT8     green_mask_size;
  UINT8     blue_mask_pos;
  UINT8     blue_mask_size;
  UINT8     reserved_mask_pos;
  UINT8     reserved_mask_size;
};

#define CB_TAG_ACPI_RSDP  0x0043
struct cb_acpi_rsdp {
  UINT32             tag;
  UINT32             size;
  struct cbuint64    rsdp_pointer;
} __attribute__ ((packed));

#define CB_TAG_VDAT  0x0015
struct cb_vdat {
  UINT32    tag;
  UINT32    size; /* size of the entire entry */
  UINT64    vdat_addr;
  UINT32    vdat_size;
};

#define CB_TAG_TIMESTAMPS     0x0016
#define CB_TAG_CBMEM_CONSOLE  0x0017

#define CB_TAG_CBMEM_ENTRY    0x0031
#define CB_TAG_TSC_INFO       0x0032

#define CBMEM_ID_CONSOLE      0x434F4E53
#define CBMEM_ID_TIMESTAMP    0x54494D45

struct cb_timestamp_entry {
  UINT32    entry_id;
  INT64     entry_stamp;
} __attribute__ ((packed));

struct cb_timestamp_table {
  UINT64                    base_time;
  UINT16                    max_entries;
  UINT16                    tick_freq_mhz;
  UINT32                    num_entries;
  struct cb_timestamp_entry entries[0];
} __attribute__ ((packed));

struct cb_cbmem_entry {
  UINT32          tag;
  UINT32          size;
  struct cbuint64 address;
  UINT32          entry_size;
  UINT32          id;
} __attribute__ ((packed));

struct cb_tsc_info {
  UINT32          tag;
  UINT32          size;
  UINT32          freq_khz;
} __attribute__ ((packed));

struct cbmem_console {
  UINT32    size;
  UINT32    cursor;
  UINT8     body[0];
} __attribute__ ((packed));

#define CB_TAG_MRC_CACHE  0x0018
struct cb_cbmem_tab {
  UINT32    tag;
  UINT32    size;
  UINT64    cbmem_tab;
};

#define CB_TAG_SMMSTOREV2  0x0039
struct cb_smmstorev2 {
  UINT32    tag;
  UINT32    size;
  UINT32    num_blocks;      /* Number of writeable blocks in the store */
  UINT32    block_size;      /* Size of a block in bytes (64 KiB by default) */
  UINT32    mmap_addr;       /* MMIO address of the store for read-only access */
  UINT32    com_buffer;      /* Physical address of the communication buffer */
  UINT32    com_buffer_size; /* Size of the communication buffer in bytes */
  UINT8     apm_cmd;         /* The command byte to write to the APM I/O port to
                                communicate with the store */
  UINT8     unused[3];       /* Set to zero */
} __attribute__ ((packed));

/*
 * Machine-friendly version of a system firmware component.  A component is
 * identified by a GUID.  coreboot is an obvious main component but there could
 * be others (like EC) which should get their own instances of the tag.
 *
 * The main consumer of this information is UEFI firmware but something else
 * could reuse it too.
 *
 * Larger number in a version field corresponds to a more recent version.
 */
#define CB_TAG_FW_INFO  0x0045
struct lb_efi_fw_info {
  UINT32    tag;
  UINT32    size;
  UINT8     guid[16];                 /* Called "firmware class" in UEFI */
  UINT32    version;                  /* Current version */
  UINT32    lowest_supported_version; /* Lowest allowed version */
  UINT32    fw_size;                  /* Size of firmware in bytes */
} __attribute__ ((packed));

#define CB_TAG_CAPSULE  0x0046
struct cb_range {
  UINT32    tag;
  UINT32    size;
  UINT64    range_start;
  UINT32    range_size;
} __attribute__ ((packed));

#define CB_TAG_BOOT_INFO  0x00a1
struct cb_boot_info {
  UINT32    tag;
  UINT32    size;
  UINT8     is_disk_capsules_boot;
  UINT8     pad[3];
} __attribute__ ((packed));

#define CB_TAG_CFR_ROOT  0x0047
struct cb_cfr {
  UINT32 tag;
  UINT32 size;
  UINT32 version;
  UINT32 checksum;  /* Of the following data only; excludes these 4 fields */
  /* CFR_FORM forms[] */
};

#define CB_TAG_PAYLOAD_RESOURCE_HANDOFF  0x004b

#define CB_PAYLOAD_RESOURCE_HANDOFF_REVISION  2

#define CB_PRH_SECTION_MEMORY_POLICY       1
#define CB_PRH_SECTION_X86_CACHE_STATE     2
#define CB_PRH_SECTION_PCI_ROOT_BRIDGES    3
#define CB_PRH_SECTION_PCI_ASSIGNMENTS     4
#define CB_PRH_SECTION_BOOT_INTENT         5
#define CB_PRH_SECTION_RUNTIME_POLICY      6
#define CB_PRH_SECTION_FRAMEBUFFER         7

#define CB_PRH_SECTION_FLAG_MANDATORY       0x0001
#define CB_PRH_SECTION_FLAG_AUTHORITATIVE   0x0002
#define CB_PRH_SECTION_FLAG_VALID_MASK      \
  (CB_PRH_SECTION_FLAG_MANDATORY | CB_PRH_SECTION_FLAG_AUTHORITATIVE)

#define CB_PRH_LIFETIME_COLD_BOOT           0x0000000000000001ULL
#define CB_PRH_LIFETIME_S3_RESUME           0x0000000000000002ULL
#define CB_PRH_LIFETIME_END_OF_DXE          0x0000000000000004ULL
#define CB_PRH_LIFETIME_EXIT_BOOT_SERVICES  0x0000000000000008ULL
#define CB_PRH_LIFETIME_RUNTIME             0x0000000000000010ULL
#define CB_PRH_LIFETIME_VALID_UNTIL_MASK    \
  (CB_PRH_LIFETIME_END_OF_DXE | CB_PRH_LIFETIME_EXIT_BOOT_SERVICES | \
   CB_PRH_LIFETIME_RUNTIME)
#define CB_PRH_LIFETIME_VALID_MASK          \
  (CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_S3_RESUME | \
   CB_PRH_LIFETIME_VALID_UNTIL_MASK)

#define CB_PRH_GCD_MEMORY_TYPE_NON_EXISTENT  0
#define CB_PRH_GCD_MEMORY_TYPE_RESERVED      1
#define CB_PRH_GCD_MEMORY_TYPE_SYSTEM        2
#define CB_PRH_GCD_MEMORY_TYPE_MMIO          3
#define CB_PRH_GCD_MEMORY_TYPE_PERSISTENT    4
#define CB_PRH_GCD_MEMORY_TYPE_RELIABLE      5
#define CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED    6

#define CB_PRH_MEMORY_CACHE_AUTHORITATIVE       0x00000001
#define CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE  0x00000002
#define CB_PRH_MEMORY_GCD_AUTHORITATIVE         0x00000004
#define CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE    0x00000008
#define CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD      0x80000000
#define CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK     \
  (CB_PRH_MEMORY_CACHE_AUTHORITATIVE | \
   CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE | \
   CB_PRH_MEMORY_GCD_AUTHORITATIVE | \
   CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE | \
   CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD)

#define CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC       0x00000001
#define CB_PRH_X86_CACHE_FLAG_S3_VALID          0x00000002
#define CB_PRH_X86_CACHE_FLAG_FIXED_VALID       0x00000004
#define CB_PRH_X86_CACHE_FLAG_VALID_MASK        \
  (CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC | \
   CB_PRH_X86_CACHE_FLAG_S3_VALID | \
   CB_PRH_X86_CACHE_FLAG_FIXED_VALID)

#define CB_PRH_PCI_RESOURCE_IO              1
#define CB_PRH_PCI_RESOURCE_MMIO32          2
#define CB_PRH_PCI_RESOURCE_MMIO64          3
#define CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32 4
#define CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64 5

#define CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE  0x00000001
#define CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED        0x80000000
#define CB_PRH_FRAMEBUFFER_OWNER_FLAG_VALID_MASK   \
  (CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE | \
   CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED)

struct cb_payload_resource_section {
  UINT16 type;
  UINT16 flags;
  UINT16 header_length;
  UINT16 entry_size;
  UINT32 entry_count;
  UINT32 offset;
  UINT32 length;
} __attribute__ ((packed));

struct cb_payload_resource_handoff {
  UINT32                         tag;
  UINT32                         size;
  UINT16                         revision;
  UINT16                         header_length;
  UINT16                         section_header_length;
  UINT16                         flags;
  UINT32                         crc32;
  UINT32                         section_count;
  UINT32                         producer_stage;
  struct cbuint64                producer_generation;
  struct cbuint64                lifetime_flags;
  struct cb_payload_resource_section sections[0];
} __attribute__ ((packed));

struct cb_prh_memory_policy_entry {
  struct cbuint64 base;
  struct cbuint64 length;
  struct cbuint64 capabilities;
  struct cbuint64 attributes;
  UINT32          gcd_type;
  UINT32          efi_memory_type;
  UINT32          owner_flags;
  UINT32          reserved;
} __attribute__ ((packed));

struct cb_prh_x86_cache_state {
  struct cbuint64 mtrr_default_type_msr;
  struct cbuint64 pat_msr;
  struct cbuint64 fixed_mtrr_crc64;
  UINT32          variable_count;
  UINT32          physical_address_bits;
  UINT32          flags;
  UINT32          reserved;
  /* struct cb_prh_x86_variable_mtrr variable[] */
} __attribute__ ((packed));

struct cb_prh_x86_variable_mtrr {
  struct cbuint64 phys_base_msr;
  struct cbuint64 phys_mask_msr;
} __attribute__ ((packed));

struct cb_prh_pci_root_bridge_entry {
  UINT16          segment;
  UINT8           bus_start;
  UINT8           bus_end;
  UINT32          flags;
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
} __attribute__ ((packed));

struct cb_prh_pci_assignment_entry {
  UINT16          segment;
  UINT8           bus;
  UINT8           device;
  UINT8           function;
  UINT8           bar;
  UINT8           resource_type;
  UINT8           flags;
  struct cbuint64 base;
  struct cbuint64 length;
  struct cbuint64 attributes;
} __attribute__ ((packed));

struct cb_prh_framebuffer_entry {
  struct cbuint64 physical_address;
  struct cbuint64 size;
  UINT32          x_resolution;
  UINT32          y_resolution;
  UINT32          bytes_per_line;
  UINT8           bits_per_pixel;
  UINT8           red_mask_pos;
  UINT8           red_mask_size;
  UINT8           green_mask_pos;
  UINT8           green_mask_size;
  UINT8           blue_mask_pos;
  UINT8           blue_mask_size;
  UINT8           reserved_mask_pos;
  UINT8           reserved_mask_size;
  UINT8           reserved[3];
  UINT32          owner_flags;
} __attribute__ ((packed));

/* Helpful macros */

#define MEM_RANGE_COUNT(_rec) \
  (((_rec)->size - sizeof(*(_rec))) / sizeof((_rec)->map[0]))

#define MEM_RANGE_PTR(_rec, _idx) \
  (void *)(((UINT8 *) (_rec)) + sizeof(*(_rec)) \
    + (sizeof((_rec)->map[0]) * (_idx)))

typedef struct cb_memory CB_MEMORY;

#define CB_TAG_BOOT_MODE  0x00cd

enum cb_boot_mode {
  /* Regular boot scenarios */
  LB_BOOT_MODE_NORMAL,
  /* Device is booting in low-batter w/o charger attached */
  LB_BOOT_MODE_LOW_BATTERY,
  /* Device is booting in low-batter w/ charger attached */
  LB_BOOT_MODE_LOW_BATTERY_CHARGING,
  /* Device is booting in due to charger insertion */
  LB_BOOT_MODE_OFFMODE_CHARGING,
  /* Device is booting in due to RTC alarm */
  LB_BOOT_MODE_RTC_WAKE,
  /* Device is booting in "no-battery" */
  LB_BOOT_MODE_NO_BATTERY,
  /* Device is booting with flash unlocked. */
  LB_BOOT_MODE_FLASH_UPDATE,
};

/*
 * Boot Mode: Passed the platform boot mode information to payload.
 */
struct lb_boot_mode {
  UINT32               tag;
  UINT32               size;
  enum cb_boot_mode    boot_mode;
} __attribute__ ((packed));

#define CB_TAG_TPM_PPI_HANDOFF       0x003a

enum lb_tmp_ppi_tpm_version {
  LB_TPM_VERSION_UNSPEC = 0,
  LB_TPM_VERSION_TPM_VERSION_1_2,
  LB_TPM_VERSION_TPM_VERSION_2,
};

/*
 * Handoff buffer for TPM Physical Presence Interface.
 * * ppi_address   Pointer to PPI buffer shared with ACPI
 *                 The layout of the buffer matches the QEMU virtual memory device
 *                 that is generated by QEMU.
 *                 See files 'hw/i386/acpi-build.c' and 'include/hw/acpi/tpm.h'
 *                 for details.
 * * tpm_version   TPM version: 1 for TPM1.2, 2 for TPM2.0
 * * ppi_version   BCD encoded version of TPM PPI interface
 */
struct cb_tpm_physical_presence {
  UINT32 tag;
  UINT32 size;
  UINT32 ppi_address;  /* Address of ACPI PPI communication buffer */
  UINT8 tpm_version;  /* 1: TPM1.2, 2: TPM2.0 */
  UINT8 ppi_version;  /* BCD encoded */
} __attribute__((packed));

#endif // _COREBOOT_PEI_H_INCLUDED_
