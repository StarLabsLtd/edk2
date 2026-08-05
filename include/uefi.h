/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_UEFI_H_
#define CDK2_ABI_UEFI_H_

#include <stddef.h>
#include <stdint.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef uint8_t BOOLEAN;
typedef int8_t INT8;
typedef uint8_t UINT8;
typedef int16_t INT16;
typedef uint16_t UINT16;
typedef int32_t INT32;
typedef uint32_t UINT32;
typedef long long INT64;
typedef unsigned long long UINT64;
typedef unsigned long long UINTN;
typedef long long INTN;
typedef char CHAR8;
typedef uint16_t CHAR16;
typedef void VOID;

typedef UINTN EFI_STATUS;
typedef UINT64 EFI_PHYSICAL_ADDRESS;
typedef UINT64 EFI_VIRTUAL_ADDRESS;

typedef struct {
	UINT32 data1;
	UINT16 data2;
	UINT16 data3;
	UINT8 data4[8];
} EFI_GUID;
typedef EFI_GUID GUID;

#ifndef TRUE
#define TRUE ((BOOLEAN)1)
#endif
#ifndef FALSE
#define FALSE ((BOOLEAN)0)
#endif

#define EFIAPI
#define IN
#define OUT
#define OPTIONAL
#define CONST const
#define STATIC static

#if defined(__GNUC__)
#ifndef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#endif
#ifndef __noreturn
#define __noreturn __attribute__((__noreturn__))
#endif
#ifndef __packed
#define __packed __attribute__((__packed__))
#endif
#ifndef __section
#define __section(section) __attribute__((__section__(section)))
#endif
#ifndef __used
#define __used __attribute__((__used__))
#endif
#ifndef __weak
#define __weak __attribute__((__weak__))
#endif
#else
#ifndef __aligned
#define __aligned(x)
#endif
#ifndef __noreturn
#define __noreturn
#endif
#ifndef __packed
#define __packed
#endif
#ifndef __section
#define __section(section)
#endif
#ifndef __used
#define __used
#endif
#ifndef __weak
#define __weak
#endif
#endif

#define BIT0  0x00000001U
#define BIT1  0x00000002U
#define BIT2  0x00000004U
#define BIT3  0x00000008U
#define BIT4  0x00000010U
#define BIT5  0x00000020U
#define BIT6  0x00000040U
#define BIT7  0x00000080U
#define BIT8  0x00000100U
#define BIT9  0x00000200U
#define BIT10 0x00000400U
#define BIT11 0x00000800U
#define BIT12 0x00001000U
#define BIT13 0x00002000U
#define BIT14 0x00004000U
#define BIT15 0x00008000U
#define BIT16 0x00010000U
#define BIT17 0x00020000U
#define BIT18 0x00040000U
#define BIT19 0x00080000U
#define BIT20 0x00100000U
#define BIT21 0x00200000U
#define BIT22 0x00400000U
#define BIT23 0x00800000U
#define BIT24 0x01000000U
#define BIT25 0x02000000U
#define BIT26 0x04000000U
#define BIT27 0x08000000U
#define BIT28 0x10000000U
#define BIT29 0x20000000U
#define BIT30 0x40000000U
#define BIT31 0x80000000U

#define MAX_UINT8  ((UINT8)0xffU)
#define MAX_UINT16 ((UINT16)0xffffU)
#define MAX_UINT32 ((UINT32)0xffffffffU)
#define MAX_UINT64 ((UINT64)0xffffffffffffffffULL)
#define MAX_UINTN  ((UINTN)~(UINTN)0)

#define SIGNATURE_16(A, B) ((UINT16)((UINT8)(A) | ((UINT16)(UINT8)(B) << 8)))
#define SIGNATURE_32(A, B, C, D)                                                   \
	((UINT32)((UINT8)(A) | ((UINT32)(UINT8)(B) << 8) |                         \
		  ((UINT32)(UINT8)(C) << 16) | ((UINT32)(UINT8)(D) << 24)))
#define SIGNATURE_64(A, B, C, D, E, F, G, H)                                       \
	((UINT64)SIGNATURE_32(A, B, C, D) |                                        \
	 ((UINT64)SIGNATURE_32(E, F, G, H) << 32))

#define OFFSET_OF(TYPE, field) ((UINTN)offsetof(TYPE, field))
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

#define SIZE_4KB 0x00001000U
#define SIZE_1MB 0x00100000U

#define ALIGN_VALUE_ADDEND(value, alignment) (((alignment) - (value)) & ((alignment)-1U))
#define ALIGN_VALUE(value, alignment) ((value) + ALIGN_VALUE_ADDEND(value, alignment))

#define EFI_PAGE_SIZE  SIZE_4KB
#define EFI_PAGE_MASK  0xfffU
#define EFI_PAGE_SHIFT 12U
#define EFI_SIZE_TO_PAGES(size) (((UINTN)(size) >> EFI_PAGE_SHIFT) + \
				 (((UINTN)(size)&EFI_PAGE_MASK) ? 1U : 0U))

#define EFI_ERROR_MASK ((UINTN)1 << (sizeof(UINTN) * 8U - 1U))
#define EFIERR(value)  (EFI_ERROR_MASK | (UINTN)(value))
#define EFI_ERROR(value) (((INTN)(value)) < 0)

#define EFI_SUCCESS            0
#define EFI_INVALID_PARAMETER  EFIERR(2)
#define EFI_UNSUPPORTED        EFIERR(3)
#define EFI_NOT_READY          EFIERR(6)
#define EFI_DEVICE_ERROR       EFIERR(7)
#define EFI_OUT_OF_RESOURCES   EFIERR(9)
#define EFI_NOT_FOUND          EFIERR(14)
#define EFI_SECURITY_VIOLATION EFIERR(26)
#define EFI_CRC_ERROR          EFIERR(27)
#define EFI_COMPROMISED_DATA   EFIERR(33)

typedef enum {
	efi_reserved_memory_type,
	efi_loader_code,
	efi_loader_data,
	efi_boot_services_code,
	efi_boot_services_data,
	efi_runtime_services_code,
	efi_runtime_services_data,
	efi_conventional_memory,
	efi_unusable_memory,
	efi_acpi_reclaim_memory,
	efi_acpi_memory_nvs,
	efi_memory_mapped_io,
	efi_memory_mapped_io_port_space,
	efi_pal_code,
	efi_persistent_memory,
	efi_unaccepted_memory_type,
	efi_max_memory_type
} EFI_MEMORY_TYPE;

#define MEMORY_TYPE_OEM_RESERVED_MIN 0x70000000U
#define MEMORY_TYPE_OEM_RESERVED_MAX 0x7fffffffU
#define MEMORY_TYPE_OS_RESERVED_MIN  0x80000000U
#define MEMORY_TYPE_OS_RESERVED_MAX  0xffffffffU

#define EFI_MEMORY_UC           0x0000000000000001ULL
#define EFI_MEMORY_WC           0x0000000000000002ULL
#define EFI_MEMORY_WT           0x0000000000000004ULL
#define EFI_MEMORY_WB           0x0000000000000008ULL
#define EFI_MEMORY_UCE          0x0000000000000010ULL
#define EFI_MEMORY_WP           0x0000000000001000ULL
#define EFI_MEMORY_RP           0x0000000000002000ULL
#define EFI_MEMORY_XP           0x0000000000004000ULL
#define EFI_MEMORY_NV           0x0000000000008000ULL
#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000ULL
#define EFI_MEMORY_RO           0x0000000000020000ULL
#define EFI_MEMORY_SP           0x0000000000040000ULL
#define EFI_MEMORY_CPU_CRYPTO   0x0000000000080000ULL
#define EFI_MEMORY_HOT_PLUGGABLE 0x0000000000100000ULL
#define EFI_MEMORY_RUNTIME      0x8000000000000000ULL

#define EFI_CACHE_ATTRIBUTE_MASK                                                    \
	(EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB |             \
	 EFI_MEMORY_UCE | EFI_MEMORY_WP)
#define EFI_MEMORY_ACCESS_MASK (EFI_MEMORY_RP | EFI_MEMORY_XP | EFI_MEMORY_RO)

#endif
