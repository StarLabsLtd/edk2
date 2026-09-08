/** @file
  This module forms the interface between bootloader SMM and payload MM.
  It also supplements a payload MM core with the CPU protocols.

  Copyright (c) 2023, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _BL_SMM_CPU_PAYLOAD_MM_H_
#define _BL_SMM_CPU_PAYLOAD_MM_H_

#include <PiSmm.h>
#include <Library/BaseLib.h>
#include <Library/CpuPageTableLib.h>
#include <Library/SynchronizationLib.h>

#include <Protocol/MmMp.h>
#include <Protocol/MpService.h>
#include <Protocol/SmmConfiguration.h>
#include <Protocol/SmmMemoryAttribute.h>

#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/PiSmmMemoryAttributesTable.h>

#include "SmmProfile.h"

#define CR4_CET_ENABLE  BIT23

///
/// Page Table Entry
///
#define IA32_PG_P     BIT0
#define IA32_PG_RW    BIT1
#define IA32_PG_U     BIT2
#define IA32_PG_A     BIT5
#define IA32_PG_D     BIT6
#define IA32_PG_PS    BIT7
#define IA32_PG_PMNT  BIT62
#define IA32_PG_NX    BIT63

#define PAGE_ATTRIBUTE_BITS  (IA32_PG_D | IA32_PG_A | IA32_PG_U | IA32_PG_RW | IA32_PG_P)

#define PAGING_PAE_INDEX_MASK  0x1FF

#define PAGING_4K_ADDRESS_MASK_64  0x000FFFFFFFFFF000ull
#define PAGING_2M_ADDRESS_MASK_64  0x000FFFFFFFE00000ull
#define PAGING_1G_ADDRESS_MASK_64  0x000FFFFFC0000000ull

#define SMRR_MAX_ADDRESS  BASE_4GB

typedef enum {
  PageNone,
  Page4K,
  Page2M,
  Page1G,
} PAGE_ATTRIBUTE;

//
// Wrapper used to convert EFI_AP_PROCEDURE2 and EFI_AP_PROCEDURE.
//
typedef struct {
  EFI_AP_PROCEDURE    Procedure;
  VOID                *ProcedureArgument;
} PROCEDURE_WRAPPER;

#define PROCEDURE_TOKEN_SIGNATURE  SIGNATURE_32 ('P', 'R', 'T', 'S')

typedef struct {
  UINTN              Signature;
  LIST_ENTRY         Link;

  SPIN_LOCK          *SpinLock;
  volatile UINT32    RunningApCount;
} PROCEDURE_TOKEN;

//
// Private structure for the SMM CPU module that is stored in DXE Runtime memory
// Contains the SMM Configuration Protocols that is produced.
// Contains a mix of DXE and SMM contents.  All the fields must be used properly.
//
#define PAYLOAD_MM_CPU_PRIVATE_DATA_SIGNATURE  SIGNATURE_32 ('P', 'M', 'M', '2')

typedef struct {
  UINT32                            Signature;
  EFI_HANDLE                        SmmCpuHandle;

  PAYLOAD_MM_EDK2_PRIVATE_DATA      PayloadMmPrivateData;

  EFI_SMM_ENTRY_CONTEXT             SmmCoreEntryContext;
  EFI_SMM_ENTRY_POINT               SmmCoreEntry;

  EFI_SMM_RESERVED_SMRAM_REGION     SmmReservedSmramRegion[1];
  EFI_SMM_CONFIGURATION_PROTOCOL    SmmConfiguration;

  EFI_PROCESSOR_INFORMATION         *ProcessorInfo;

  PROCEDURE_WRAPPER                 *ApWrapperFunc;
  LIST_ENTRY                        TokenList;
  LIST_ENTRY                        *FirstFreeToken;
} PAYLOAD_MM_CPU_PRIVATE_DATA;

extern const BOOLEAN  mIsStandaloneMm;

extern PAYLOAD_MM_CPU_PRIVATE_DATA  *gPayloadMmCpuPrivateData;
extern UINT32                       mSmrrBase, mSmrrSize;
extern UINTN                        mMaxNumberOfCpus;
extern UINTN                        mNumberOfCpus;
extern PAGING_MODE                  mPagingMode;

#define PAGE_TABLE_POOL_ALIGNMENT   BASE_128KB
#define PAGE_TABLE_POOL_UNIT_SIZE   BASE_128KB
#define PAGE_TABLE_POOL_UNIT_PAGES  EFI_SIZE_TO_PAGES (PAGE_TABLE_POOL_UNIT_SIZE)

typedef struct {
  VOID     *NextPool;
  UINTN    Offset;
  UINTN    FreePages;
} PAGE_TABLE_POOL;

/**
  Disable CET.
**/
VOID
EFIAPI
DisableCet (
  VOID
  );

/**
  Enable CET.
**/
VOID
EFIAPI
EnableCet (
  VOID
  );

extern IA32_DESCRIPTOR       gSmiHandlerIdtr;
extern UINT64                gPhyMask;
extern UINTN                 mSmmStackArrayBase;
extern UINTN                 mSmmStackSize;
extern SPIN_LOCK             *mPFLock;
extern EFI_SMRAM_DESCRIPTOR  *mSmmCpuSmramRanges;
extern UINTN                 mSmmCpuSmramRangeCount;
extern UINT8                 mPhysicalAddressBits;

//
// Copy of the PcdPteMemoryEncryptionAddressOrMask
//
extern UINT64  mAddressEncMask;

typedef struct {
  ///
  /// Address of the first byte in the memory region.
  ///
  EFI_PHYSICAL_ADDRESS    Base;
  ///
  /// Length in bytes of the memory region.
  ///
  UINT64                  Length;
  ///
  /// Attributes of the memory region
  ///
  UINT64                  Attribute;
} MM_CPU_MEMORY_REGION;

/**
  Create page table based on input PagingMode and PhysicalAddressBits in smm.

  @param[in]      PagingMode           The paging mode.
  @param[in]      PhysicalAddressBits  The bits of physical address to map.

  @retval         PageTable Address

**/
UINTN
GenSmmPageTable (
  IN PAGING_MODE  PagingMode,
  IN UINT8        PhysicalAddressBits
  );

/**
  Initialize global data for MP synchronization.

  @param Stacks             Base address of SMI stack buffer for all processors.
  @param StackSize          Stack size for each processor in SMM.

**/
UINT32
InitializeMpServiceData (
  IN UINTN  Stacks,
  IN UINTN  StackSize
  );

/**
  Initialize IDT IST Field.

  @param[in]  ExceptionType       Exception type.
  @param[in]  Ist                 IST value.

**/
VOID
EFIAPI
InitializeIdtIst (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN UINT8               Ist
  );

/**
  Initialize Gdt for all processors.

**/
EFI_STATUS
InitGdt (
  IN  UINTN  Cr3
  );

/**
  Register the MM Foundation entry point.

  This function registers the MM Foundation entry point with the processor code. This entry point
  will be invoked by the SMM Processor entry code.

  @param[in] This                The EFI_MM_CONFIGURATION_PROTOCOL instance.
  @param[in] MmEntryPoint        MM Foundation entry point.

  @retval EFI_SUCCESS            Success to register MM Entry Point.
  @retval EFI_INVALID_PARAMETER  MmEntryPoint is NULL.
**/
EFI_STATUS
EFIAPI
RegisterPayloadMmEntry (
  IN CONST EFI_SMM_CONFIGURATION_PROTOCOL  *This,
  IN EFI_SMM_ENTRY_POINT                   MmEntryPoint
  );

/**
  Create PageTable for SMM use.

  @return     PageTable Address

**/
UINT32
SmmInitPageTable (
  VOID
  );

/**
  Schedule a procedure to run on the specified CPU.

  @param   Procedure        The address of the procedure to run
  @param   CpuIndex         Target CPU number
  @param   ProcArguments    The parameter to pass to the procedure

  @retval   EFI_INVALID_PARAMETER    CpuNumber not valid
  @retval   EFI_INVALID_PARAMETER    CpuNumber specifying BSP
  @retval   EFI_INVALID_PARAMETER    The AP specified by CpuNumber did not enter SMM
  @retval   EFI_INVALID_PARAMETER    The AP specified by CpuNumber is busy
  @retval   EFI_SUCCESS - The procedure has been successfully scheduled

**/
EFI_STATUS
EFIAPI
SmmStartupThisAp (
  IN      EFI_AP_PROCEDURE  Procedure,
  IN      UINTN             CpuIndex,
  IN OUT  VOID              *ProcArguments OPTIONAL
  );

/**
  This function modifies the page attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  Caller should make sure BaseAddress and Length is at page boundary.

  @param[in]   PageTableBase    The page table base.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to modify for the memory region.
  @param[in]   IsSet            TRUE means to set attributes. FALSE means to clear attributes.
  @param[out]  IsModified       TRUE means page table modified. FALSE means page table not modified.

  @retval RETURN_SUCCESS           The attributes were modified for the memory region.
  @retval RETURN_ACCESS_DENIED     The attributes for the memory resource range specified by
                                   BaseAddress and Length cannot be modified.
  @retval RETURN_INVALID_PARAMETER Length is zero.
                                   Attributes specified an illegal combination of attributes that
                                   cannot be set together.
  @retval RETURN_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                   the memory resource range.
  @retval RETURN_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                   resource range specified by BaseAddress and Length.
                                   The bit mask of attributes is not support for the memory resource
                                   range specified by BaseAddress and Length.
**/
RETURN_STATUS
ConvertMemoryPageAttributes (
  IN  UINTN             PageTableBase,
  IN  PAGING_MODE       PagingMode,
  IN  PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64            Length,
  IN  UINT64            Attributes,
  IN  BOOLEAN           IsSet,
  OUT BOOLEAN           *IsModified   OPTIONAL
  );

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.
  @param[in]  Attributes       The bit mask of attributes to set for the memory region.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmSetMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );

/**
  This function clears the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]  BaseAddress      The physical address that is the start address of a memory region.
  @param[in]  Length           The size in bytes of the memory region.
  @param[in]  Attributes       The bit mask of attributes to clear for the memory region.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmClearMemoryAttributes (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );

/**
  Retrieves a pointer to the system configuration table from the SMM System Table
  based on a specified GUID.

  @param[in]   TableGuid       The pointer to table's GUID type.
  @param[out]  Table           The pointer to the table associated with TableGuid in the EFI System Table.

  @retval EFI_SUCCESS     A configuration table matching TableGuid was found.
  @retval EFI_NOT_FOUND   A configuration table matching TableGuid could not be found.

**/
EFI_STATUS
EFIAPI
SmmGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  );

/**

  Find out SMRAM information including SMRR base and SMRR size.

  @param          SmrrBase          SMRR base
  @param          SmrrSize          SMRR size

**/
EFI_STATUS
FindSmramInfo (
  OUT UINT32  *SmrrBase,
  OUT UINT32  *SmrrSize
  );

/**
  Page Fault handler for SMM use.

  @param  InterruptType    Defines the type of interrupt or exception that
                           occurred on the processor.This parameter is processor architecture specific.
  @param  SystemContext    A pointer to the processor context when
                           the interrupt occurred on the processor.
**/
VOID
EFIAPI
SmiPFHandler (
  IN EFI_EXCEPTION_TYPE  InterruptType,
  IN EFI_SYSTEM_CONTEXT  SystemContext
  );

/**
  Perform the remaining tasks.

**/
VOID
PerformRemainingTasks (
  VOID
  );

/**
  Search module name by input IP address and output it.

  @param CallerIpAddress   Caller instruction pointer.

**/
VOID
DumpModuleInfoByIp (
  IN  UINTN  CallerIpAddress
  );

/**
  This function sets memory attribute according to MemoryAttributesTable.
**/
VOID
SetMemMapAttributes (
  EDKII_PI_SMM_MEMORY_ATTRIBUTES_TABLE  *MemoryAttributesTable
  );

/**
  Return if the Address is forbidden as SMM communication buffer.

  @param[in] Address the address to be checked

  @return TRUE  The address is forbidden as SMM communication buffer.
  @return FALSE The address is allowed as SMM communication buffer.
**/
BOOLEAN
IsSmmCommBufferForbiddenAddress (
  IN UINT64  Address
  );

/**
  Create the Non-Mmram Memory Region.

  The caller is responsible for freeing MemoryRegion via FreePool().

  @param[in]      PhysicalAddressBits  The bits of physical address to map.
  @param[out]     MemoryRegion         Returned Non-Mmram Memory regions.
  @param[out]     MemoryRegionCount    A pointer to the number of Memory regions.

**/
VOID
CreateNonMmramMemMap (
  IN  UINT8                 PhysicalAddressBits,
  OUT MM_CPU_MEMORY_REGION  **MemoryRegion,
  OUT UINTN                 *MemoryRegionCount
  );

/**
  This function updates UEFI memory attribute according to UEFI memory map.

**/
VOID
UpdateUefiMemMapAttributes (
  VOID
  );

/**
  This function caches the UEFI memory map information.
**/
VOID
GetUefiMemoryMap (
  VOID
  );

/**
  This function sets memory attribute for page table.
**/
VOID
SetPageTableAttributes (
  VOID
  );

/**
  This function sets the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   PagingMode       The paging mode.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to set for the memory region.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be set together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not support for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmSetMemoryAttributesEx (
  IN  UINTN             PageTableBase,
  IN  PAGING_MODE       PagingMode,
  IN  PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64            Length,
  IN  UINT64            Attributes
  );

/**
  This function clears the attributes for the memory region specified by BaseAddress and
  Length from their current attributes to the attributes specified by Attributes.

  @param[in]   PageTableBase    The page table base.
  @param[in]   PagingMode       The paging mode.
  @param[in]   BaseAddress      The physical address that is the start address of a memory region.
  @param[in]   Length           The size in bytes of the memory region.
  @param[in]   Attributes       The bit mask of attributes to clear for the memory region.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_ACCESS_DENIED     The attributes for the memory resource range specified by
                                BaseAddress and Length cannot be modified.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of attributes that
                                cannot be cleared together.
  @retval EFI_OUT_OF_RESOURCES  There are not enough system resources to modify the attributes of
                                the memory resource range.
  @retval EFI_UNSUPPORTED       The processor does not support one or more bytes of the memory
                                resource range specified by BaseAddress and Length.
                                The bit mask of attributes is not supported for the memory resource
                                range specified by BaseAddress and Length.

**/
EFI_STATUS
SmmClearMemoryAttributesEx (
  IN  UINTN                 PageTableBase,
  IN  PAGING_MODE           PagingMode,
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINT64                Length,
  IN  UINT64                Attributes
  );

/**
  This API provides a way to allocate memory for page table.

  This API can be called more once to allocate memory for page tables.

  Allocates the number of 4KB pages of type EfiRuntimeServicesData and returns a pointer to the
  allocated buffer.  The buffer returned is aligned on a 4KB boundary.  If Pages is 0, then NULL
  is returned.  If there is not enough memory remaining to satisfy the request, then NULL is
  returned.

  @param  Pages                 The number of 4 KB pages to allocate.

  @return A pointer to the allocated buffer or NULL if allocation fails.

**/
VOID *
AllocatePageTableMemory (
  IN UINTN  Pages
  );

/**
  Allocate pages for code.

  @param[in]  Pages Number of pages to be allocated.

  @return Allocated memory.
**/
VOID *
AllocateCodePages (
  IN UINTN  Pages
  );

/**
  Initialise payload MM restore struct used by bootloader.

**/
EFI_STATUS
SaveMmInfoForS3 (
  IN EFI_PHYSICAL_ADDRESS  PayloadMmEntryPoint
  );

/**
  This function set given attributes of the memory region specified by
  BaseAddress and Length.

  @param  This              The EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL instance.
  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        The bit mask of attributes to set for the memory
                            region.

  @retval EFI_SUCCESS           The attributes were set for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of
                                attributes that cannot be set together.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.
                                The bit mask of attributes is not supported for
                                the memory resource range specified by
                                BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
EdkiiSmmSetMemoryAttributes (
  IN  EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL  *This,
  IN  EFI_PHYSICAL_ADDRESS                 BaseAddress,
  IN  UINT64                               Length,
  IN  UINT64                               Attributes
  );

/**
  This function clears given attributes of the memory region specified by
  BaseAddress and Length.

  @param  This              The EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL instance.
  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        The bit mask of attributes to clear for the memory
                            region.

  @retval EFI_SUCCESS           The attributes were cleared for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes specified an illegal combination of
                                attributes that cannot be cleared together.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.
                                The bit mask of attributes is not supported for
                                the memory resource range specified by
                                BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
EdkiiSmmClearMemoryAttributes (
  IN  EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL  *This,
  IN  EFI_PHYSICAL_ADDRESS                 BaseAddress,
  IN  UINT64                               Length,
  IN  UINT64                               Attributes
  );

/**
  This function retrieves the attributes of the memory region specified by
  BaseAddress and Length. If different attributes are got from different part
  of the memory region, EFI_NO_MAPPING will be returned.

  @param  This              The EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL instance.
  @param  BaseAddress       The physical address that is the start address of
                            a memory region.
  @param  Length            The size in bytes of the memory region.
  @param  Attributes        Pointer to attributes returned.

  @retval EFI_SUCCESS           The attributes got for the memory region.
  @retval EFI_INVALID_PARAMETER Length is zero.
                                Attributes is NULL.
  @retval EFI_NO_MAPPING        Attributes are not consistent cross the memory
                                region.
  @retval EFI_UNSUPPORTED       The processor does not support one or more
                                bytes of the memory resource range specified
                                by BaseAddress and Length.

**/
EFI_STATUS
EFIAPI
EdkiiSmmGetMemoryAttributes (
  IN  EDKII_SMM_MEMORY_ATTRIBUTE_PROTOCOL  *This,
  IN  EFI_PHYSICAL_ADDRESS                 BaseAddress,
  IN  UINT64                               Length,
  IN  UINT64                               *Attributes
  );

/**
  This function fixes up the address of the global variable or function
  referred in SmiEntry assembly files to be the absolute address.
**/
VOID
EFIAPI
PayloadMmTransferExecFixupAddress (
  VOID
  );

/**
  Worker function to execute a caller provided function on all enabled APs.

  @param[in]     Procedure               A pointer to the function to be run on
                                         enabled APs of the system.
  @param[in]     TimeoutInMicroseconds   Indicates the time limit in microseconds for
                                         APs to return from Procedure, either for
                                         blocking or non-blocking mode.
  @param[in,out] ProcedureArguments      The parameter passed into Procedure for
                                         all APs.
  @param[in,out] Token                   This is an optional parameter that allows the caller to execute the
                                         procedure in a blocking or non-blocking fashion. If it is NULL the
                                         call is blocking, and the call will not return until the AP has
                                         completed the procedure. If the token is not NULL, the call will
                                         return immediately. The caller can check whether the procedure has
                                         completed with CheckOnProcedure or WaitForProcedure.
  @param[in,out] CPUStatus               This optional pointer may be used to get the status code returned
                                         by Procedure when it completes execution on the target AP, or with
                                         EFI_TIMEOUT if the Procedure fails to complete within the optional
                                         timeout. The implementation will update this variable with
                                         EFI_NOT_READY prior to starting Procedure on the target AP.

  @retval EFI_SUCCESS             In blocking mode, all APs have finished before
                                  the timeout expired.
  @retval EFI_SUCCESS             In non-blocking mode, function has been dispatched
                                  to all enabled APs.
  @retval others                  Failed to Startup all APs.

**/
EFI_STATUS
InternalSmmStartupAllAPs (
  IN       EFI_AP_PROCEDURE2  Procedure,
  IN       UINTN              TimeoutInMicroseconds,
  IN OUT   VOID               *ProcedureArguments OPTIONAL,
  IN OUT   MM_COMPLETION      *Token,
  IN OUT   EFI_STATUS         *CPUStatus
  );

/**
  Allocate buffer for SpinLock and Wrapper function buffer.

**/
VOID
InitializeDataForMmMp (
  VOID
  );

/**
  Return whether access to non-SMRAM is restricted.

  @retval TRUE  Access to non-SMRAM is restricted.
  @retval FALSE Access to non-SMRAM is not restricted.
**/
BOOLEAN
IsRestrictedMemoryAccess (
  VOID
  );

/**
  Write unprotect read-only pages if Cr0.Bits.WP is 1.

  @param[out]  WriteProtect      If Cr0.Bits.WP is enabled.

**/
VOID
SmmWriteUnprotectReadOnlyPage (
  OUT BOOLEAN  *WriteProtect
  );

/**
  Write protect read-only pages.

  @param[in]  WriteProtect      If Cr0.Bits.WP should be enabled.

**/
VOID
SmmWriteProtectReadOnlyPage (
  IN  BOOLEAN  WriteProtect
  );

///
/// Define macros to encapsulate the write unprotect/protect
/// read-only pages.
/// Below pieces of logic are defined as macros and not functions
/// because "CET" feature disable & enable must be in the same
/// function to avoid shadow stack and normal SMI stack mismatch,
/// thus WRITE_UNPROTECT_RO_PAGES () must be called pair with
/// WRITE_PROTECT_RO_PAGES () in same function.
///
/// @param[in,out] Wp   A BOOLEAN variable local to the containing
///                     function, carrying write protection status from
///                     WRITE_UNPROTECT_RO_PAGES() to
///                     WRITE_PROTECT_RO_PAGES().
///
/// @param[in,out] Cet  A BOOLEAN variable local to the containing
///                     function, carrying control flow integrity
///                     enforcement status from
///                     WRITE_UNPROTECT_RO_PAGES() to
///                     WRITE_PROTECT_RO_PAGES().
///
#define WRITE_UNPROTECT_RO_PAGES(Wp, Cet) \
  do { \
    Cet = ((AsmReadCr4 () & CR4_CET_ENABLE) != 0); \
    if (Cet) { \
      DisableCet (); \
    } \
    SmmWriteUnprotectReadOnlyPage (&Wp); \
  } while (FALSE)

#define WRITE_PROTECT_RO_PAGES(Wp, Cet) \
  do { \
    SmmWriteProtectReadOnlyPage (Wp); \
    if (Cet) { \
      EnableCet (); \
    } \
  } while (FALSE)

/**
  Get the maximum number of logical processors supported by the system.

  @retval The maximum number of logical processors supported by the system
          is indicated by the return value.
**/
UINTN
GetSupportedMaxLogicalProcessorNumber (
  VOID
  );

/**
  Extract NumberOfCpus, MaxNumberOfCpus and EFI_PROCESSOR_INFORMATION for all CPU from gEfiMpServiceProtocolGuid.

  @param[out] NumberOfCpus           Pointer to NumberOfCpus.
  @param[out] MaxNumberOfCpus        Pointer to MaxNumberOfCpus.

  @retval ProcessorInfo              Pointer to EFI_PROCESSOR_INFORMATION buffer.
**/
EFI_PROCESSOR_INFORMATION *
GetMpInformationFromMpServices (
  OUT UINTN  *NumberOfCpus,
  OUT UINTN  *MaxNumberOfCpus
  );

/**
  The common Entry Point of the SMM CPU driver.

  @retval EFI_SUCCESS    The common entry point is executed successfully.
  @retval Other          Some error occurs when executing this entry point.

**/
EFI_STATUS
BlSmmCpuPayloadMmEntry (
  VOID
  );

#endif
