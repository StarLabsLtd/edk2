/** @file
  Exercise production TPM2 log publication and strict failure handling.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#undef NULL
#include <PiDxe.h>
static BOOLEAN Required;
static UINT8 ConfigRevision = 4;
static UINT32 LogSize = 0x10004a;
static UINT64 LogAddress = 0x1234000;
#define _PCD_VALUE_PcdTpm2MeasurementRequired Required
#define _PCD_GET_MODE_8_PcdTpm2AcpiTableRev ConfigRevision
#define _PCD_GET_MODE_8_PcdTpmPlatformClass 0
#define _PCD_GET_MODE_8_PcdActiveTpmInterfaceType Tpm2PtpInterfaceCrb
#define _PCD_GET_MODE_PTR_PcdAcpiDefaultOemId ((VOID *)"TEST  ")
#define _PCD_GET_MODE_64_PcdAcpiDefaultOemTableId 0
#define _PCD_GET_MODE_32_PcdAcpiDefaultOemRevision 1
#define _PCD_GET_MODE_32_PcdAcpiDefaultCreatorId 0
#define _PCD_GET_MODE_32_PcdAcpiDefaultCreatorRevision 1
#define _PCD_GET_MODE_64_PcdTpmBaseAddress 0xfed40000
#define _PCD_GET_MODE_32_PcdTpm2AcpiTableLaml LogSize
#define _PCD_GET_MODE_64_PcdTpm2AcpiTableLasa LogAddress
#include "Tpm2AcpiTableDxe.c"

#define CHECK(C) do { if (!(C)) { fprintf(stderr, "%d: %s\n", __LINE__, #C); exit(1); } } while (0)
static jmp_buf Halt;
static BOOLEAN Present;
static unsigned Lookup, FailLookup, Installs;
static EFI_STATUS EnumerationError, RemovalError, InstallError;
static EFI_ACPI_SDT_HEADER Inherited;
static UEFI_PAYLOAD_TPM2_ACPI_TABLE Published;
EFI_GUID gEfiAcpiSdtProtocolGuid, gEfiAcpiTableProtocolGuid;
VOID *EFIAPI CopyMem(VOID *To, CONST VOID *From, UINTN Size) { return memcpy(To, From, Size); }
VOID *EFIAPI ZeroMem(VOID *To, UINTN Size) { return memset(To, 0, Size); }
BOOLEAN EFIAPI DebugAssertEnabled(VOID) { return TRUE; }
BOOLEAN EFIAPI DebugPrintEnabled(VOID) { return FALSE; }
VOID EFIAPI DebugAssert(CONST CHAR8 *File, UINTN Line, CONST CHAR8 *Text) { abort(); }
VOID EFIAPI DebugPrint(UINTN Level, CONST CHAR8 *Format, ...) { }
VOID EFIAPI CpuDeadLoop(VOID) { longjmp(Halt, 1); }
static EFI_STATUS EFIAPI GetTable(UINTN Index, EFI_ACPI_SDT_HEADER **Table,
  EFI_ACPI_TABLE_VERSION *Version, UINTN *Key)
{
  if (EnumerationError) return EnumerationError;
  if (Index || !Present) return EFI_NOT_FOUND;
  *Table = &Inherited; *Version = EFI_ACPI_TABLE_VERSION_2_0; *Key = 1;
  return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Remove(EFI_ACPI_TABLE_PROTOCOL *This, UINTN Key)
{
  if (RemovalError) return RemovalError;
  CHECK(Key == 1); Present = FALSE; return EFI_SUCCESS;
}
static EFI_STATUS EFIAPI Install(EFI_ACPI_TABLE_PROTOCOL *This, VOID *Table,
  UINTN Size, UINTN *Key)
{
  Installs++;
  CHECK(Size == sizeof(Published));
  memcpy(&Published, Table, Size);
  *Key = 2;
  return InstallError;
}
static EFI_ACPI_SDT_PROTOCOL Sdt = { .GetAcpiTable = GetTable };
static EFI_ACPI_TABLE_PROTOCOL Acpi = { .InstallAcpiTable = Install, .UninstallAcpiTable = Remove };
static EFI_STATUS EFIAPI Locate(EFI_GUID *Guid, VOID *Registration, VOID **Protocol)
{
  if (++Lookup == FailLookup) return EFI_NOT_FOUND;
  *Protocol = Guid == &gEfiAcpiSdtProtocolGuid ? (VOID *)&Sdt : (VOID *)&Acpi;
  return EFI_SUCCESS;
}
static EFI_BOOT_SERVICES Services = { .LocateProtocol = Locate };
EFI_BOOT_SERVICES *gBS = &Services;
static void Reset(void)
{
  Lookup = FailLookup = Installs = 0;
  EnumerationError = RemovalError = InstallError = EFI_SUCCESS;
  LogSize = 0x10004a; LogAddress = 0x1234000;
  Present = TRUE;
  Inherited.Signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE;
}
static void Run(EFI_STATUS Expected, BOOLEAN ExpectHalt)
{
  if (setjmp(Halt)) { CHECK(ExpectHalt); return; }
  EFI_STATUS Status = Tpm2AcpiTableDxeEntryPoint(NULL, NULL);
  CHECK(!ExpectHalt);
  CHECK(Status == Expected);
}
int main(void)
{
  for (Required = FALSE; Required <= TRUE; Required++) {
    for (ConfigRevision = 3; ConfigRevision <= 4; ConfigRevision++) {
      Reset(); Run(EFI_SUCCESS, FALSE);
      CHECK(Installs == 1 && !Present);
      CHECK(Published.Header.Revision == 4);
      CHECK(Published.Laml == LogSize && Published.Lasa == LogAddress);
    }
    for (unsigned Stage = 1; Stage <= 2; Stage++) {
      Reset(); FailLookup = Stage; Run(EFI_NOT_FOUND, Required); CHECK(!Installs);
    }
    Reset(); EnumerationError = EFI_DEVICE_ERROR;
    Run(Required ? EFI_DEVICE_ERROR : EFI_SUCCESS, Required);
    CHECK(Installs == !Required);
    Reset(); RemovalError = EFI_ACCESS_DENIED;
    Run(Required ? EFI_ACCESS_DENIED : EFI_SUCCESS, Required);
    CHECK(Installs == !Required);
    Reset(); InstallError = EFI_OUT_OF_RESOURCES;
    Run(EFI_OUT_OF_RESOURCES, Required); CHECK(Installs == 1);
    Reset(); LogSize = 0; Run(EFI_NOT_READY, Required); CHECK(!Installs);
    Reset(); LogAddress = 0; Run(EFI_NOT_READY, Required); CHECK(!Installs);
  }
  puts("Production TPM2 publication: revisions, geometry, lookup, removal and installation failures passed");
  return 0;
}
