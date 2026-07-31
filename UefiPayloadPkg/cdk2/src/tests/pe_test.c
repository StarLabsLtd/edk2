/** @file

  Host checks for native PE32+ loading and relocation.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <cdk2/pe.h>

#include <stdio.h>
#include <string.h>

#define TEST_IMAGE_SIZE  0x600U
#define TEST_LOAD_SIZE   0x3000U

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 PE test: %s\n", Message);
    return 1;
  }

  return 0;
}

static UINTN
BuildImage (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  EFI_IMAGE_DOS_HEADER      *Dos;
  EFI_IMAGE_NT_HEADERS64    *Nt;
  EFI_IMAGE_SECTION_HEADER  *Sections;
  EFI_IMAGE_BASE_RELOCATION *Reloc;
  UINT16                    *RelocEntry;
  UINTN                      PeOffset;

  memset (Storage, 0, StorageSize);
  PeOffset = 0x80;
  Dos = (EFI_IMAGE_DOS_HEADER *)(VOID *)Storage;
  Dos->e_magic  = EFI_IMAGE_DOS_SIGNATURE;
  Dos->e_lfanew = PeOffset;
  Nt = (EFI_IMAGE_NT_HEADERS64 *)(VOID *)(Storage + PeOffset);
  Nt->Signature                         = EFI_IMAGE_NT_SIGNATURE;
  Nt->FileHeader.Machine                = IMAGE_FILE_MACHINE_X64;
  Nt->FileHeader.NumberOfSections       = 2;
  Nt->FileHeader.SizeOfOptionalHeader   = sizeof (EFI_IMAGE_OPTIONAL_HEADER64);
  Nt->OptionalHeader.Magic              = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt->OptionalHeader.ImageBase          = 0x00400000;
  Nt->OptionalHeader.SectionAlignment   = 0x1000;
  Nt->OptionalHeader.FileAlignment      = 0x200;
  Nt->OptionalHeader.SizeOfImage        = 0x3000;
  Nt->OptionalHeader.SizeOfHeaders      = 0x200;
  Nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;
  Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0x2000;
  Nt->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 12;

  Sections = (EFI_IMAGE_SECTION_HEADER *)(VOID *)((UINT8 *)Nt + sizeof (EFI_IMAGE_NT_HEADERS64));
  Sections[0].Misc.VirtualSize      = 0x100;
  Sections[0].VirtualAddress         = 0x1000;
  Sections[0].SizeOfRawData          = 0x200;
  Sections[0].PointerToRawData       = 0x200;
  Sections[1].Misc.VirtualSize       = 0x100;
  Sections[1].VirtualAddress         = 0x2000;
  Sections[1].SizeOfRawData           = 0x200;
  Sections[1].PointerToRawData        = 0x400;
  *(UINT64 *)(VOID *)(Storage + 0x200) = 0x00400123;

  Reloc = (EFI_IMAGE_BASE_RELOCATION *)(VOID *)(Storage + 0x400);
  Reloc->VirtualAddress = 0x1000;
  Reloc->SizeOfBlock    = 12;
  RelocEntry = (UINT16 *)(VOID *)(Reloc + 1);
  RelocEntry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 0);
  RelocEntry[1] = 0;
  return 0x600;
}

int
main (
  void
  )
{
  UINT8                  Image[TEST_IMAGE_SIZE];
  UINT8                  Loaded[TEST_LOAD_SIZE];
  EFI_PHYSICAL_ADDRESS   LoadedBase;
  EFI_PHYSICAL_ADDRESS   EntryPoint;
  UINTN                  LoadedSize;
  EFI_STATUS              Status;
  int                    Failures;

  Failures = 0;
  BuildImage (Image, sizeof (Image));
  Status = Cdk2NativeLoadPe32Plus (
             Image,
             sizeof (Image),
             (EFI_PHYSICAL_ADDRESS)(UINTN)Loaded,
             sizeof (Loaded),
             &LoadedBase,
             &LoadedSize,
             &EntryPoint
             );
  Failures += Expect (Status == EFI_SUCCESS, "valid PE image rejected");
  Failures += Expect (LoadedBase == (EFI_PHYSICAL_ADDRESS)(UINTN)Loaded, "loaded base is wrong");
  Failures += Expect (LoadedSize == 0x3000, "loaded size is wrong");
  Failures += Expect (EntryPoint == LoadedBase + 0x1000, "entry point is wrong");
  Failures += Expect (*(UINT64 *)(VOID *)(Loaded + 0x1000) == LoadedBase + 0x123, "DIR64 relocation is wrong");

  Status = Cdk2NativeLoadPe32Plus (
             Image,
             sizeof (Image),
             (EFI_PHYSICAL_ADDRESS)(UINTN)Loaded,
             0x1000,
             &LoadedBase,
             &LoadedSize,
             &EntryPoint
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "destination exhaustion accepted");

  Status = Cdk2NativeLoadPe32Plus (
             Image,
             sizeof (Image),
             (EFI_PHYSICAL_ADDRESS)(MAX_UINT64 - 0x1000U),
             sizeof (Loaded),
             &LoadedBase,
             &LoadedSize,
             &EntryPoint
  );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "wrapping destination range accepted");

  BuildImage (Image, sizeof (Image));
  {
    EFI_IMAGE_BASE_RELOCATION  *Reloc;
    UINT16                     *RelocEntry;

    Reloc = (EFI_IMAGE_BASE_RELOCATION *)(VOID *)(Image + 0x400);
    Reloc->VirtualAddress = MAX_UINT32;
    RelocEntry = (UINT16 *)(VOID *)(Reloc + 1);
    RelocEntry[0] = (UINT16)((EFI_IMAGE_REL_BASED_DIR64 << 12) | 1);
    Status = Cdk2NativeLoadPe32Plus (
               Image,
               sizeof (Image),
               (EFI_PHYSICAL_ADDRESS)(UINTN)Loaded,
               sizeof (Loaded),
               &LoadedBase,
               &LoadedSize,
               &EntryPoint
               );
    Failures += Expect (Status == EFI_COMPROMISED_DATA, "relocation RVA wraparound accepted");
  }

  BuildImage (Image, sizeof (Image));
  ((EFI_IMAGE_SECTION_HEADER *)(VOID *)(Image + 0x80 + sizeof (EFI_IMAGE_NT_HEADERS64)))[1].VirtualAddress = 0x1000;
  Status = Cdk2NativeLoadPe32Plus (
             Image,
             sizeof (Image),
             (EFI_PHYSICAL_ADDRESS)(UINTN)Loaded,
             sizeof (Loaded),
             &LoadedBase,
             &LoadedSize,
             &EntryPoint
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "overlapping sections accepted");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 PE test: PASS");
  return 0;
}
