/** @file

  Host checks for native firmware-volume packing.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#define _POSIX_C_SOURCE  200809L

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>
#include <Pi/PiFirmwareFile.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_ENTRY_SIZE    0x400U
#define TEST_DXE_FV_SIZE   0x100U
#define TEST_PATH_SIZE     4096U
#define FV_BASE_ADDRESS    0x00800000ULL
#define FFS_HEADER_SIZE    0x18U

static UINT16
Get16 (
  const UINT8  *Buffer
  )
{
  return (UINT16)(Buffer[0] | ((UINT16)Buffer[1] << 8));
}

static UINT32
Get32 (
  const UINT8  *Buffer
  )
{
  return (UINT32)(Buffer[0] |
                  ((UINT32)Buffer[1] << 8) |
                  ((UINT32)Buffer[2] << 16) |
                  ((UINT32)Buffer[3] << 24));
}

static UINT64
Get64 (
  const UINT8  *Buffer
  )
{
  return (UINT64)Get32 (Buffer) | ((UINT64)Get32 (Buffer + 4) << 32);
}

static UINTN
Get24 (
  const UINT8  *Buffer
  )
{
  return (UINTN)(Buffer[0] |
                 ((UINTN)Buffer[1] << 8) |
                 ((UINTN)Buffer[2] << 16));
}

static void
Put16 (
  UINT8   *Buffer,
  UINT16  Value
  )
{
  Buffer[0] = (UINT8)Value;
  Buffer[1] = (UINT8)(Value >> 8);
}

static void
Put32 (
  UINT8   *Buffer,
  UINT32  Value
  )
{
  Buffer[0] = (UINT8)Value;
  Buffer[1] = (UINT8)(Value >> 8);
  Buffer[2] = (UINT8)(Value >> 16);
  Buffer[3] = (UINT8)(Value >> 24);
}

static void
Put64 (
  UINT8   *Buffer,
  UINT64  Value
  )
{
  Put32 (Buffer, (UINT32)Value);
  Put32 (Buffer + 4, (UINT32)(Value >> 32));
}

static UINTN
AlignUp (
  UINTN  Value,
  UINTN  Alignment
  )
{
  return (Value + Alignment - 1U) & ~(Alignment - 1U);
}

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 fvpack test: %s\n", Message);
    return 1;
  }

  return 0;
}

static int
BuildPath (
  char        *Path,
  size_t      PathSize,
  const char  *Directory,
  const char  *Suffix
  )
{
  int  Count;

  Count = snprintf (
            Path,
            PathSize,
            "%s/cdk2-fvpack-test-%ld-%s",
            Directory,
            (long)getpid (),
            Suffix
            );
  if ((Count < 0) || ((size_t)Count >= PathSize)) {
    fprintf (stderr, "cdk2 fvpack test: temporary path is too long\n");
    return 1;
  }

  return 0;
}

static UINTN
BuildNoRelocPe32Plus (
  UINT8  *Storage,
  UINTN  StorageSize
  )
{
  EFI_IMAGE_DOS_HEADER      *Dos;
  EFI_IMAGE_NT_HEADERS64    *Nt;
  EFI_IMAGE_SECTION_HEADER  *Section;
  UINTN                     PeOffset;

  if (StorageSize < TEST_ENTRY_SIZE) {
    return 0;
  }

  memset (Storage, 0, StorageSize);
  PeOffset = 0x80;
  Dos = (EFI_IMAGE_DOS_HEADER *)(VOID *)Storage;
  Dos->e_magic  = EFI_IMAGE_DOS_SIGNATURE;
  Dos->e_lfanew = (UINT32)PeOffset;

  Nt = (EFI_IMAGE_NT_HEADERS64 *)(VOID *)(Storage + PeOffset);
  Nt->Signature                       = EFI_IMAGE_NT_SIGNATURE;
  Nt->FileHeader.Machine              = IMAGE_FILE_MACHINE_X64;
  Nt->FileHeader.NumberOfSections     = 1;
  Nt->FileHeader.SizeOfOptionalHeader = sizeof (EFI_IMAGE_OPTIONAL_HEADER64);
  Nt->FileHeader.Characteristics      = EFI_IMAGE_FILE_EXECUTABLE_IMAGE | EFI_IMAGE_FILE_LARGE_ADDRESS_AWARE;
  Nt->OptionalHeader.Magic            = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  Nt->OptionalHeader.ImageBase        = 0;
  Nt->OptionalHeader.SectionAlignment = 0x1000;
  Nt->OptionalHeader.FileAlignment    = 0x200;
  Nt->OptionalHeader.SizeOfImage      = 0x2000;
  Nt->OptionalHeader.SizeOfHeaders    = 0x200;
  Nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
  Nt->OptionalHeader.NumberOfRvaAndSizes = EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES;

  Section = (EFI_IMAGE_SECTION_HEADER *)(VOID *)((UINT8 *)Nt + sizeof (EFI_IMAGE_NT_HEADERS64));
  memcpy (Section->Name, ".text", 5);
  Section->Misc.VirtualSize = 0x10;
  Section->VirtualAddress   = 0x1000;
  Section->SizeOfRawData    = 0x200;
  Section->PointerToRawData = 0x200;
  Storage[0x200] = 0xC3;
  return TEST_ENTRY_SIZE;
}

static UINTN
BuildDxeVolume (
  UINT8  *Storage,
  UINTN  StorageSize
  )
{
  if (StorageSize < TEST_DXE_FV_SIZE) {
    return 0;
  }

  memset (Storage, 0xFF, StorageSize);
  memset (Storage, 0, 0x48);
  Put64 (Storage + 0x20, TEST_DXE_FV_SIZE);
  memcpy (Storage + 0x28, "_FVH", 4);
  Put16 (Storage + 0x30, 0x48);
  Storage[0x37] = 2;
  return TEST_DXE_FV_SIZE;
}

static int
WriteBinaryFile (
  const char   *Path,
  const UINT8  *Data,
  UINTN        Size
  )
{
  FILE  *File;
  int   Result;

  File = fopen (Path, "wb");
  if (File == NULL) {
    fprintf (stderr, "cdk2 fvpack test: cannot create %s: %s\n", Path, strerror (errno));
    return 1;
  }

  Result = 0;
  if (fwrite (Data, 1, (size_t)Size, File) != (size_t)Size) {
    fprintf (stderr, "cdk2 fvpack test: cannot write %s\n", Path);
    Result = 1;
  }

  if (fclose (File) != 0) {
    fprintf (stderr, "cdk2 fvpack test: cannot close %s\n", Path);
    Result = 1;
  }

  return Result;
}

static UINT8 *
ReadBinaryFile (
  const char  *Path,
  size_t      *Size
  )
{
  FILE   *File;
  long   Length;
  UINT8  *Data;

  File = fopen (Path, "rb");
  if ((File == NULL) || (fseek (File, 0, SEEK_END) != 0)) {
    if (File != NULL) {
      fclose (File);
    }

    fprintf (stderr, "cdk2 fvpack test: cannot open %s\n", Path);
    return NULL;
  }

  Length = ftell (File);
  if ((Length <= 0) || (fseek (File, 0, SEEK_SET) != 0)) {
    fclose (File);
    fprintf (stderr, "cdk2 fvpack test: invalid size for %s\n", Path);
    return NULL;
  }

  Data = malloc ((size_t)Length);
  if (Data == NULL) {
    fclose (File);
    fprintf (stderr, "cdk2 fvpack test: out of memory\n");
    return NULL;
  }

  if (fread (Data, 1, (size_t)Length, File) != (size_t)Length) {
    free (Data);
    fclose (File);
    fprintf (stderr, "cdk2 fvpack test: cannot read %s\n", Path);
    return NULL;
  }

  fclose (File);
  *Size = (size_t)Length;
  return Data;
}

static int
RunPacker (
  const char  *Packer,
  const char  *OutputPath,
  const char  *EntryPath,
  const char  *DxePath
  )
{
  pid_t  Child;
  int    Status;

  Child = fork ();
  if (Child == 0) {
    execl (
      Packer,
      Packer,
      "--output",
      OutputPath,
      "--entry-efi",
      EntryPath,
      "--dxe-fv",
      DxePath,
      "--size",
      "0x2000",
      (char *)NULL
      );
    _exit (127);
  }

  if (Child < 0) {
    fprintf (stderr, "cdk2 fvpack test: cannot fork: %s\n", strerror (errno));
    return 1;
  }

  if (waitpid (Child, &Status, 0) < 0) {
    fprintf (stderr, "cdk2 fvpack test: cannot wait for packer: %s\n", strerror (errno));
    return 1;
  }

  if (!WIFEXITED (Status) || (WEXITSTATUS (Status) != 0)) {
    fprintf (stderr, "cdk2 fvpack test: packer failed\n");
    return 1;
  }

  return 0;
}

static int
FindPackedEntryImageBase (
  const UINT8  *Volume,
  size_t       VolumeSize,
  UINT64       *ImageBase,
  UINT64       *ExpectedBase
  )
{
  UINTN   FileOffset;
  UINTN   FileSize;
  UINTN   FileEnd;
  UINTN   RawSectionSize;
  UINTN   PeSectionOffset;
  UINTN   PeSectionSize;
  UINTN   PeOffset;
  UINTN   PeHeaderOffset;
  UINTN   OptionalOffset;
  UINT16  OptionalMagic;

  if (VolumeSize < 0x48) {
    return Expect (0, "packed FV is smaller than its header");
  }

  FileOffset = AlignUp ((UINTN)Get16 (Volume + 0x30), 8);
  while (FileOffset + FFS_HEADER_SIZE <= VolumeSize) {
    FileSize = Get24 (Volume + FileOffset + 20);
    if (FileSize == 0xFFFFFFU) {
      return Expect (0, "packed FV does not contain an entry file");
    }

    if ((FileSize < FFS_HEADER_SIZE) || (FileSize > VolumeSize - FileOffset)) {
      return Expect (0, "packed FV contains an invalid FFS file");
    }

    if (Volume[FileOffset + 18] == EFI_FV_FILETYPE_FFS_PAD) {
      FileOffset = AlignUp (FileOffset + FileSize, 8);
      continue;
    }

    if (Volume[FileOffset + 18] != EFI_FV_FILETYPE_SECURITY_CORE) {
      return Expect (0, "packed FV first non-pad file is not the entry image");
    }

    FileEnd = FileOffset + FileSize;
    RawSectionSize = Get24 (Volume + FileOffset + FFS_HEADER_SIZE);
    if ((RawSectionSize < 4) ||
        (FileOffset + FFS_HEADER_SIZE + RawSectionSize + 4 > FileEnd) ||
        (Volume[FileOffset + FFS_HEADER_SIZE + 3] != EFI_SECTION_RAW))
    {
      return Expect (0, "packed entry raw section is invalid");
    }

    PeSectionOffset = FileOffset + FFS_HEADER_SIZE + RawSectionSize;
    PeSectionSize = Get24 (Volume + PeSectionOffset);
    if ((PeSectionSize < 4) ||
        (PeSectionOffset + PeSectionSize > FileEnd) ||
        (Volume[PeSectionOffset + 3] != EFI_SECTION_PE32))
    {
      return Expect (0, "packed entry PE section is invalid");
    }

    PeOffset = PeSectionOffset + 4;
    if ((PeOffset + 0x40 > VolumeSize) || (Get16 (Volume + PeOffset) != EFI_IMAGE_DOS_SIGNATURE)) {
      return Expect (0, "packed entry PE image is invalid");
    }

    PeHeaderOffset = PeOffset + Get32 (Volume + PeOffset + 0x3C);
    if ((PeHeaderOffset + 24 > VolumeSize) ||
        (Get32 (Volume + PeHeaderOffset) != EFI_IMAGE_NT_SIGNATURE))
    {
      return Expect (0, "packed entry PE header is invalid");
    }

    OptionalOffset = PeHeaderOffset + 4 + 20;
    if (OptionalOffset + 32 > VolumeSize) {
      return Expect (0, "packed entry optional header is invalid");
    }

    OptionalMagic = Get16 (Volume + OptionalOffset);
    if (OptionalMagic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
      return Expect (0, "packed entry is not PE32+");
    }

    *ImageBase = Get64 (Volume + OptionalOffset + 24);
    *ExpectedBase = FV_BASE_ADDRESS + (UINT64)PeOffset;
    return 0;
  }

  return Expect (0, "packed FV does not contain an entry file");
}

int
main (
  int    ArgumentCount,
  char   **Arguments
  )
{
  UINT8   Entry[TEST_ENTRY_SIZE];
  UINT8   Dxe[TEST_DXE_FV_SIZE];
  char    EntryPath[TEST_PATH_SIZE];
  char    DxePath[TEST_PATH_SIZE];
  char    OutputPath[TEST_PATH_SIZE];
  UINTN   EntrySize;
  UINTN   DxeSize;
  UINT8   *Packed;
  size_t  PackedSize;
  UINT64  ImageBase;
  UINT64  ExpectedBase;
  int     Failures;

  if (ArgumentCount != 3) {
    fprintf (stderr, "usage: %s PACKER BUILD_DIR\n", Arguments[0]);
    return 1;
  }

  EntryPath[0] = '\0';
  DxePath[0] = '\0';
  OutputPath[0] = '\0';
  Packed = NULL;
  PackedSize = 0;
  ImageBase = 0;
  ExpectedBase = 0;
  Failures = 0;

  Failures += BuildPath (EntryPath, sizeof (EntryPath), Arguments[2], "entry.efi");
  Failures += BuildPath (DxePath, sizeof (DxePath), Arguments[2], "dxe.fv");
  Failures += BuildPath (OutputPath, sizeof (OutputPath), Arguments[2], "packed.fv");

  EntrySize = BuildNoRelocPe32Plus (Entry, sizeof (Entry));
  DxeSize = BuildDxeVolume (Dxe, sizeof (Dxe));
  Failures += Expect (EntrySize != 0, "cannot build test PE32+ entry");
  Failures += Expect (DxeSize != 0, "cannot build test DXE FV");

  if (Failures == 0) {
    Failures += WriteBinaryFile (EntryPath, Entry, EntrySize);
    Failures += WriteBinaryFile (DxePath, Dxe, DxeSize);
  }

  if (Failures == 0) {
    Failures += RunPacker (Arguments[1], OutputPath, EntryPath, DxePath);
  }

  if (Failures == 0) {
    Packed = ReadBinaryFile (OutputPath, &PackedSize);
    Failures += Expect (Packed != NULL, "cannot read packed FV");
  }

  if (Failures == 0) {
    Failures += FindPackedEntryImageBase (Packed, PackedSize, &ImageBase, &ExpectedBase);
  }

  if (Failures == 0) {
    if (ImageBase != ExpectedBase) {
      fprintf (
        stderr,
        "cdk2 fvpack test: packed no-relocation PE32+ ImageBase is 0x%llx, expected 0x%llx\n",
        (unsigned long long)ImageBase,
        (unsigned long long)ExpectedBase
        );
      Failures++;
    }
  }

  free (Packed);
  if (EntryPath[0] != '\0') {
    remove (EntryPath);
  }

  if (DxePath[0] != '\0') {
    remove (DxePath);
  }

  if (OutputPath[0] != '\0') {
    remove (OutputPath);
  }

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 fvpack test: PASS");
  return 0;
}
