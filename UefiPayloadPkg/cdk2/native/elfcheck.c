/** @file

  Host checks for the native cdk2 ELF layout contract.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#define EI_NIDENT      16U
#define EI_MAG0        0U
#define EI_MAG1        1U
#define EI_MAG2        2U
#define EI_MAG3        3U
#define EI_CLASS       4U
#define EI_DATA        5U
#define EI_VERSION     6U
#define ELFMAG0        0x7fU
#define ELFMAG1        'E'
#define ELFMAG2        'L'
#define ELFMAG3        'F'
#define ELFCLASS64     2U
#define ELFDATA2LSB    1U
#define EV_CURRENT     1U
#define ET_EXEC        2U
#define EM_X86_64      62U
#define PT_LOAD        1U
#define PF_X           1U
#define PF_W           2U
#define PF_R           4U
#define SHT_SYMTAB     2U
#define SHT_NOBITS     8U
#define SHF_WRITE      0x1U
#define SHF_ALLOC      0x2U
#define SHF_EXECINSTR  0x4U
#define SHN_UNDEF      0U

#define CDK2_LINK_BASE          0x00100000ULL
#define CDK2_MODULE_ENTRY_SIZE  16ULL
#define CDK2_FV_ALIGNMENT       128ULL

typedef struct {
  unsigned char  e_ident[EI_NIDENT];
  uint16_t       e_type;
  uint16_t       e_machine;
  uint32_t       e_version;
  uint64_t       e_entry;
  uint64_t       e_phoff;
  uint64_t       e_shoff;
  uint32_t       e_flags;
  uint16_t       e_ehsize;
  uint16_t       e_phentsize;
  uint16_t       e_phnum;
  uint16_t       e_shentsize;
  uint16_t       e_shnum;
  uint16_t       e_shstrndx;
} ELF64_EHDR;

typedef struct {
  uint32_t  p_type;
  uint32_t  p_flags;
  uint64_t  p_offset;
  uint64_t  p_vaddr;
  uint64_t  p_paddr;
  uint64_t  p_filesz;
  uint64_t  p_memsz;
  uint64_t  p_align;
} ELF64_PHDR;

typedef struct {
  uint32_t  sh_name;
  uint32_t  sh_type;
  uint64_t  sh_flags;
  uint64_t  sh_addr;
  uint64_t  sh_offset;
  uint64_t  sh_size;
  uint32_t  sh_link;
  uint32_t  sh_info;
  uint64_t  sh_addralign;
  uint64_t  sh_entsize;
} ELF64_SHDR;

typedef struct {
  uint32_t  st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t  st_shndx;
  uint64_t  st_value;
  uint64_t  st_size;
} ELF64_SYM;

typedef struct {
  uint8_t           *Data;
  size_t            Size;
  const ELF64_EHDR  *Header;
  const ELF64_PHDR  *ProgramHeaders;
  const ELF64_SHDR  *SectionHeaders;
  const char        *SectionStrings;
  size_t            SectionStringsSize;
} ELF_IMAGE;

typedef struct {
  uint64_t  Value;
  uint64_t  Size;
  uint16_t  SectionIndex;
} ELF_SYMBOL;

static void
Fail (
  const char  *Format,
  ...
  )
{
  va_list  Args;

  fprintf (stderr, "cdk2-elfcheck: ");
  va_start (Args, Format);
  vfprintf (stderr, Format, Args);
  va_end (Args);
  fputc ('\n', stderr);
  exit (EXIT_FAILURE);
}

static bool
RangeInFile (
  uint64_t  Offset,
  uint64_t  Size,
  size_t    FileSize
  )
{
  return (Offset <= (uint64_t)FileSize) &&
         (Size <= (uint64_t)FileSize - Offset);
}

static uint64_t
CheckedTableSize (
  uint64_t  Count,
  uint64_t  EntrySize
  )
{
  if ((EntrySize != 0) && (Count > UINT64_MAX / EntrySize)) {
    Fail ("ELF table size overflows");
  }

  return Count * EntrySize;
}

static bool
IsPowerOfTwo (
  uint64_t  Value
  )
{
  return (Value != 0) && ((Value & (Value - 1U)) == 0);
}

static const char *
CheckedString (
  const char  *Table,
  size_t      TableSize,
  uint32_t    Offset,
  const char  *Description
  )
{
  const char  *String;

  if (Offset >= TableSize) {
    Fail ("%s string offset is outside its table", Description);
  }

  String = Table + Offset;
  if (memchr (String, '\0', TableSize - Offset) == NULL) {
    Fail ("%s string is not nul-terminated", Description);
  }

  return String;
}

static const char *
SectionName (
  const ELF_IMAGE  *Image,
  const ELF64_SHDR *Section
  )
{
  return CheckedString (
           Image->SectionStrings,
           Image->SectionStringsSize,
           Section->sh_name,
           "section"
           );
}

static uint8_t *
ReadFile (
  const char  *Path,
  size_t      *Size
  )
{
  FILE     *File;
  long     Length;
  uint8_t  *Data;

  File = fopen (Path, "rb");
  if (File == NULL) {
    Fail ("cannot open %s: %s", Path, strerror (errno));
  }

  if (fseek (File, 0, SEEK_END) != 0) {
    Fail ("cannot seek %s", Path);
  }

  Length = ftell (File);
  if (Length < 0) {
    Fail ("cannot determine size of %s", Path);
  }

  if (fseek (File, 0, SEEK_SET) != 0) {
    Fail ("cannot rewind %s", Path);
  }

  Data = malloc ((size_t)Length == 0 ? 1 : (size_t)Length);
  if (Data == NULL) {
    Fail ("out of memory");
  }

  if (fread (Data, 1, (size_t)Length, File) != (size_t)Length) {
    Fail ("cannot read %s", Path);
  }

  fclose (File);
  *Size = (size_t)Length;
  return Data;
}

static void
OpenElf (
  ELF_IMAGE  *Image,
  const char *Path
  )
{
  uint64_t          ProgramHeaderSize;
  uint64_t          SectionHeaderSize;
  const ELF64_SHDR  *SectionStrings;

  memset (Image, 0, sizeof (*Image));
  Image->Data = ReadFile (Path, &Image->Size);
  if (Image->Size < sizeof (ELF64_EHDR)) {
    Fail ("%s is smaller than an ELF header", Path);
  }

  Image->Header = (const ELF64_EHDR *)(const void *)Image->Data;
  if (Image->Header->e_ident[EI_MAG0] != ELFMAG0 ||
      Image->Header->e_ident[EI_MAG1] != ELFMAG1 ||
      Image->Header->e_ident[EI_MAG2] != ELFMAG2 ||
      Image->Header->e_ident[EI_MAG3] != ELFMAG3 ||
      Image->Header->e_ident[EI_CLASS] != ELFCLASS64 ||
      Image->Header->e_ident[EI_DATA] != ELFDATA2LSB ||
      Image->Header->e_ident[EI_VERSION] != EV_CURRENT)
  {
    Fail ("%s is not an ELF64 little-endian image", Path);
  }

  if (Image->Header->e_type != ET_EXEC ||
      Image->Header->e_machine != EM_X86_64 ||
      Image->Header->e_version != EV_CURRENT ||
      Image->Header->e_ehsize != sizeof (ELF64_EHDR) ||
      Image->Header->e_phentsize != sizeof (ELF64_PHDR) ||
      Image->Header->e_shentsize != sizeof (ELF64_SHDR) ||
      Image->Header->e_phnum == 0 ||
      Image->Header->e_shnum == 0 ||
      Image->Header->e_shstrndx == SHN_UNDEF ||
      Image->Header->e_shstrndx >= Image->Header->e_shnum)
  {
    Fail ("%s has an unsupported ELF header", Path);
  }

  ProgramHeaderSize = CheckedTableSize (Image->Header->e_phnum, sizeof (ELF64_PHDR));
  SectionHeaderSize = CheckedTableSize (Image->Header->e_shnum, sizeof (ELF64_SHDR));
  if (!RangeInFile (Image->Header->e_phoff, ProgramHeaderSize, Image->Size) ||
      !RangeInFile (Image->Header->e_shoff, SectionHeaderSize, Image->Size))
  {
    Fail ("%s has an ELF table outside the file", Path);
  }

  Image->ProgramHeaders = (const ELF64_PHDR *)(const void *)(Image->Data + Image->Header->e_phoff);
  Image->SectionHeaders = (const ELF64_SHDR *)(const void *)(Image->Data + Image->Header->e_shoff);
  SectionStrings = &Image->SectionHeaders[Image->Header->e_shstrndx];
  if (!RangeInFile (SectionStrings->sh_offset, SectionStrings->sh_size, Image->Size)) {
    Fail ("%s has an invalid section string table", Path);
  }

  Image->SectionStrings     = (const char *)Image->Data + SectionStrings->sh_offset;
  Image->SectionStringsSize = (size_t)SectionStrings->sh_size;
}

static const ELF64_SHDR *
FindSection (
  const ELF_IMAGE  *Image,
  const char       *Name
  )
{
  uint16_t  Index;

  for (Index = 0; Index < Image->Header->e_shnum; Index++) {
    if (strcmp (SectionName (Image, &Image->SectionHeaders[Index]), Name) == 0) {
      return &Image->SectionHeaders[Index];
    }
  }

  return NULL;
}

static const ELF64_SHDR *
RequireSection (
  const ELF_IMAGE  *Image,
  const char       *Name
  )
{
  const ELF64_SHDR  *Section;

  Section = FindSection (Image, Name);
  if (Section == NULL) {
    Fail ("missing section %s", Name);
  }

  return Section;
}

static const ELF64_PHDR *
FindLoadSegment (
  const ELF_IMAGE  *Image,
  uint64_t         Address,
  uint64_t         Size
  )
{
  uint16_t            Index;
  const ELF64_PHDR    *ProgramHeader;

  for (Index = 0; Index < Image->Header->e_phnum; Index++) {
    ProgramHeader = &Image->ProgramHeaders[Index];
    if (ProgramHeader->p_type != PT_LOAD) {
      continue;
    }

    if ((Address >= ProgramHeader->p_vaddr) &&
        (Size <= ProgramHeader->p_memsz) &&
        (Address - ProgramHeader->p_vaddr <= ProgramHeader->p_memsz - Size))
    {
      return ProgramHeader;
    }
  }

  return NULL;
}

static void
CheckSectionPlacement (
  const ELF_IMAGE  *Image,
  const ELF64_SHDR *Section,
  const char       *Name,
  bool             ExpectExecutable,
  bool             ExpectWritable
  )
{
  const ELF64_PHDR  *Load;
  uint64_t          Span;

  if ((Section->sh_flags & SHF_ALLOC) == 0) {
    Fail ("%s is not allocated", Name);
  }

  if (ExpectExecutable != ((Section->sh_flags & SHF_EXECINSTR) != 0)) {
    Fail ("%s has unexpected executable section flags", Name);
  }

  if (ExpectWritable != ((Section->sh_flags & SHF_WRITE) != 0)) {
    Fail ("%s has unexpected writable section flags", Name);
  }

  Span = (Section->sh_size == 0) ? 1 : Section->sh_size;
  Load = FindLoadSegment (Image, Section->sh_addr, Span);
  if (Load == NULL) {
    Fail ("%s is not covered by a PT_LOAD segment", Name);
  }

  if ((Load->p_flags & PF_R) == 0) {
    Fail ("%s load segment is not readable", Name);
  }

  if (ExpectExecutable != ((Load->p_flags & PF_X) != 0)) {
    Fail ("%s has unexpected executable load flags", Name);
  }

  if (ExpectWritable != ((Load->p_flags & PF_W) != 0)) {
    Fail ("%s has unexpected writable load flags", Name);
  }
}

static bool
FindSymbol (
  const ELF_IMAGE  *Image,
  const char       *Name,
  ELF_SYMBOL       *Symbol
  )
{
  uint16_t          SectionIndex;
  uint64_t          SymbolCount;
  uint64_t          SymbolIndex;
  const ELF64_SHDR  *Symtab;
  const ELF64_SHDR  *Strtab;
  const ELF64_SYM   *Symbols;
  const char        *Strings;
  const char        *SymbolName;

  for (SectionIndex = 0; SectionIndex < Image->Header->e_shnum; SectionIndex++) {
    Symtab = &Image->SectionHeaders[SectionIndex];
    if (Symtab->sh_type != SHT_SYMTAB) {
      continue;
    }

    if (Symtab->sh_entsize != sizeof (ELF64_SYM) ||
        Symtab->sh_link >= Image->Header->e_shnum ||
        !RangeInFile (Symtab->sh_offset, Symtab->sh_size, Image->Size))
    {
      Fail ("invalid ELF symbol table");
    }

    Strtab = &Image->SectionHeaders[Symtab->sh_link];
    if (!RangeInFile (Strtab->sh_offset, Strtab->sh_size, Image->Size)) {
      Fail ("invalid ELF symbol string table");
    }

    Symbols = (const ELF64_SYM *)(const void *)(Image->Data + Symtab->sh_offset);
    Strings = (const char *)Image->Data + Strtab->sh_offset;
    SymbolCount = Symtab->sh_size / sizeof (ELF64_SYM);
    for (SymbolIndex = 0; SymbolIndex < SymbolCount; SymbolIndex++) {
      if (Symbols[SymbolIndex].st_name == 0) {
        continue;
      }

      SymbolName = CheckedString (
                     Strings,
                     (size_t)Strtab->sh_size,
                     Symbols[SymbolIndex].st_name,
                     "symbol"
                     );
      if (strcmp (SymbolName, Name) == 0) {
        Symbol->Value        = Symbols[SymbolIndex].st_value;
        Symbol->Size         = Symbols[SymbolIndex].st_size;
        Symbol->SectionIndex = Symbols[SymbolIndex].st_shndx;
        return true;
      }
    }
  }

  return false;
}

static ELF_SYMBOL
RequireSymbol (
  const ELF_IMAGE  *Image,
  const char       *Name
  )
{
  ELF_SYMBOL  Symbol;

  if (!FindSymbol (Image, Name, &Symbol)) {
    Fail ("missing symbol %s", Name);
  }

  return Symbol;
}

static void
CheckLoadSegments (
  const ELF_IMAGE  *Image
  )
{
  uint16_t          Index;
  const ELF64_PHDR  *ProgramHeader;
  bool              HasExecutable;
  bool              HasReadOnly;
  bool              HasWritable;

  HasExecutable = false;
  HasReadOnly   = false;
  HasWritable   = false;
  for (Index = 0; Index < Image->Header->e_phnum; Index++) {
    ProgramHeader = &Image->ProgramHeaders[Index];
    if (ProgramHeader->p_type != PT_LOAD) {
      continue;
    }

    if ((ProgramHeader->p_flags & PF_R) == 0) {
      Fail ("PT_LOAD segment is not readable");
    }

    if ((ProgramHeader->p_flags & PF_W) != 0 &&
        (ProgramHeader->p_flags & PF_X) != 0)
    {
      Fail ("PT_LOAD segment is both writable and executable");
    }

    if (ProgramHeader->p_filesz > ProgramHeader->p_memsz ||
        ProgramHeader->p_vaddr != ProgramHeader->p_paddr ||
        ProgramHeader->p_align < 0x1000 ||
        !IsPowerOfTwo (ProgramHeader->p_align) ||
        ((ProgramHeader->p_vaddr - ProgramHeader->p_offset) &
         (ProgramHeader->p_align - 1U)) != 0)
    {
      Fail ("PT_LOAD segment has invalid bounds or alignment");
    }

    HasExecutable = HasExecutable || ((ProgramHeader->p_flags & PF_X) != 0);
    HasReadOnly   = HasReadOnly ||
                    ((ProgramHeader->p_flags & (PF_W | PF_X)) == 0);
    HasWritable   = HasWritable || ((ProgramHeader->p_flags & PF_W) != 0);
  }

  if (!HasExecutable || !HasReadOnly || !HasWritable) {
    Fail ("ELF must have executable, read-only, and writable PT_LOAD segments");
  }
}

static void
CheckSectionFileBounds (
  const ELF_IMAGE  *Image
  )
{
  uint16_t          Index;
  const ELF64_SHDR  *Section;

  for (Index = 0; Index < Image->Header->e_shnum; Index++) {
    Section = &Image->SectionHeaders[Index];
    if (Section->sh_size != 0 &&
        Section->sh_type != SHT_NOBITS &&
        !RangeInFile (Section->sh_offset, Section->sh_size, Image->Size))
    {
      Fail ("%s section data is outside the file", SectionName (Image, Section));
    }

    if (Section->sh_addralign != 0 && !IsPowerOfTwo (Section->sh_addralign)) {
      Fail ("%s has invalid section alignment", SectionName (Image, Section));
    }
  }
}

static void
CheckImageContract (
  const ELF_IMAGE  *Image,
  const char       *EntrySymbolName,
  bool             RequireFv
  )
{
  ELF_SYMBOL        EntrySymbol;
  ELF_SYMBOL        ImageStart;
  ELF_SYMBOL        ImageEnd;
  ELF_SYMBOL        ModulesStart;
  ELF_SYMBOL        ModulesEnd;
  ELF_SYMBOL        FvStart;
  ELF_SYMBOL        FvEnd;
  const ELF64_SHDR  *TextEntry;
  const ELF64_SHDR  *Modules;
  const ELF64_SHDR  *Fv;
  const ELF64_SHDR  *Bss;
  uint64_t          ModuleTableSize;
  uint64_t          FvSize;

  CheckLoadSegments (Image);
  CheckSectionFileBounds (Image);

  TextEntry = RequireSection (Image, ".text.entry");
  Modules   = RequireSection (Image, ".cdk2.modules");
  Bss       = RequireSection (Image, ".bss");
  Fv        = FindSection (Image, ".cdk2.fv");

  CheckSectionPlacement (Image, TextEntry, ".text.entry", true, false);
  CheckSectionPlacement (Image, Modules, ".cdk2.modules", false, false);
  CheckSectionPlacement (Image, Bss, ".bss", false, true);
  if (Fv != NULL) {
    CheckSectionPlacement (Image, Fv, ".cdk2.fv", false, false);
  }

  EntrySymbol  = RequireSymbol (Image, EntrySymbolName);
  ImageStart   = RequireSymbol (Image, "__cdk2_image_start");
  ImageEnd     = RequireSymbol (Image, "__cdk2_image_end");
  ModulesStart = RequireSymbol (Image, "__cdk2_modules_start");
  ModulesEnd   = RequireSymbol (Image, "__cdk2_modules_end");
  FvStart      = RequireSymbol (Image, "__cdk2_fv_start");
  FvEnd        = RequireSymbol (Image, "__cdk2_fv_end");

  if (Image->Header->e_entry != EntrySymbol.Value) {
    Fail ("ELF entry does not match %s", EntrySymbolName);
  }

  if (ImageStart.Value != CDK2_LINK_BASE ||
      TextEntry->sh_addr != ImageStart.Value ||
      ImageEnd.Value <= ImageStart.Value)
  {
    Fail ("native image start/end symbols do not match the link contract");
  }

  if (EntrySymbol.Value < TextEntry->sh_addr ||
      EntrySymbol.Value >= TextEntry->sh_addr + TextEntry->sh_size)
  {
    Fail ("%s is outside .text.entry", EntrySymbolName);
  }

  if (ModulesStart.Value != Modules->sh_addr ||
      ModulesEnd.Value != Modules->sh_addr + Modules->sh_size ||
      ModulesEnd.Value < ModulesStart.Value)
  {
    Fail ("native module table symbols do not match .cdk2.modules");
  }

  ModuleTableSize = ModulesEnd.Value - ModulesStart.Value;
  if (ModuleTableSize == 0 ||
      (ModuleTableSize % CDK2_MODULE_ENTRY_SIZE) != 0)
  {
    Fail ("native module table has invalid size");
  }

  if (FvEnd.Value < FvStart.Value ||
      (FvStart.Value & (CDK2_FV_ALIGNMENT - 1U)) != 0 ||
      FvEnd.Value > ImageEnd.Value)
  {
    Fail ("native FV symbols have invalid bounds");
  }

  FvSize = FvEnd.Value - FvStart.Value;
  if (RequireFv) {
    if (Fv == NULL || Fv->sh_size == 0 || FvSize == 0) {
      Fail ("final coreboot image has no embedded FV section");
    }

    if (FvStart.Value != Fv->sh_addr ||
        FvEnd.Value != Fv->sh_addr + Fv->sh_size)
    {
      Fail ("embedded FV symbols do not match .cdk2.fv");
    }
  } else if (Fv != NULL &&
             (FvStart.Value != Fv->sh_addr ||
              FvEnd.Value != Fv->sh_addr + Fv->sh_size))
  {
    Fail ("FV symbols do not match .cdk2.fv");
  }
}

static void
Usage (
  const char  *Program
  )
{
  fprintf (
    stderr,
    "usage: %s --entry SYMBOL [--require-fv] FILE\n",
    Program
    );
}

int
main (
  int    Argc,
  char   **Argv
  )
{
  const char  *Path;
  const char  *EntrySymbol;
  bool        RequireFv;
  ELF_IMAGE   Image;

  Path        = NULL;
  EntrySymbol = NULL;
  RequireFv   = false;
  for (int Index = 1; Index < Argc; Index++) {
    if ((strcmp (Argv[Index], "--entry") == 0) && (Index + 1 < Argc)) {
      EntrySymbol = Argv[++Index];
    } else if (strcmp (Argv[Index], "--require-fv") == 0) {
      RequireFv = true;
    } else if (Path == NULL) {
      Path = Argv[Index];
    } else {
      Usage (Argv[0]);
      return EXIT_FAILURE;
    }
  }

  if (Path == NULL || EntrySymbol == NULL) {
    Usage (Argv[0]);
    return EXIT_FAILURE;
  }

  OpenElf (&Image, Path);
  CheckImageContract (&Image, EntrySymbol, RequireFv);
  printf ("cdk2 ELF layout: PASS (%s)\n", Path);
  free (Image.Data);
  return EXIT_SUCCESS;
}
