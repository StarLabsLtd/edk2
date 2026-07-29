/** @file

  Host regressions for the native cdk2 ELF layout checker.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#define _POSIX_C_SOURCE  200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

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
#define SHT_PROGBITS   1U
#define SHT_SYMTAB     2U
#define SHT_STRTAB     3U
#define SHT_NOBITS     8U
#define SHF_WRITE      0x1U
#define SHF_ALLOC      0x2U
#define SHF_EXECINSTR  0x4U

#define CDK2_LINK_BASE          0x00100000ULL
#define CDK2_MODULE_ENTRY_SIZE  16ULL
#define CDK2_FV_ALIGNMENT       128ULL

#define TEST_FILE_SIZE        0x2010U
#define TEST_PATH_SIZE        4096U
#define TEST_SYMTAB_OFFSET    0x0100U
#define TEST_STRTAB_OFFSET    0x0200U
#define TEST_SHSTRTAB_OFFSET  0x0300U
#define TEST_SECTION_OFFSET   0x0400U
#define TEST_TEXT_OFFSET      0x1000U
#define TEST_MODULES_OFFSET   0x2000U
#define TEST_TEXT_ADDRESS     CDK2_LINK_BASE
#define TEST_MODULES_ADDRESS  0x00101000ULL
#define TEST_BSS_ADDRESS      0x00102000ULL
#define TEST_BSS_SIZE         0x1000ULL

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

typedef enum {
  ElfFixtureValid,
  ElfFixtureBadLoadFileRange,
  ElfFixtureOverlappingLoad,
  ElfFixtureWrappingLoad,
  ElfFixtureBssOutsideImage
} ELF_FIXTURE_KIND;

enum {
  SectionNull,
  SectionTextEntry,
  SectionModules,
  SectionBss,
  SectionShstrtab,
  SectionSymtab,
  SectionStrtab,
  SectionCount
};

enum {
  ProgramText,
  ProgramModules,
  ProgramBss,
  ProgramExtra,
  ProgramCount
};

enum {
  SymbolNull,
  SymbolEntry,
  SymbolImageStart,
  SymbolImageEnd,
  SymbolModulesStart,
  SymbolModulesEnd,
  SymbolFvStart,
  SymbolFvEnd,
  SymbolCount
};

enum {
  SectionNameTextEntry = 1,
  SectionNameModules   = SectionNameTextEntry + sizeof (".text.entry"),
  SectionNameBss       = SectionNameModules + sizeof (".cdk2.modules"),
  SectionNameShstrtab  = SectionNameBss + sizeof (".bss"),
  SectionNameSymtab    = SectionNameShstrtab + sizeof (".shstrtab"),
  SectionNameStrtab    = SectionNameSymtab + sizeof (".symtab")
};

enum {
  SymbolNameEntry        = 1,
  SymbolNameImageStart   = SymbolNameEntry + sizeof ("Cdk2NativeStageEntry"),
  SymbolNameImageEnd     = SymbolNameImageStart + sizeof ("__cdk2_image_start"),
  SymbolNameModulesStart = SymbolNameImageEnd + sizeof ("__cdk2_image_end"),
  SymbolNameModulesEnd   = SymbolNameModulesStart + sizeof ("__cdk2_modules_start"),
  SymbolNameFvStart      = SymbolNameModulesEnd + sizeof ("__cdk2_modules_end"),
  SymbolNameFvEnd        = SymbolNameFvStart + sizeof ("__cdk2_fv_start")
};

static const char  mSectionStrings[] =
  "\0.text.entry\0.cdk2.modules\0.bss\0.shstrtab\0.symtab\0.strtab\0";
static const char  mSymbolStrings[] =
  "\0Cdk2NativeStageEntry\0__cdk2_image_start\0__cdk2_image_end\0"
  "__cdk2_modules_start\0__cdk2_modules_end\0__cdk2_fv_start\0"
  "__cdk2_fv_end\0";

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 ELF checker test: %s\n", Message);
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
            "%s/cdk2-elfcheck-test-%ld-%s.elf",
            Directory,
            (long)getpid (),
            Suffix
            );
  if ((Count < 0) || ((size_t)Count >= PathSize)) {
    fprintf (stderr, "cdk2 ELF checker test: temporary path is too long\n");
    return 1;
  }

  return 0;
}

static void
FillLoad (
  ELF64_PHDR  *Header,
  uint32_t    Flags,
  uint64_t    Offset,
  uint64_t    Address,
  uint64_t    FileSize,
  uint64_t    MemorySize
  )
{
  Header->p_type   = PT_LOAD;
  Header->p_flags  = Flags;
  Header->p_offset = Offset;
  Header->p_vaddr  = Address;
  Header->p_paddr  = Address;
  Header->p_filesz = FileSize;
  Header->p_memsz  = MemorySize;
  Header->p_align  = 0x1000;
}

static void
FillSymbol (
  ELF64_SYM  *Symbol,
  uint32_t   Name,
  uint16_t   SectionIndex,
  uint64_t   Value,
  uint64_t   Size
  )
{
  Symbol->st_name  = Name;
  Symbol->st_shndx = SectionIndex;
  Symbol->st_value = Value;
  Symbol->st_size  = Size;
}

static size_t
BuildElf (
  uint8_t           *Storage,
  size_t            StorageSize,
  ELF_FIXTURE_KIND  Kind
  )
{
  ELF64_EHDR  *Elf;
  ELF64_PHDR  *Programs;
  ELF64_SHDR  *Sections;
  ELF64_SYM   *Symbols;

  if (StorageSize < TEST_FILE_SIZE) {
    return 0;
  }

  memset (Storage, 0, StorageSize);

  Elf = (ELF64_EHDR *)(void *)Storage;
  Elf->e_ident[EI_MAG0]    = ELFMAG0;
  Elf->e_ident[EI_MAG1]    = ELFMAG1;
  Elf->e_ident[EI_MAG2]    = ELFMAG2;
  Elf->e_ident[EI_MAG3]    = ELFMAG3;
  Elf->e_ident[EI_CLASS]   = ELFCLASS64;
  Elf->e_ident[EI_DATA]    = ELFDATA2LSB;
  Elf->e_ident[EI_VERSION] = EV_CURRENT;
  Elf->e_type              = ET_EXEC;
  Elf->e_machine           = EM_X86_64;
  Elf->e_version           = EV_CURRENT;
  Elf->e_entry             = TEST_TEXT_ADDRESS;
  Elf->e_phoff             = sizeof (*Elf);
  Elf->e_shoff             = TEST_SECTION_OFFSET;
  Elf->e_ehsize            = sizeof (*Elf);
  Elf->e_phentsize         = sizeof (ELF64_PHDR);
  Elf->e_phnum             = (Kind == ElfFixtureOverlappingLoad ||
                              Kind == ElfFixtureWrappingLoad) ?
                             ProgramCount : ProgramExtra;
  Elf->e_shentsize         = sizeof (ELF64_SHDR);
  Elf->e_shnum             = SectionCount;
  Elf->e_shstrndx          = SectionShstrtab;

  Programs = (ELF64_PHDR *)(void *)(Storage + Elf->e_phoff);
  FillLoad (
    &Programs[ProgramText],
    PF_R | PF_X,
    (Kind == ElfFixtureBadLoadFileRange) ? 0x3000U : TEST_TEXT_OFFSET,
    TEST_TEXT_ADDRESS,
    1,
    1
    );
  FillLoad (
    &Programs[ProgramModules],
    PF_R,
    TEST_MODULES_OFFSET,
    TEST_MODULES_ADDRESS,
    CDK2_MODULE_ENTRY_SIZE,
    CDK2_MODULE_ENTRY_SIZE
    );
  FillLoad (
    &Programs[ProgramBss],
    PF_R | PF_W,
    0,
    TEST_BSS_ADDRESS,
    0,
    TEST_BSS_SIZE
    );
  if (Kind == ElfFixtureOverlappingLoad) {
    FillLoad (&Programs[ProgramExtra], PF_R, TEST_TEXT_OFFSET, TEST_TEXT_ADDRESS, 0, 1);
  } else if (Kind == ElfFixtureWrappingLoad) {
    FillLoad (&Programs[ProgramExtra], PF_R, 0, UINT64_MAX - 0xfffU, 0, 0x2000);
  }

  Sections = (ELF64_SHDR *)(void *)(Storage + TEST_SECTION_OFFSET);
  Sections[SectionTextEntry].sh_name       = SectionNameTextEntry;
  Sections[SectionTextEntry].sh_type       = SHT_PROGBITS;
  Sections[SectionTextEntry].sh_flags      = SHF_ALLOC | SHF_EXECINSTR;
  Sections[SectionTextEntry].sh_addr       = TEST_TEXT_ADDRESS;
  Sections[SectionTextEntry].sh_offset     = TEST_TEXT_OFFSET;
  Sections[SectionTextEntry].sh_size       = 1;
  Sections[SectionTextEntry].sh_addralign  = 1;
  Sections[SectionModules].sh_name         = SectionNameModules;
  Sections[SectionModules].sh_type         = SHT_PROGBITS;
  Sections[SectionModules].sh_flags        = SHF_ALLOC;
  Sections[SectionModules].sh_addr         = TEST_MODULES_ADDRESS;
  Sections[SectionModules].sh_offset       = TEST_MODULES_OFFSET;
  Sections[SectionModules].sh_size         = CDK2_MODULE_ENTRY_SIZE;
  Sections[SectionModules].sh_addralign    = 16;
  Sections[SectionBss].sh_name             = SectionNameBss;
  Sections[SectionBss].sh_type             = SHT_NOBITS;
  Sections[SectionBss].sh_flags            = SHF_ALLOC | SHF_WRITE;
  Sections[SectionBss].sh_addr             = TEST_BSS_ADDRESS;
  Sections[SectionBss].sh_size             = TEST_BSS_SIZE;
  Sections[SectionBss].sh_addralign        = 0x1000;
  Sections[SectionShstrtab].sh_name        = SectionNameShstrtab;
  Sections[SectionShstrtab].sh_type        = SHT_STRTAB;
  Sections[SectionShstrtab].sh_offset      = TEST_SHSTRTAB_OFFSET;
  Sections[SectionShstrtab].sh_size        = sizeof (mSectionStrings);
  Sections[SectionShstrtab].sh_addralign   = 1;
  Sections[SectionSymtab].sh_name          = SectionNameSymtab;
  Sections[SectionSymtab].sh_type          = SHT_SYMTAB;
  Sections[SectionSymtab].sh_offset        = TEST_SYMTAB_OFFSET;
  Sections[SectionSymtab].sh_size          = SymbolCount * sizeof (ELF64_SYM);
  Sections[SectionSymtab].sh_link          = SectionStrtab;
  Sections[SectionSymtab].sh_addralign     = 8;
  Sections[SectionSymtab].sh_entsize       = sizeof (ELF64_SYM);
  Sections[SectionStrtab].sh_name          = SectionNameStrtab;
  Sections[SectionStrtab].sh_type          = SHT_STRTAB;
  Sections[SectionStrtab].sh_offset        = TEST_STRTAB_OFFSET;
  Sections[SectionStrtab].sh_size          = sizeof (mSymbolStrings);
  Sections[SectionStrtab].sh_addralign     = 1;

  Symbols = (ELF64_SYM *)(void *)(Storage + TEST_SYMTAB_OFFSET);
  FillSymbol (&Symbols[SymbolEntry], SymbolNameEntry, SectionTextEntry, TEST_TEXT_ADDRESS, 1);
  FillSymbol (&Symbols[SymbolImageStart], SymbolNameImageStart, SectionTextEntry, TEST_TEXT_ADDRESS, 0);
  FillSymbol (
    &Symbols[SymbolImageEnd],
    SymbolNameImageEnd,
    SectionBss,
    (Kind == ElfFixtureBssOutsideImage) ?
      TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT :
      TEST_BSS_ADDRESS + TEST_BSS_SIZE,
    0
    );
  FillSymbol (
    &Symbols[SymbolModulesStart],
    SymbolNameModulesStart,
    SectionModules,
    TEST_MODULES_ADDRESS,
    0
    );
  FillSymbol (
    &Symbols[SymbolModulesEnd],
    SymbolNameModulesEnd,
    SectionModules,
    TEST_MODULES_ADDRESS + CDK2_MODULE_ENTRY_SIZE,
    0
    );
  FillSymbol (
    &Symbols[SymbolFvStart],
    SymbolNameFvStart,
    SectionModules,
    TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT,
    0
    );
  FillSymbol (
    &Symbols[SymbolFvEnd],
    SymbolNameFvEnd,
    SectionModules,
    TEST_MODULES_ADDRESS + CDK2_FV_ALIGNMENT,
    0
    );

  memcpy (Storage + TEST_STRTAB_OFFSET, mSymbolStrings, sizeof (mSymbolStrings));
  memcpy (Storage + TEST_SHSTRTAB_OFFSET, mSectionStrings, sizeof (mSectionStrings));
  Storage[TEST_TEXT_OFFSET] = 0xc3;
  memset (Storage + TEST_MODULES_OFFSET, 0xa5, CDK2_MODULE_ENTRY_SIZE);
  return TEST_FILE_SIZE;
}

static int
WriteBinaryFile (
  const char     *Path,
  const uint8_t  *Data,
  size_t         Size
  )
{
  FILE  *File;
  int   Result;

  File = fopen (Path, "wb");
  if (File == NULL) {
    fprintf (stderr, "cdk2 ELF checker test: cannot create %s: %s\n", Path, strerror (errno));
    return 1;
  }

  Result = 0;
  if (fwrite (Data, 1, Size, File) != Size) {
    fprintf (stderr, "cdk2 ELF checker test: cannot write %s\n", Path);
    Result = 1;
  }

  if (fclose (File) != 0) {
    fprintf (stderr, "cdk2 ELF checker test: cannot close %s\n", Path);
    Result = 1;
  }

  return Result;
}

static void
RedirectToNull (
  void
  )
{
  int  NullFile;

  NullFile = open ("/dev/null", O_WRONLY);
  if (NullFile < 0) {
    return;
  }

  (void)dup2 (NullFile, STDOUT_FILENO);
  (void)dup2 (NullFile, STDERR_FILENO);
  if (NullFile > STDERR_FILENO) {
    close (NullFile);
  }
}

static int
RunChecker (
  const char  *Checker,
  const char  *Path,
  int         ExpectSuccess
  )
{
  pid_t  Child;
  int    Status;
  int    Succeeded;

  Child = fork ();
  if (Child == 0) {
    RedirectToNull ();
    execl (
      Checker,
      Checker,
      "--entry",
      "Cdk2NativeStageEntry",
      Path,
      (char *)NULL
      );
    _exit (127);
  }

  if (Child < 0) {
    fprintf (stderr, "cdk2 ELF checker test: cannot fork: %s\n", strerror (errno));
    return 1;
  }

  if (waitpid (Child, &Status, 0) < 0) {
    fprintf (stderr, "cdk2 ELF checker test: cannot wait for checker: %s\n", strerror (errno));
    return 1;
  }

  if (!WIFEXITED (Status)) {
    fprintf (stderr, "cdk2 ELF checker test: checker exited abnormally\n");
    return 1;
  }

  Succeeded = (WEXITSTATUS (Status) == 0);
  if (Succeeded != ExpectSuccess) {
    fprintf (
      stderr,
      "cdk2 ELF checker test: checker %s %s unexpectedly\n",
      Succeeded ? "accepted" : "rejected",
      Path
      );
    return 1;
  }

  return 0;
}

static int
RunFixture (
  const char        *Checker,
  const char        *Directory,
  const char        *Suffix,
  ELF_FIXTURE_KIND  Kind,
  int               ExpectSuccess
  )
{
  uint8_t  Storage[TEST_FILE_SIZE];
  char     Path[TEST_PATH_SIZE];
  size_t   Size;
  int      Result;

  if (BuildPath (Path, sizeof (Path), Directory, Suffix) != 0) {
    return 1;
  }

  Size = BuildElf (Storage, sizeof (Storage), Kind);
  if (Size == 0) {
    return Expect (0, "fixture storage is too small");
  }

  Result = WriteBinaryFile (Path, Storage, Size);
  if (Result == 0) {
    Result = RunChecker (Checker, Path, ExpectSuccess);
  }

  if (unlink (Path) != 0 && Result == 0) {
    fprintf (stderr, "cdk2 ELF checker test: cannot remove %s: %s\n", Path, strerror (errno));
    Result = 1;
  }

  return Result;
}

int
main (
  int    ArgumentCount,
  char   **Arguments
  )
{
  int  Failures;

  if (ArgumentCount != 3) {
    fprintf (stderr, "usage: %s ELFCHECK BUILD_DIR\n", Arguments[0]);
    return 1;
  }

  Failures = 0;
  Failures += RunFixture (Arguments[1], Arguments[2], "valid", ElfFixtureValid, 1);
  Failures += RunFixture (
                Arguments[1],
                Arguments[2],
                "bad-load-file-range",
                ElfFixtureBadLoadFileRange,
                0
                );
  Failures += RunFixture (
                Arguments[1],
                Arguments[2],
                "overlapping-load",
                ElfFixtureOverlappingLoad,
                0
                );
  Failures += RunFixture (
                Arguments[1],
                Arguments[2],
                "wrapping-load",
                ElfFixtureWrappingLoad,
                0
                );
  Failures += RunFixture (
                Arguments[1],
                Arguments[2],
                "bss-outside-image",
                ElfFixtureBssOutsideImage,
                0
                );

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 ELF checker test: PASS");
  return 0;
}
