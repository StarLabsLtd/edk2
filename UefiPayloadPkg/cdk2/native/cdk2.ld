/* SPDX-License-Identifier: BSD-2-Clause-Patent */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(Cdk2NativeStageEntry)

PHDRS
{
  text PT_LOAD FLAGS(5);
  rodata PT_LOAD FLAGS(4);
  data PT_LOAD FLAGS(6);
}

SECTIONS
{
  . = 0x00100000;
  __cdk2_image_start = .;

  .text.entry ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    KEEP(*(.text.entry))
  } :text

  .text ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    *(.text .text.*)
  } :text

  .cdk2.modules ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    __cdk2_modules_start = .;
    KEEP(*(.cdk2.modules))
    __cdk2_modules_end = .;
  } :rodata

  .rodata ALIGN(16) :
  {
    *(.rodata .rodata.*)
  } :rodata

  /* Match the 128-byte alignment declared by the firmware-volume header. */
  .cdk2.fv ALIGN(128) :
  {
    __cdk2_fv_start = .;
    KEEP(*(.cdk2.fv))
    __cdk2_fv_end = .;
  } :rodata

  .data ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    *(.data .data.*)
  } :data

  .bss ALIGN(CONSTANT (MAXPAGESIZE)) (NOLOAD) :
  {
    *(.bss .bss.* COMMON)
  } :data

  __cdk2_image_end = .;

  ASSERT(__cdk2_image_end > __cdk2_image_start, "cdk2 native image is empty")
  ASSERT((__cdk2_modules_end - __cdk2_modules_start) != 0, "cdk2 native module table is empty")
  ASSERT(((__cdk2_modules_end - __cdk2_modules_start) % 16) == 0, "cdk2 native module table has invalid size")
  ASSERT((__cdk2_fv_start % 128) == 0, "cdk2 FV section is not 128-byte aligned")
  ASSERT(__cdk2_fv_end >= __cdk2_fv_start, "cdk2 FV section wraps")

  /DISCARD/ :
  {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
  }
}
