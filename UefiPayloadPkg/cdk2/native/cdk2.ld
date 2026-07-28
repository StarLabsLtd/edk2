/* SPDX-License-Identifier: BSD-2-Clause-Patent */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(Cdk2NativeStageEntry)

PHDRS
{
  text PT_LOAD FLAGS(5);
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

  .cdk2.modules ALIGN(16) :
  {
    __cdk2_modules_start = .;
    KEEP(*(.cdk2.modules))
    __cdk2_modules_end = .;
  } :text

  .rodata ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    *(.rodata .rodata.*)
  } :text

  /* Match the 128-byte alignment declared by the firmware-volume header. */
  .cdk2.fv ALIGN(128) :
  {
    __cdk2_fv_start = .;
    KEEP(*(.cdk2.fv))
    __cdk2_fv_end = .;
  } :text

  .data ALIGN(CONSTANT (MAXPAGESIZE)) :
  {
    *(.data .data.*)
  } :data

  .bss ALIGN(CONSTANT (MAXPAGESIZE)) (NOLOAD) :
  {
    *(.bss .bss.* COMMON)
  } :data

  __cdk2_image_end = .;

  /DISCARD/ :
  {
    *(.comment)
    *(.note*)
    *(.eh_frame*)
  }
}
