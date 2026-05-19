/** @file
  Remap AMD external GOP framebuffers for CPU access on x86-64.
**/

#ifndef AMD_GOP_FRAMEBUFFER_MAP_LIB_H_
#define AMD_GOP_FRAMEBUFFER_MAP_LIB_H_

/**
  Provide the DXE image handle used for GCD allocation.
**/
VOID
EFIAPI
AmdGopFramebufferMapLibSetImageHandle (
  IN EFI_HANDLE  ImageHandle
  );

/**
  Map sub-canonical GOP framebuffer addresses and patch Mode->FrameBufferBase.

  AMD external GOP reports GPU framebuffer MMIO in 48-bit physical form (bit 47
  set, bits 63:48 clear). Using that value as a pointer causes #GP; Windows
  Boot Manager reads FrameBufferBase directly and may change it via SetMode.
**/
VOID
EFIAPI
RemapAllGraphicsOutputFramebuffers (
  VOID
  );

#endif
