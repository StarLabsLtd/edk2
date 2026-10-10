/** @file

  Copyright (c) 2017-2021, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include "SpiCommon.h"

/**
  Acquire SPI MMIO BAR.

  @param[in] PchSpiBase           PCH SPI PCI Base Address

  @retval                         Return SPI BAR Address

**/
UINT32
AcquireSpiBar0 (
  IN  UINTN  PchSpiBase
  )
{
  return MmioRead32 (PchSpiBase + R_SPI_BASE) & ~(B_SPI_BAR0_MASK);
}

/**
  Release SPI MMIO BAR. Do nothing.

  @param[in] PchSpiBase           PCH SPI PCI Base Address

**/
VOID
ReleaseSpiBar0 (
  IN  UINTN  PchSpiBase
  )
{
}

/**
  Set the chipset in-SMM qualification and return its previous state.

  @param[in] EnableSmmSts  Whether flash writes are qualified as SMM accesses.

  @return Previous in-SMM qualification state.
**/
STATIC
BOOLEAN
CpuSmmDisableBiosWriteProtect (
  IN  BOOLEAN  EnableSmmSts
  )
{
  UINT32   Data32;
  BOOLEAN  SmmStsSave;

  Data32     = MmioRead32 (0xFED30880);
  SmmStsSave = (Data32 & BIT0) != 0;
  if (EnableSmmSts) {
    Data32 |= BIT0;
  } else {
    Data32 &= ~BIT0;
  }

  AsmWriteMsr32 (0x000001FE, Data32);
  // Read back the chipset status to complete the qualification change.
  MmioRead32 (0xFED30880);

  return SmmStsSave;
}

/**
  This function is a hook for Spi to disable BIOS Write Protect.

  @param[in] PchSpiBase           PCH SPI PCI Base Address
  @param[in] CpuSmmBwp            Need to disable CPU SMM Bios write protection or not
  @param[out] SmmStsSave          Previous in-SMM qualification, also valid on failure

  @retval EFI_SUCCESS             The protocol instance was properly initialized
  @retval EFI_ACCESS_DENIED       The BIOS Region can only be updated in SMM phase

**/
EFI_STATUS
EFIAPI
DisableBiosWriteProtect (
  IN  UINTN    PchSpiBase,
  IN  UINT8    CpuSmmBwp,
  OUT BOOLEAN  *SmmStsSave
  )
{
  *SmmStsSave = FALSE;

  //
  // Write clear BC_SYNC_SS prior to change WPD from 0 to 1.
  //
  MmioOr8 (PchSpiBase + R_SPI_BCR + 1, (B_SPI_BCR_SYNC_SS >> 8));

  //
  // Enable the access to the BIOS space for both read and write cycles
  //
  MmioOr8 (PchSpiBase + R_SPI_BCR, B_SPI_BCR_BIOSWE);

  if (CpuSmmBwp != 0) {
    *SmmStsSave = CpuSmmDisableBiosWriteProtect (TRUE);
  }

  if ((MmioRead8 (PchSpiBase + R_SPI_BCR) & B_SPI_BCR_BIOSWE) == 0) {
    DEBUG ((DEBUG_ERROR, "SPI BIOS write enable rejected: BCR=0x%04x\n", MmioRead16 (PchSpiBase + R_SPI_BCR)));
    return EFI_ACCESS_DENIED;
  }

  return EFI_SUCCESS;
}

/**
  This function is a hook for Spi to enable BIOS Write Protect.

  @param[in] PchSpiBase           PCH SPI PCI Base Address
  @param[in] CpuSmmBwp            Need to disable CPU SMM Bios write protection or not
  @param[in] SmmStsSave           In-SMM qualification to restore

**/
VOID
EFIAPI
EnableBiosWriteProtect (
  IN  UINTN    PchSpiBase,
  IN  UINT8    CpuSmmBwp,
  IN  BOOLEAN  SmmStsSave
  )
{
  //
  // Disable the access to the BIOS space for write cycles
  //
  MmioAnd8 (PchSpiBase + R_SPI_BCR, (UINT8)(~B_SPI_BCR_BIOSWE));

  if (CpuSmmBwp != 0) {
    CpuSmmDisableBiosWriteProtect (SmmStsSave);
  }
}

/**
  This function disables SPI Prefetching and caching,
  and returns previous BIOS Control Register value before disabling.

  @param[in] PchSpiBase           PCH SPI PCI Base Address

  @retval                         Previous BIOS Control Register value

**/
UINT8
SaveAndDisableSpiPrefetchCache (
  IN  UINTN  PchSpiBase
  )
{
  UINT8  BiosCtlSave;

  BiosCtlSave = MmioRead8 (PchSpiBase + R_SPI_BCR) & B_SPI_BCR_SRC;

  MmioAndThenOr8 (
    PchSpiBase + R_SPI_BCR, \
    (UINT8)(~B_SPI_BCR_SRC), \
    (UINT8)(V_SPI_BCR_SRC_PREF_DIS_CACHE_DIS <<  N_SPI_BCR_SRC)
    );

  return BiosCtlSave;
}

/**
  This function updates BIOS Control Register with the given value.

  @param[in] PchSpiBase           PCH SPI PCI Base Address
  @param[in] BiosCtlValue         BIOS Control Register Value to be updated

**/
VOID
SetSpiBiosControlRegister (
  IN  UINTN  PchSpiBase,
  IN  UINT8  BiosCtlValue
  )
{
  MmioAndThenOr8 (PchSpiBase + R_SPI_BCR, (UINT8) ~B_SPI_BCR_SRC, BiosCtlValue);
}
