/** @file
  Merlin EC Implementation

  Copyright (c) 2025
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "EcAcpiBatteryStatusDxe.h"
#include <Library/DebugLib.h>
#include <Library/IoLib.h>

//
// Merlin EC RAM Battery Offsets
//
#define MERLIN_ECRAM_POWER_STATE               0x80  // Power state register
  #define MERLIN_POWER_CHARGER_CONNECTED       BIT0  // Charger is connected
  #define MERLIN_BATTERY_PRESENT               BIT1  // Battery is present
  #define MERLIN_BATTERY_DETECTED              BIT2  // Battery is detected
  #define MERLIN_POWER_BATTERY_CHARGING        BIT6  // Battery is charging
#define MERLIN_ECRAM_BATTERY_STATE             0x8c  // Battery state register
  #define MERLIN_BATTERY_CHARGING              BIT1  // Battery is charging
  #define MERLIN_BATTERY_CRITICAL              BIT2  // Battery is critical
#define MERLIN_ECRAM_BATTERY_DESIGN_CAP        0x84  // 2 bytes
#define MERLIN_ECRAM_BATTERY_FULL_CHARGE_CAP   0x88  // 2 bytes
#define MERLIN_ECRAM_BATTERY_REMAINING_CAP     0x8f  // 2 bytes
#define MERLIN_ECRAM_BATTERY_REL_STATE_OF_CHRG 0x93  // 2 bytes
#define MERLIN_BATTERY_WORD_UNKNOWN            0xffff

/**
  Read a byte from Merlin EC RAM.

  @param[in]  Address   EC RAM address to read
  @param[out] Data      Pointer to store the read data

  @retval EFI_SUCCESS         Data read successfully
  @retval EFI_DEVICE_ERROR    EC communication error
  @retval EFI_TIMEOUT         Timeout waiting for EC
**/
STATIC
EFI_STATUS
MerlinEcReadByte (
  IN  UINT8   Address,
  OUT UINT8   *Data
  )
{
  EFI_STATUS  Status;

  // Send read command
  Status = WaitForEcReadySend ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_SC, RD_EC);

  // Send address
  Status = WaitForEcReadySend ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_DATA, Address);

  // Read data
  Status = WaitForEcReadyRecv ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Data = IoRead8 (EC_DATA);

  return EFI_SUCCESS;
}

/**
  Read a 16-bit word from Merlin EC RAM (little-endian).

  @param[in]  Address   EC RAM address to read
  @param[out] Data      Pointer to store the read data

  @retval EFI_SUCCESS         Data read successfully
  @retval EFI_DEVICE_ERROR    EC communication error
  @retval EFI_TIMEOUT         Timeout waiting for EC
**/
STATIC
EFI_STATUS
MerlinEcReadWord (
  IN  UINT8    Address,
  OUT UINT16   *Data
  )
{
  EFI_STATUS  Status;
  UINT8       Low;
  UINT8       High;

  Status = MerlinEcReadByte (Address, &Low);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MerlinEcReadByte (Address + 1, &High);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Data = (UINT16)((High << 8) | Low);

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
MerlinBatteryCapacityValid (
  IN UINT16  Capacity
  )
{
  return (Capacity != 0) && (Capacity != MERLIN_BATTERY_WORD_UNKNOWN);
}

STATIC
EFI_STATUS
ReadMerlinBatteryFullChargeCapacity (
  OUT UINT16  *FullChargeCapacity
  )
{
  EFI_STATUS  Status;

  Status = MerlinEcReadWord (MERLIN_ECRAM_BATTERY_FULL_CHARGE_CAP, FullChargeCapacity);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "EcAcpiBattery: Failed to read battery full charge capacity: %r\n", Status));
    return Status;
  }

  if (MerlinBatteryCapacityValid (*FullChargeCapacity)) {
    return EFI_SUCCESS;
  }

  Status = MerlinEcReadWord (MERLIN_ECRAM_BATTERY_DESIGN_CAP, FullChargeCapacity);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "EcAcpiBattery: Failed to read battery design capacity: %r\n", Status));
  }

  return Status;
}

STATIC
EFI_STATUS
ReadMerlinBatteryPercentage (
  OUT UINT8   *BatteryPercentage,
  OUT UINT16  *RelativeStateOfCharge,
  OUT UINT16  *RemainingCapacity,
  OUT UINT16  *FullChargeCapacity
  )
{
  EFI_STATUS  Status;
  UINT32      Percentage;

  *BatteryPercentage     = BATTERY_PERCENT_UNKNOWN;
  *RelativeStateOfCharge = MERLIN_BATTERY_WORD_UNKNOWN;
  *RemainingCapacity     = MERLIN_BATTERY_WORD_UNKNOWN;
  *FullChargeCapacity    = MERLIN_BATTERY_WORD_UNKNOWN;

  Status = MerlinEcReadWord (MERLIN_ECRAM_BATTERY_REL_STATE_OF_CHRG, RelativeStateOfCharge);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "EcAcpiBattery: Failed to read battery percentage: %r\n", Status));
    return Status;
  }

  //
  // Coreboot converts valid B1RP to remaining capacity because _BST reports
  // capacity values. This DXE path reports a percentage, so keep valid B1RP
  // directly and mirror coreboot's B1RC/BFCX fallback when B1RP is invalid.
  //
  if (*RelativeStateOfCharge <= 100) {
    *BatteryPercentage = (UINT8)*RelativeStateOfCharge;
    return EFI_SUCCESS;
  }

  Status = ReadMerlinBatteryFullChargeCapacity (FullChargeCapacity);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MerlinEcReadWord (MERLIN_ECRAM_BATTERY_REMAINING_CAP, RemainingCapacity);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "EcAcpiBattery: Failed to read battery remaining capacity: %r\n", Status));
    return Status;
  }

  if (*RemainingCapacity == MERLIN_BATTERY_WORD_UNKNOWN) {
    return EFI_NOT_READY;
  }

  if (MerlinBatteryCapacityValid (*FullChargeCapacity) &&
      (*RemainingCapacity > *FullChargeCapacity))
  {
    *RemainingCapacity = *FullChargeCapacity;
  }

  if (!MerlinBatteryCapacityValid (*FullChargeCapacity)) {
    return EFI_NOT_READY;
  }

  Percentage = ((UINT32)*RemainingCapacity * 100) / *FullChargeCapacity;
  if (Percentage > 100) {
    Percentage = 100;
  }

  *BatteryPercentage = (UINT8)Percentage;
  return EFI_SUCCESS;
}

/**
  Check if Merlin EC is present by reading a known register.

  @retval EFI_SUCCESS      EC is present
  @retval EFI_NOT_FOUND    EC not found
**/
EFI_STATUS
CheckMerlinEcPresent (
  VOID
  )
{
  UINT8       Data;
  EFI_STATUS  Status;

  // Try to read EC RAM version (offset 0x00 in ACPI region)
  Status = MerlinEcReadByte (0x00, &Data);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  // If we get 0xFF, EC is likely not present
  if (Data == 0xFF) {
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}

/**
  Get battery information from Merlin EC.

  @param[out] BatteryPercentage  Battery charge percentage (0-100)
  @param[out] BatteryPresent     TRUE if battery is present
  @param[out] BatteryCharging    TRUE if battery is charging

  @retval EFI_SUCCESS            Battery information retrieved successfully
  @retval EFI_DEVICE_ERROR       Communication error
  @retval EFI_UNSUPPORTED        Battery not available
**/
EFI_STATUS
GetMerlinBatteryInfo (
  OUT UINT8    *BatteryPercentage,
  OUT BOOLEAN  *BatteryPresent,
  OUT BOOLEAN  *BatteryCharging
  )
{
  EFI_STATUS  Status;
  UINT8       PowerState;
  UINT8       BatteryState;
  UINT16      RelativeStateOfCharge;
  UINT16      RemainingCapacity;
  UINT16      FullChargeCapacity;

  if (mEcBatteryPrivate == NULL || !mEcBatteryPrivate->EcPresent) {
    return EFI_UNSUPPORTED;
  }

  // Read power state to determine battery presence
  Status = MerlinEcReadByte (MERLIN_ECRAM_POWER_STATE, &PowerState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "EcAcpiBattery: Failed to read power state at offset 0x%02x: %r\n", MERLIN_ECRAM_POWER_STATE, Status));
    return Status;
  }

  //
  // Match the ACPI battery device and vendor firmware: ECPS bit 1 is the
  // battery-present signal. Some Merlin EC firmware does not assert bit 2.
  //
  *BatteryPresent = ((PowerState & MERLIN_BATTERY_PRESENT) != 0);

  if (!*BatteryPresent) {
    *BatteryCharging   = FALSE;
    *BatteryPercentage = BATTERY_PERCENT_UNKNOWN;
    DEBUG ((DEBUG_INFO, "EcAcpiBattery: [Merlin] No battery present (power_state=0x%02x)\n", PowerState));
    return EFI_UNSUPPORTED;
  }

  // Read battery state for charging status
  Status = MerlinEcReadByte (MERLIN_ECRAM_BATTERY_STATE, &BatteryState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "EcAcpiBattery: Failed to read battery state at offset 0x%02x: %r\n", MERLIN_ECRAM_BATTERY_STATE, Status));
    return Status;
  }

  Status = ReadMerlinBatteryPercentage (
             BatteryPercentage,
             &RelativeStateOfCharge,
             &RemainingCapacity,
             &FullChargeCapacity
             );
  if (EFI_ERROR (Status)) {
    *BatteryPercentage = BATTERY_PERCENT_UNKNOWN;
  }

  *BatteryCharging = ((BatteryState & MERLIN_BATTERY_CHARGING) != 0);

  DEBUG ((
    DEBUG_INFO,
    "EcAcpiBattery: [Merlin] Battery %d%%, Present=%d, Charging=%d "
    "(power_state=0x%02x, battery_state=0x%02x, rsoc=%u, remaining=%u, full=%u)\n",
    *BatteryPercentage,
    *BatteryPresent,
    *BatteryCharging,
    PowerState,
    BatteryState,
    RelativeStateOfCharge,
    RemainingCapacity,
    FullChargeCapacity
    ));

  return EFI_SUCCESS;
}

/**
  Get battery critical state from Merlin EC.

  @param[out] BatteryCritical  TRUE if battery is critical.

  @retval EFI_SUCCESS            Battery critical state retrieved successfully.
  @retval EFI_DEVICE_ERROR       Communication error.
  @retval EFI_UNSUPPORTED        Battery state is not available.

**/
EFI_STATUS
GetMerlinBatteryCritical (
  OUT BOOLEAN  *BatteryCritical
  )
{
  EFI_STATUS  Status;
  UINT8       BatteryState;

  if (mEcBatteryPrivate == NULL || !mEcBatteryPrivate->EcPresent) {
    return EFI_UNSUPPORTED;
  }

  *BatteryCritical = FALSE;

  Status = MerlinEcReadByte (MERLIN_ECRAM_BATTERY_STATE, &BatteryState);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "EcAcpiBattery: Failed to read battery state: %r\n", Status));
    return Status;
  }

  *BatteryCritical = ((BatteryState & MERLIN_BATTERY_CRITICAL) != 0);
  DEBUG ((DEBUG_INFO, "EcAcpiBattery: [Merlin] Battery critical=%d (battery_state=0x%02x)\n", *BatteryCritical, BatteryState));
  return EFI_SUCCESS;
}
