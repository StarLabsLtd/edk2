/** @file
  Reconcile GCD attributes for PCI MMIO apertures before PciHostBridgeDxe.
**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PciHostBridgeLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>

STATIC
BOOLEAN
ApertureIsValid (
  IN CONST PCI_ROOT_BRIDGE_APERTURE  *Aperture
  )
{
  if (Aperture == NULL) {
    return FALSE;
  }

  if ((Aperture->Base == 0) || (Aperture->Base >= Aperture->Limit)) {
    return FALSE;
  }

  if (Aperture->Base == MAX_UINT64) {
    return FALSE;
  }

  return TRUE;
}

STATIC
BOOLEAN
DescriptorCoversRange (
  IN CONST EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *Descriptor,
  IN UINT64                                 Base,
  IN UINT64                                 Length
  )
{
  UINT64  End;

  if ((Descriptor == NULL) || (Length == 0)) {
    return FALSE;
  }

  End = Base + Length;
  return (Descriptor->BaseAddress <= Base) &&
         ((Descriptor->BaseAddress + Descriptor->Length) >= End);
}

STATIC
EFI_STATUS
AddMmioUcRegion (
  IN UINT64  Base,
  IN UINT64  Length
  )
{
  EFI_STATUS  Status;

  if (Length == 0) {
    return EFI_SUCCESS;
  }

  Status = gDS->AddMemorySpace (
                  EfiGcdMemoryTypeMemoryMappedIo,
                  Base,
                  Length,
                  EFI_MEMORY_UC
                  );
  if (EFI_ERROR (Status) && (Status != EFI_ALREADY_STARTED)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "PciGcdMmioFixup: AddMemorySpace [%016lx, %016lx) returned %r\n",
      Base,
      Base + Length,
      Status
      ));
  }

  return gDS->SetMemorySpaceAttributes (Base, Length, EFI_MEMORY_UC);
}

STATIC
EFI_STATUS
RemoveAndAddMmioUcRegion (
  IN UINT64  Base,
  IN UINT64  Length
  )
{
  EFI_STATUS  Status;

  if (Length == 0) {
    return EFI_SUCCESS;
  }

  Status = gDS->RemoveMemorySpace (Base, Length);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "PciGcdMmioFixup: RemoveMemorySpace [%016lx, %016lx) returned %r\n",
      Base,
      Base + Length,
      Status
      ));
  }

  return AddMmioUcRegion (Base, Length);
}

STATIC
EFI_STATUS
ApplyMmioUcAttributes (
  IN UINT64                                 Base,
  IN UINT64                                 Length,
  IN CONST EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *Descriptor OPTIONAL
  )
{
  EFI_STATUS  Status;

  if (Length == 0) {
    return EFI_SUCCESS;
  }

  Status = AddMmioUcRegion (Base, Length);
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  Status = RemoveAndAddMmioUcRegion (Base, Length);
  if (!EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_INFO,
      "PciGcdMmioFixup: fixed [%016lx, %016lx) after remove/add\n",
      Base,
      Base + Length
      ));
    return EFI_SUCCESS;
  }

  if ((Descriptor != NULL) &&
      ((Base != Descriptor->BaseAddress) || (Length != Descriptor->Length)))
  {
    Status = gDS->RemoveMemorySpace (
                    Descriptor->BaseAddress,
                    Descriptor->Length
                    );
    if (!EFI_ERROR (Status) || (Status == EFI_NOT_FOUND)) {
      Status = AddMmioUcRegion (Base, Length);
      if (!EFI_ERROR (Status)) {
        DEBUG ((
          DEBUG_INFO,
          "PciGcdMmioFixup: fixed [%016lx, %016lx) after descriptor remove\n",
          Base,
          Base + Length
          ));
        return EFI_SUCCESS;
      }
    }
  }

  DEBUG ((
    DEBUG_WARN,
    "PciGcdMmioFixup: SetMemorySpaceAttributes [%016lx, %016lx) failed: %r\n",
    Base,
    Base + Length,
    Status
    ));
  return Status;
}

STATIC
EFI_STATUS
FixMmioOverlap (
  IN UINT64                                 IntersectionBase,
  IN UINT64                                 IntersectionLength,
  IN CONST EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *Descriptor
  )
{
  if (IntersectionLength == 0) {
    return EFI_SUCCESS;
  }

  DEBUG ((
    DEBUG_INFO,
    "PciGcdMmioFixup: reconcile [%016lx, %016lx) (was type %u cap %016lx)\n",
    IntersectionBase,
    IntersectionBase + IntersectionLength,
    (UINT32)Descriptor->GcdMemoryType,
    Descriptor->Capabilities
    ));

  if ((Descriptor->GcdMemoryType == EfiGcdMemoryTypeMemoryMappedIo) &&
      ((Descriptor->Capabilities & EFI_MEMORY_UC) == EFI_MEMORY_UC) &&
      DescriptorCoversRange (Descriptor, IntersectionBase, IntersectionLength))
  {
    return EFI_SUCCESS;
  }

  if ((IntersectionBase == Descriptor->BaseAddress) &&
      (IntersectionLength == Descriptor->Length))
  {
    return RemoveAndAddMmioUcRegion (IntersectionBase, IntersectionLength);
  }

  return ApplyMmioUcAttributes (IntersectionBase, IntersectionLength, Descriptor);
}

STATIC
EFI_STATUS
EnsureMmioApertureUc (
  IN UINT64  ApertureBase,
  IN UINT64  ApertureLimit
  )
{
  EFI_STATUS                       Status;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR  *MemorySpaceMap;
  UINTN                            NumberOfDescriptors;
  UINTN                            Index;
  UINT64                           ApertureEnd;
  UINT64                           IntersectionBase;
  UINT64                           IntersectionEnd;
  UINT64                           IntersectionLength;
  BOOLEAN                          MapChanged;

  ApertureEnd = ApertureLimit + 1;

  do {
    MapChanged = FALSE;
    Status     = gDS->GetMemorySpaceMap (&NumberOfDescriptors, &MemorySpaceMap);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    for (Index = 0; Index < NumberOfDescriptors; Index++) {
      IntersectionBase = MAX (ApertureBase, MemorySpaceMap[Index].BaseAddress);
      IntersectionEnd  = MIN (
                           ApertureEnd,
                           MemorySpaceMap[Index].BaseAddress + MemorySpaceMap[Index].Length
                           );
      if (IntersectionBase >= IntersectionEnd) {
        continue;
      }

      if ((MemorySpaceMap[Index].GcdMemoryType == EfiGcdMemoryTypeMemoryMappedIo) &&
          ((MemorySpaceMap[Index].Capabilities & EFI_MEMORY_UC) == EFI_MEMORY_UC))
      {
        continue;
      }

      IntersectionLength = IntersectionEnd - IntersectionBase;
      Status             = FixMmioOverlap (
                             IntersectionBase,
                             IntersectionLength,
                             &MemorySpaceMap[Index]
                             );
      if (!EFI_ERROR (Status)) {
        MapChanged = TRUE;
        break;
      }
    }

    FreePool (MemorySpaceMap);
  } while (MapChanged);

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FixRootBridgeAperture (
  IN CONST PCI_ROOT_BRIDGE_APERTURE  *Aperture
  )
{
  if (!ApertureIsValid (Aperture)) {
    return EFI_SUCCESS;
  }

  return EnsureMmioApertureUc (Aperture->Base, Aperture->Limit);
}

STATIC
EFI_STATUS
FixRootBridgeApertures (
  IN CONST PCI_ROOT_BRIDGE  *RootBridge
  )
{
  EFI_STATUS  Status;

  //
  // Only reconcile above-4G apertures. Below-4G MMIO overlaps coreboot's
  // fixed memory map and RemoveMemorySpace is unsafe there.
  //
  Status = FixRootBridgeAperture (&RootBridge->MemAbove4G);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return FixRootBridgeAperture (&RootBridge->PMemAbove4G);
}

EFI_STATUS
EFIAPI
PciGcdMmioFixupEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  PCI_ROOT_BRIDGE  *RootBridges;
  UINTN            RootBridgeCount;
  UINTN            Index;
  EFI_STATUS       Status;

  RootBridges = PciHostBridgeGetRootBridges (&RootBridgeCount);
  if ((RootBridges == NULL) || (RootBridgeCount == 0)) {
    DEBUG ((DEBUG_WARN, "PciGcdMmioFixup: no root bridges found\n"));
    return EFI_SUCCESS;
  }

  for (Index = 0; Index < RootBridgeCount; Index++) {
    Status = FixRootBridgeApertures (&RootBridges[Index]);
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_WARN,
        "PciGcdMmioFixup: bridge %u fix failed: %r\n",
        Index,
        Status
        ));
    }
  }

  PciHostBridgeFreeRootBridges (RootBridges, RootBridgeCount);
  return EFI_SUCCESS;
}
