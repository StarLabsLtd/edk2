/** @file
  Remap AMD external GOP framebuffers for CPU access on x86-64.
**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/AmdGopFramebufferMapLib.h>

#define MAX_GOP_FRAMEBUFFER_MAPS  8

typedef struct {
  EFI_GRAPHICS_OUTPUT_PROTOCOL              *Gop;
  EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE   QueryMode;
  EFI_GRAPHICS_OUTPUT_PROTOCOL_SET_MODE     SetMode;
  EFI_GRAPHICS_OUTPUT_PROTOCOL_BLT          Blt;
  EFI_PHYSICAL_ADDRESS                      PhysicalBase;
  EFI_PHYSICAL_ADDRESS                      HostBase;
  UINTN                                     MappedSize;
  BOOLEAN                                   Hooked;
} GOP_FRAMEBUFFER_STATE;

STATIC GOP_FRAMEBUFFER_STATE  mFramebufferMaps[MAX_GOP_FRAMEBUFFER_MAPS];
STATIC UINTN                  mFramebufferMapCount;
STATIC EFI_HANDLE             mImageHandle;

STATIC
VOID
RemapGraphicsOutputFramebufferOnGop (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  );

STATIC
EFI_STATUS
EFIAPI
HookedGopQueryMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL          *This,
  IN  UINT32                                ModeNumber,
  OUT UINTN                                 *SizeOfInfo,
  OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  **Info
  );

STATIC
EFI_STATUS
EFIAPI
HookedGopSetMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL  *This,
  IN  UINT32                        ModeNumber
  );

STATIC
EFI_STATUS
EFIAPI
HookedGopBlt (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL       *This,
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BltBuffer OPTIONAL,
  IN  EFI_GRAPHICS_OUTPUT_BLT_OPERATION  BltOperation,
  IN  UINTN                              SourceX,
  IN  UINTN                              SourceY,
  IN  UINTN                              DestinationX,
  IN  UINTN                              DestinationY,
  IN  UINTN                              Width,
  IN  UINTN                              Height,
  IN  UINTN                              Delta OPTIONAL
  );

VOID
EFIAPI
AmdGopFramebufferMapLibSetImageHandle (
  IN EFI_HANDLE  ImageHandle
  )
{
  mImageHandle = ImageHandle;
}

STATIC
BOOLEAN
IsSubCanonicalMmioAddress (
  IN UINT64  Address
  )
{
  return ((Address & BIT47) != 0) && ((Address & 0xFFFF000000000000ULL) == 0);
}

STATIC
UINT64
CanonicalMmioAddress (
  IN UINT64  Address
  )
{
  if (IsSubCanonicalMmioAddress (Address)) {
    Address |= 0xFFFF000000000000ULL;
  }

  return Address;
}

STATIC
EFI_PHYSICAL_ADDRESS
MaskTo48BitPhysical (
  IN EFI_PHYSICAL_ADDRESS  Address
  )
{
  return Address & 0xFFFFFFFFFFFFULL;
}

STATIC
VOID
EnsureFramebufferInGcd (
  IN EFI_PHYSICAL_ADDRESS  PhysicalBase,
  IN UINTN                 FrameBufferSize
  )
{
  EFI_STATUS                       Status;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR  Descriptor;

  PhysicalBase = MaskTo48BitPhysical (PhysicalBase);

  Status = gDS->GetMemorySpaceDescriptor (PhysicalBase, &Descriptor);
  if (Status == EFI_NOT_FOUND) {
    Status = gDS->AddMemorySpace (
                    EfiGcdMemoryTypeMemoryMappedIo,
                    PhysicalBase,
                    FrameBufferSize,
                    EFI_MEMORY_UC
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_WARN,
        "AmdGopFramebufferMap: AddMemorySpace [%016lx, %016lx) failed: %r\n",
        PhysicalBase,
        PhysicalBase + FrameBufferSize,
        Status
        ));
      return;
    }
  }

  Status = gDS->SetMemorySpaceAttributes (
                  PhysicalBase,
                  FrameBufferSize,
                  EFI_MEMORY_UC
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "AmdGopFramebufferMap: SetMemorySpaceAttributes [%016lx, %016lx) failed: %r\n",
      PhysicalBase,
      PhysicalBase + FrameBufferSize,
      Status
      ));
  }
}

STATIC
GOP_FRAMEBUFFER_STATE *
FindFramebufferStateByGop (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  UINTN  Index;

  for (Index = 0; Index < mFramebufferMapCount; Index++) {
    if (mFramebufferMaps[Index].Gop == Gop) {
      return &mFramebufferMaps[Index];
    }
  }

  return NULL;
}

STATIC
GOP_FRAMEBUFFER_STATE *
FindFramebufferStateByPhysical (
  IN EFI_PHYSICAL_ADDRESS  PhysicalBase
  )
{
  UINTN  Index;

  PhysicalBase = MaskTo48BitPhysical (PhysicalBase);

  for (Index = 0; Index < mFramebufferMapCount; Index++) {
    if (mFramebufferMaps[Index].PhysicalBase == PhysicalBase) {
      return &mFramebufferMaps[Index];
    }
  }

  return NULL;
}

STATIC
GOP_FRAMEBUFFER_STATE *
AllocateFramebufferState (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  GOP_FRAMEBUFFER_STATE  *State;

  State = FindFramebufferStateByGop (Gop);
  if (State != NULL) {
    return State;
  }

  if (mFramebufferMapCount >= MAX_GOP_FRAMEBUFFER_MAPS) {
    return NULL;
  }

  State           = &mFramebufferMaps[mFramebufferMapCount++];
  State->Gop      = Gop;
  State->Hooked   = FALSE;
  State->MappedSize = 0;
  return State;
}

STATIC
EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE
GetOriginalGopQueryMode (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  GOP_FRAMEBUFFER_STATE  *State;

  State = FindFramebufferStateByGop (Gop);
  if ((State != NULL) && (State->Hooked) && (State->QueryMode != NULL)) {
    return State->QueryMode;
  }

  return Gop->QueryMode;
}

STATIC
UINTN
ComputeFrameBufferSizeFromModeInfo (
  IN CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  *Info
  )
{
  UINTN  BytesPerPixel;

  if (Info == NULL) {
    return 0;
  }

  switch (Info->PixelFormat) {
    case PixelRedGreenBlueReserved8BitPerColor:
    case PixelBlueGreenRedReserved8BitPerColor:
      BytesPerPixel = 4;
      break;
    case PixelBitMask:
    case PixelBltOnly:
      return 0;
    default:
      BytesPerPixel = 4;
      break;
  }

  return (UINTN)Info->HorizontalResolution * (UINTN)Info->VerticalResolution * BytesPerPixel;
}

STATIC
UINTN
RefreshGopFramebufferSize (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  EFI_STATUS                             Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL_QUERY_MODE  QueryMode;
  UINTN                                  SizeOfInfo;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION   *Info;
  UINT32                                 ModeNumber;
  UINTN                                  FrameBufferSize;

  if ((Gop == NULL) || (Gop->Mode == NULL)) {
    return 0;
  }

  FrameBufferSize = Gop->Mode->FrameBufferSize;
  if (FrameBufferSize != 0) {
    return FrameBufferSize;
  }

  ModeNumber = Gop->Mode->Mode;
  QueryMode  = GetOriginalGopQueryMode (Gop);
  Info       = NULL;
  Status     = QueryMode (Gop, ModeNumber, &SizeOfInfo, &Info);
  if (!EFI_ERROR (Status) && (Info != NULL)) {
    FrameBufferSize = ComputeFrameBufferSizeFromModeInfo (Info);
    FreePool (Info);
  }

  if (FrameBufferSize != 0) {
    DEBUG ((
      DEBUG_VERBOSE,
      "AmdGopFramebufferMap: derived FB size %u from QueryMode(%u)\n",
      FrameBufferSize,
      ModeNumber
      ));
    return FrameBufferSize;
  }

  return 0;
}

STATIC
BOOLEAN
GopNeedsFramebufferRemap (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop,
  IN GOP_FRAMEBUFFER_STATE         *State OPTIONAL
  )
{
  if ((Gop == NULL) || (Gop->Mode == NULL)) {
    return FALSE;
  }

  if (Gop->Mode->FrameBufferBase == 0) {
    return FALSE;
  }

  if (IsSubCanonicalMmioAddress (Gop->Mode->FrameBufferBase)) {
    return TRUE;
  }

  if ((State != NULL) && (State->HostBase != 0) &&
      (Gop->Mode->FrameBufferBase != State->HostBase))
  {
    return TRUE;
  }

  return FALSE;
}

STATIC
EFI_STATUS
MapFramebufferForCpu (
  IN  EFI_PHYSICAL_ADDRESS  PhysicalBase,
  IN  UINTN                 FrameBufferSize,
  OUT EFI_PHYSICAL_ADDRESS  *HostBase
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  HostAddress;
  EFI_PHYSICAL_ADDRESS  Phys48;

  Phys48      = MaskTo48BitPhysical (PhysicalBase);
  HostAddress = CanonicalMmioAddress (Phys48);

  EnsureFramebufferInGcd (Phys48, FrameBufferSize);

  Status = gDS->AllocateMemorySpace (
                  EfiGcdAllocateAddress,
                  EfiGcdMemoryTypeMemoryMappedIo,
                  0,
                  FrameBufferSize,
                  &HostAddress,
                  mImageHandle,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_VERBOSE,
      "AmdGopFramebufferMap: AllocateMemorySpace @%016lx (%u bytes): %r\n",
      HostAddress,
      FrameBufferSize,
      Status
      ));
    HostAddress = CanonicalMmioAddress (Phys48);
  }

  *HostBase = HostAddress;
  return EFI_SUCCESS;
}

STATIC
VOID
InstallGopHooks (
  IN OUT GOP_FRAMEBUFFER_STATE         *State,
  IN     EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  if ((State == NULL) || (State->Hooked) || (Gop == NULL)) {
    return;
  }

  State->Gop       = Gop;
  State->QueryMode = Gop->QueryMode;
  State->SetMode   = Gop->SetMode;
  State->Blt       = Gop->Blt;
  Gop->QueryMode   = HookedGopQueryMode;
  Gop->SetMode     = HookedGopSetMode;
  Gop->Blt         = HookedGopBlt;
  State->Hooked    = TRUE;
}

STATIC
VOID
EnsureGopHooksForSubCanonicalBase (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  EFI_PHYSICAL_ADDRESS  PhysicalBase;
  GOP_FRAMEBUFFER_STATE *State;

  if ((Gop == NULL) || (Gop->Mode == NULL)) {
    return;
  }

  PhysicalBase = Gop->Mode->FrameBufferBase;
  if ((PhysicalBase == 0) || !IsSubCanonicalMmioAddress (PhysicalBase)) {
    return;
  }

  State = AllocateFramebufferState (Gop);
  if (State != NULL) {
    InstallGopHooks (State, Gop);
  }
}

STATIC
EFI_STATUS
EFIAPI
HookedGopQueryMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL          *This,
  IN  UINT32                                ModeNumber,
  OUT UINTN                                 *SizeOfInfo,
  OUT EFI_GRAPHICS_OUTPUT_MODE_INFORMATION  **Info
  )
{
  GOP_FRAMEBUFFER_STATE  *State;
  EFI_STATUS             Status;

  State = FindFramebufferStateByGop (This);
  if ((State == NULL) || (State->QueryMode == NULL)) {
    return EFI_UNSUPPORTED;
  }

  Status = State->QueryMode (This, ModeNumber, SizeOfInfo, Info);
  RemapGraphicsOutputFramebufferOnGop (This);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
HookedGopSetMode (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL  *This,
  IN  UINT32                        ModeNumber
  )
{
  GOP_FRAMEBUFFER_STATE  *State;
  EFI_STATUS             Status;

  State = FindFramebufferStateByGop (This);
  if ((State == NULL) || (State->SetMode == NULL)) {
    return EFI_UNSUPPORTED;
  }

  Status = State->SetMode (This, ModeNumber);
  RemapGraphicsOutputFramebufferOnGop (This);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
HookedGopBlt (
  IN  EFI_GRAPHICS_OUTPUT_PROTOCOL       *This,
  IN  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *BltBuffer OPTIONAL,
  IN  EFI_GRAPHICS_OUTPUT_BLT_OPERATION  BltOperation,
  IN  UINTN                              SourceX,
  IN  UINTN                              SourceY,
  IN  UINTN                              DestinationX,
  IN  UINTN                              DestinationY,
  IN  UINTN                              Width,
  IN  UINTN                              Height,
  IN  UINTN                              Delta OPTIONAL
  )
{
  GOP_FRAMEBUFFER_STATE  *State;

  State = FindFramebufferStateByGop (This);
  if ((State == NULL) || (State->Blt == NULL)) {
    return EFI_UNSUPPORTED;
  }

  RemapGraphicsOutputFramebufferOnGop (This);
  return State->Blt (
                 This,
                 BltBuffer,
                 BltOperation,
                 SourceX,
                 SourceY,
                 DestinationX,
                 DestinationY,
                 Width,
                 Height,
                 Delta
                 );
}

STATIC
VOID
RemapGraphicsOutputFramebufferOnGop (
  IN EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
  )
{
  EFI_PHYSICAL_ADDRESS    PhysicalBase;
  EFI_PHYSICAL_ADDRESS    HostBase;
  UINTN                   FrameBufferSize;
  GOP_FRAMEBUFFER_STATE   *State;
  GOP_FRAMEBUFFER_STATE   *PhysicalState;
  BOOLEAN                 NeedsRemap;

  if ((Gop == NULL) || (Gop->Mode == NULL)) {
    return;
  }

  EnsureGopHooksForSubCanonicalBase (Gop);

  FrameBufferSize = RefreshGopFramebufferSize (Gop);

  PhysicalBase = Gop->Mode->FrameBufferBase;
  if (PhysicalBase == 0) {
    return;
  }

  State      = AllocateFramebufferState (Gop);
  NeedsRemap = GopNeedsFramebufferRemap (Gop, State);
  if (!NeedsRemap) {
    return;
  }

  if (FrameBufferSize == 0) {
    return;
  }

  PhysicalBase = MaskTo48BitPhysical (PhysicalBase);
  State          = AllocateFramebufferState (Gop);
  if (State == NULL) {
    return;
  }

  if ((State->PhysicalBase != 0) && (State->PhysicalBase != PhysicalBase)) {
    MapFramebufferForCpu (PhysicalBase, FrameBufferSize, &State->HostBase);
    DEBUG ((
      DEBUG_INFO,
      "AmdGopFramebufferMap: GOP FB moved %016lx -> %016lx (%u bytes)\n",
      PhysicalBase,
      State->HostBase,
      FrameBufferSize
      ));
    State->PhysicalBase = PhysicalBase;
    State->MappedSize   = FrameBufferSize;
  } else if ((State->HostBase == 0) ||
             (State->MappedSize < FrameBufferSize) ||
             IsSubCanonicalMmioAddress (Gop->Mode->FrameBufferBase))
  {
    PhysicalState = FindFramebufferStateByPhysical (PhysicalBase);
    if ((PhysicalState != NULL) && (PhysicalState != State) &&
        (PhysicalState->HostBase != 0) &&
        (PhysicalState->MappedSize >= FrameBufferSize))
    {
      HostBase = PhysicalState->HostBase;
    } else {
      MapFramebufferForCpu (PhysicalBase, FrameBufferSize, &HostBase);
      DEBUG ((
        DEBUG_INFO,
        "AmdGopFramebufferMap: GOP FB %016lx -> %016lx (%u bytes)\n",
        PhysicalBase,
        HostBase,
        FrameBufferSize
        ));
    }

    State->PhysicalBase = PhysicalBase;
    State->HostBase     = HostBase;
    State->MappedSize   = FrameBufferSize;
  }

  Gop->Mode->FrameBufferBase = State->HostBase;
  InstallGopHooks (State, Gop);
}

STATIC
VOID
RemapGraphicsOutputFramebuffer (
  IN EFI_HANDLE  Handle
  )
{
  EFI_STATUS                    Status;
  EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop;

  Status = gBS->HandleProtocol (
                  Handle,
                  &gEfiGraphicsOutputProtocolGuid,
                  (VOID **)&Gop
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  RemapGraphicsOutputFramebufferOnGop (Gop);
}

VOID
EFIAPI
RemapAllGraphicsOutputFramebuffers (
  VOID
  )
{
  EFI_STATUS  Status;
  UINTN       HandleCount;
  EFI_HANDLE  *Handles;
  UINTN       Index;

  Handles = NULL;
  Status  = gBS->LocateHandleBuffer (
                   ByProtocol,
                   &gEfiGraphicsOutputProtocolGuid,
                   NULL,
                   &HandleCount,
                   &Handles
                   );
  if (EFI_ERROR (Status)) {
    return;
  }

  DEBUG ((
    DEBUG_INFO,
    "AmdGopFramebufferMap: remapping %u GOP instance(s)\n",
    HandleCount
    ));

  for (Index = 0; Index < HandleCount; Index++) {
    RemapGraphicsOutputFramebuffer (Handles[Index]);
  }

  FreePool (Handles);
}
