/** @file
  Production coreboot splash import and BGRT publication tests.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>
#include <vector>

extern "C" {
  #include <PiDxe.h>
  #include <Coreboot.h>
  #include <Guid/BootLogo.h>
  #include <Library/BaseLib.h>
  #include <Library/BmpSupportLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <Library/PcdLib.h>
  #include <Library/HobLib.h>
  #include <Library/BlParseLib.h>
  #include <Library/BootLogoLib.h>
  #include <Library/UefiLib.h>
  #include <IndustryStandard/Acpi.h>
  #include <Protocol/BootLogo.h>
  #include <Protocol/BootLogo2.h>
  #include <Protocol/AcpiTable.h>
  #include <Protocol/PlatformLogo.h>

  UINT16
  CbCheckSum16 (
    UINT16  *Buffer,
    UINTN   Length
    );

  EFI_STATUS EFIAPI
  BootGraphicsDxeEntryPoint (
    EFI_HANDLE        ImageHandle,
    EFI_SYSTEM_TABLE  *SystemTable
    );

  VOID EFIAPI
  BgrtReadyToBootEventNotify (
    EFI_EVENT  Event,
    VOID       *Context
    );

  EFI_GRAPHICS_OUTPUT_PROTOCOL *
  TestCreateGraphics (
    VOID                  *Pixels,
    EFI_PHYSICAL_ADDRESS  PhysicalBase,
    BOOLEAN               LogicalMode
    );

  VOID
  TestSignalGraphicsReadyToBoot (
    EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
    );

  VOID
  TestFreeGraphics (
    EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
    );

  VOID
  TestClearBootPrompt (
    UINTN  X,
    UINTN  Y,
    UINTN  Width,
    UINTN  Height
    );

  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *
  TestCreateConsole (
    EFI_GRAPHICS_OUTPUT_PROTOCOL  *Gop
    );

  VOID
  TestFreeConsole (
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console
    );

  EFI_STATUS
  TestSyncConsole (
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console,
    BOOLEAN                          Adding
    );

  extern EFI_BOOT_LOGO_PROTOCOL  mBootLogoProtocolTemplate;

  extern EDKII_BOOT_LOGO2_PROTOCOL                  mBootLogo2ProtocolTemplate;
  extern EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE  mBootGraphicsResourceTableTemplate;
  extern BOOLEAN                                    mIsLogoValid;
  extern BOOLEAN                                    mAcpiBgrtInstalled;
  extern BOOLEAN                                    mAcpiBgrtStatusChanged;
  extern BOOLEAN                                    mAcpiBgrtBufferChanged;
  extern EFI_GRAPHICS_OUTPUT_BLT_PIXEL              *mLogoBltBuffer;
}

static struct {
  EFI_HOB_GUID_TYPE      Header;
  EDKII_BOOT_LOGO_HOB    Logo;
} mHob;
static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL            *mStartedConsole;
static BOOLEAN                                    mHaveHob;
static EFI_BOOT_SERVICES                          mServices;
static EFI_SYSTEM_TABLE                           mSystemTable;
static EFI_GRAPHICS_OUTPUT_PROTOCOL               mGop;
static EFI_GRAPHICS_OUTPUT_PROTOCOL               *mSelectedGop;
static EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE          mGopMode;
static EFI_GRAPHICS_OUTPUT_MODE_INFORMATION       mGopInfo;
static EFI_ACPI_TABLE_PROTOCOL                    mAcpi;
static EFI_ACPI_5_0_BOOT_GRAPHICS_RESOURCE_TABLE  mPublished;
static UINTN                                      mWrites;
static EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL            mConsole;
static BOOLEAN                                    mCursorVisible;
static BOOLEAN                                    mFailCopy;
static BOOLEAN                                    mFailBmp;
static BOOLEAN                                    mFailInstall;
static BOOLEAN                                    mUsePlatformLogo;
static EDKII_PLATFORM_LOGO_PROTOCOL                mPlatformLogo;
static UINT16                                     mFallbackWidth;
static UINT16                                     mFallbackHeight;
static UINTN                                      mDrawWidth;
static UINTN                                      mDrawHeight;
static UINTN                                      mDrawX;
static UINTN                                      mDrawY;
static std::vector<EFI_GRAPHICS_OUTPUT_BLT_PIXEL>   mFallbackPixels;
static std::vector<EFI_GRAPHICS_OUTPUT_BLT_PIXEL>   mDrawnPixels;

extern "C" {
  VOID *EFIAPI
  __real_AllocateCopyPool (
    UINTN       Size,
    CONST VOID  *Buffer
    );

  VOID *EFIAPI
  __real_AllocateZeroPool (
    UINTN  Size
    );

  VOID *EFIAPI
  __wrap_AllocateCopyPool (
    UINTN       Size,
    CONST VOID  *Buffer
    )
  {
    if (mFailCopy) {
      mFailCopy = FALSE;
      return nullptr;
    }

    return __real_AllocateCopyPool (Size, Buffer);
  }

  VOID *EFIAPI
  __wrap_AllocateZeroPool (
    UINTN  Size
    )
  {
    if (mFailBmp) {
      mFailBmp = FALSE;
      return nullptr;
    }

    return __real_AllocateZeroPool (Size);
  }

  EFI_STATUS
  TestStartConsole (
    VOID
    );

  EFI_GRAPHICS_OUTPUT_PROTOCOL *
  TestCreateStandardGraphics (
    VOID                  *Pixels,
    EFI_PHYSICAL_ADDRESS  Base
    );

  VOID
  TestPublishConsoleMode (
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console
    );
}

extern "C" {
  static EFI_STATUS EFIAPI
  EnableCursor (
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *This,
    BOOLEAN                          Visible
    )
  {
    mCursorVisible = Visible;
    return EFI_SUCCESS;
  }

  EFI_BOOT_SERVICES  *gBS = &mServices;
  EFI_SYSTEM_TABLE   *gST = &mSystemTable;

  static EFI_TPL EFIAPI
  RaiseTpl (
    EFI_TPL  Tpl
    )
  {
    return TPL_APPLICATION;
  }

  static VOID EFIAPI
  RestoreTpl (
    EFI_TPL  Tpl
    )
  {
  }

  EFI_STATUS EFIAPI
  EfiLibInstallDriverBindingComponentName2 (
    CONST EFI_HANDLE                    ImageHandle,
    CONST EFI_SYSTEM_TABLE              *SystemTable,
    EFI_DRIVER_BINDING_PROTOCOL         *DriverBinding,
    EFI_HANDLE                          DriverBindingHandle,
    CONST EFI_COMPONENT_NAME_PROTOCOL   *ComponentName,
    CONST EFI_COMPONENT_NAME2_PROTOCOL  *ComponentName2
    )
  {
    ADD_FAILURE () << "Unexpected driver registration";
    return EFI_UNSUPPORTED;
  }

  EFI_STATUS EFIAPI
  LookupUnicodeString2 (
    CONST CHAR8                     *Language,
    CONST CHAR8                     *SupportedLanguages,
    CONST EFI_UNICODE_STRING_TABLE  *Table,
    CHAR16                          **String,
    BOOLEAN                         Iso639
    )
  {
    ADD_FAILURE () << "Unexpected component-name query";
    return EFI_UNSUPPORTED;
  }

  UINTN EFIAPI
  PrintXY (
    UINTN                          PointX,
    UINTN                          PointY,
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Foreground,
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Background,
    CONST CHAR16                   *Format,
    ...
    )
  {
    ADD_FAILURE () << "Unexpected progress UI output";
    return 0;
  }

  VOID *EFIAPI
  GetNextGuidHob (
    CONST EFI_GUID  *Guid,
    CONST VOID      *Start
    )
  {
    ADD_FAILURE () << "Unexpected CFR traversal";
    return nullptr;
  }

  VOID *EFIAPI
  BuildGuidDataHob (
    CONST EFI_GUID  *Guid,
    VOID            *Data,
    UINTN           Length
    )
  {
    EXPECT_TRUE (CompareGuid (Guid, &gEdkiiBootLogoHobGuid));
    EXPECT_EQ (Length, sizeof (mHob.Logo));
    mHob.Header.Header.HobLength = sizeof (mHob);
    mHob.Header.Name             = *Guid;
    CopyMem (&mHob.Logo, Data, Length);
    mHaveHob = TRUE;
    return &mHob.Logo;
  }

  VOID *EFIAPI
  GetFirstGuidHob (
    CONST EFI_GUID  *Guid
    )
  {
    return mHaveHob && CompareGuid (Guid, &gEdkiiBootLogoHobGuid) ? &mHob : nullptr;
  }

  static EFI_STATUS EFIAPI
  LocateProtocol (
    EFI_GUID  *Guid,
    VOID      *Registration,
    VOID      **Interface
    )
  {
    if (CompareGuid (Guid, &gEfiAcpiTableProtocolGuid)) {
      *Interface = &mAcpi;
    } else if (CompareGuid (Guid, &gEfiBootLogoProtocolGuid)) {
      *Interface = &mBootLogoProtocolTemplate;
    } else if (CompareGuid (Guid, &gEdkiiBootLogo2ProtocolGuid)) {
      *Interface = &mBootLogo2ProtocolTemplate;
    } else if (mUsePlatformLogo && CompareGuid (Guid, &gEdkiiPlatformLogoProtocolGuid)) {
      *Interface = &mPlatformLogo;
    } else {
      return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  HandleProtocol (
    EFI_HANDLE  Handle,
    EFI_GUID    *Guid,
    VOID        **Interface
    )
  {
    *Interface = mSelectedGop;
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  OpenProtocol (
    EFI_HANDLE  Handle,
    EFI_GUID    *Guid,
    VOID        **Interface,
    EFI_HANDLE  Agent,
    EFI_HANDLE  Controller,
    UINT32      Attributes
    )
  {
    EXPECT_TRUE (CompareGuid (Guid, &gEfiGraphicsOutputProtocolGuid));
    *Interface = mSelectedGop;
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  CloseProtocol (
    EFI_HANDLE  Handle,
    EFI_GUID    *Guid,
    EFI_HANDLE  Agent,
    EFI_HANDLE  Controller
    )
  {
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  InstallProtocols (
    EFI_HANDLE  *Handle,
    ...
    )
  {
    VA_LIST  Args;

    VA_START (Args, Handle);
    EFI_GUID  *Guid;

    while ((Guid = VA_ARG (Args, EFI_GUID *)) != nullptr) {
      VOID  *Interface = VA_ARG (Args, VOID *);
      if (CompareGuid (Guid, &gEfiSimpleTextOutProtocolGuid)) {
        mStartedConsole = (EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *)Interface;
      }
    }

    VA_END (Args);
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  CreateEvent (
    UINT32            Type,
    EFI_TPL           Tpl,
    EFI_EVENT_NOTIFY  Notify,
    CONST VOID        *Context,
    CONST EFI_GUID    *Group,
    EFI_EVENT         *Event
    )
  {
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  InstallTable (
    EFI_ACPI_TABLE_PROTOCOL  *This,
    VOID                     *Buffer,
    UINTN                    Length,
    UINTN                    *Key
    )
  {
    if (mFailInstall) {
      mFailInstall = FALSE;
      return EFI_OUT_OF_RESOURCES;
    }

    EXPECT_EQ (Length, sizeof (mPublished));
    CopyMem (&mPublished, Buffer, Length);
    *Key = 1;
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  Blt (
    EFI_GRAPHICS_OUTPUT_PROTOCOL       *This,
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *Buffer,
    EFI_GRAPHICS_OUTPUT_BLT_OPERATION  Operation,
    UINTN                              SourceX,
    UINTN                              SourceY,
    UINTN                              X,
    UINTN                              Y,
    UINTN                              Width,
    UINTN                              Height,
    UINTN                              Delta
    )
  {
    EXPECT_EQ (Operation, EfiBltBufferToVideo);
    EXPECT_EQ (X, (UINTN)12);
    EXPECT_EQ (Y, (UINTN)10);
    EXPECT_EQ (Width, (UINTN)4);
    EXPECT_EQ (Height, (UINTN)4);
    mWrites++;
    return EFI_SUCCESS;
  }
}

static EFI_STATUS EFIAPI
GetFallbackImage (
  EDKII_PLATFORM_LOGO_PROTOCOL            *This,
  UINT32                                  *Instance,
  EFI_IMAGE_INPUT                         *Image,
  EDKII_PLATFORM_LOGO_DISPLAY_ATTRIBUTE    *Attribute,
  INTN                                    *OffsetX,
  INTN                                    *OffsetY
  )
{
  if ((*Instance)++ != 0) {
    return EFI_NOT_FOUND;
  }

  Image->Flags  = 0;
  Image->Width  = mFallbackWidth;
  Image->Height = mFallbackHeight;
  Image->Bitmap = (EFI_GRAPHICS_OUTPUT_BLT_PIXEL *)AllocateCopyPool (
                                                    mFallbackPixels.size () * sizeof (mFallbackPixels[0]),
                                                    mFallbackPixels.data ()
                                                    );
  *Attribute = EdkiiPlatformLogoDisplayAttributeCenter;
  *OffsetX   = 0;
  *OffsetY   = 0;
  return Image->Bitmap != nullptr ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

static EFI_STATUS EFIAPI
RecordFallbackBlt (
  EFI_GRAPHICS_OUTPUT_PROTOCOL       *This,
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL      *Buffer,
  EFI_GRAPHICS_OUTPUT_BLT_OPERATION  Operation,
  UINTN                             SourceX,
  UINTN                             SourceY,
  UINTN                             X,
  UINTN                             Y,
  UINTN                             Width,
  UINTN                             Height,
  UINTN                             Delta
  )
{
  EXPECT_EQ (Operation, EfiBltBufferToVideo);
  EXPECT_EQ (SourceX, (UINTN)0);
  EXPECT_EQ (SourceY, (UINTN)0);
  EXPECT_EQ (Delta, Width * sizeof (*Buffer));
  mDrawWidth = Width;
  mDrawHeight = Height;
  mDrawX = X;
  mDrawY = Y;
  mDrawnPixels.assign (Buffer, Buffer + Width * Height);
  mWrites++;
  return EFI_SUCCESS;
}

class BootSplashTest : public ::testing::Test {
protected:
  struct {
    struct cb_header         Header;
    struct cb_framebuffer    FrameBuffer;
    struct cb_boot_splash    Splash;
    struct cb_cbmem_entry    Owner;
  } Table;
  std::vector<UINT8> Bmp;

  void
  SetUp (
    ) override
  {
    mFailInstall    = FALSE;
    mStartedConsole = nullptr;
    PatchPcdSet8 (PcdBootLogoSourceScale, 1);
    mUsePlatformLogo = FALSE;
    mFallbackPixels.clear ();
    mDrawnPixels.clear ();
    mPlatformLogo.GetImage = GetFallbackImage;
    PatchPcdSet32 (PcdConOutColumn, 80);
    PatchPcdSet32 (PcdConOutRow, 25);
    PatchPcdSet32 (PcdVideoHorizontalResolution, 800);
    PatchPcdSet32 (PcdVideoVerticalResolution, 600);
    ZeroMem (&Table, sizeof (Table));
    ZeroMem (&mHob, sizeof (mHob));
    ZeroMem (&mServices, sizeof (mServices));
    ZeroMem (&mGop, sizeof (mGop));
    ZeroMem (&mGopMode, sizeof (mGopMode));
    ZeroMem (&mGopInfo, sizeof (mGopInfo));
    ZeroMem (&mPublished, sizeof (mPublished));
    mFailCopy                                   = FALSE;
    mFailBmp                                    = FALSE;
    mHaveHob                                    = FALSE;
    mConsole.EnableCursor                       = EnableCursor;
    mSystemTable.ConOut                         = &mConsole;
    mCursorVisible                              = TRUE;
    mWrites                                     = 0;
    mIsLogoValid                                = FALSE;
    mAcpiBgrtInstalled                          = FALSE;
    mAcpiBgrtStatusChanged                      = FALSE;
    mAcpiBgrtBufferChanged                      = FALSE;
    mServices.RaiseTPL                          = RaiseTpl;
    mServices.RestoreTPL                        = RestoreTpl;
    mServices.LocateProtocol                    = LocateProtocol;
    mServices.OpenProtocol                      = OpenProtocol;
    mServices.CloseProtocol                     = CloseProtocol;
    mServices.HandleProtocol                    = HandleProtocol;
    mServices.InstallMultipleProtocolInterfaces = InstallProtocols;
    mServices.CreateEventEx                     = CreateEvent;
    mAcpi.InstallAcpiTable                      = InstallTable;
    mSelectedGop                                = &mGop;
    mGop.Blt                                    = Blt;
    mGop.Mode                                   = &mGopMode;
    mGopMode.Info                               = &mGopInfo;
    mGopMode.FrameBufferBase                    = 0xd0000000;
    mGopInfo.HorizontalResolution               = 32;
    mGopInfo.VerticalResolution                 = 32;
    Bmp.assign (54 + 4 * 4 * 4, 0);
    Bmp[0] = 'B';
    Bmp[1] = 'M';
    WriteUnaligned32 ((UINT32 *)&Bmp[2], (UINT32)Bmp.size ());
    WriteUnaligned32 ((UINT32 *)&Bmp[10], 54);
    WriteUnaligned32 ((UINT32 *)&Bmp[14], 40);
    WriteUnaligned32 ((UINT32 *)&Bmp[18], 4);
    WriteUnaligned32 ((UINT32 *)&Bmp[22], 4);
    WriteUnaligned16 ((UINT16 *)&Bmp[26], 1);
    WriteUnaligned16 ((UINT16 *)&Bmp[28], 32);
    for (UINTN Index = 54; Index < Bmp.size (); Index++) {
      Bmp[Index] = (UINT8)Index;
    }

    Table.Header.signature              = CB_HEADER_SIGNATURE;
    Table.Header.header_bytes           = sizeof (Table.Header);
    Table.Header.table_bytes            = sizeof (Table) - sizeof (Table.Header);
    Table.Header.table_entries          = 3;
    Table.FrameBuffer.tag               = CB_TAG_FRAMEBUFFER;
    Table.FrameBuffer.size              = sizeof (Table.FrameBuffer);
    Table.FrameBuffer.physical_address  = mGopMode.FrameBufferBase;
    Table.FrameBuffer.x_resolution      = 32;
    Table.FrameBuffer.y_resolution      = 32;
    Table.FrameBuffer.bytes_per_line    = 128;
    Table.FrameBuffer.bits_per_pixel    = 32;
    Table.FrameBuffer.red_mask_pos      = 16;
    Table.FrameBuffer.red_mask_size     = 8;
    Table.FrameBuffer.green_mask_pos    = 8;
    Table.FrameBuffer.green_mask_size   = 8;
    Table.FrameBuffer.blue_mask_size    = 8;
    Table.Splash.tag                    = CB_TAG_BOOT_SPLASH;
    Table.Splash.size                   = sizeof (Table.Splash);
    Table.Splash.revision               = 2;
    Table.Splash.flags                  = 3;
    Table.Splash.framebuffer_address.lo = (UINT32)mGopMode.FrameBufferBase;
    Table.Splash.image_offset_x         = 12;
    Table.Splash.image_offset_y         = 10;
    Table.Splash.image_width            = 4;
    Table.Splash.image_height           = 4;
    Table.Splash.bmp_address.lo         = (UINT32)(UINTN)Bmp.data ();
    Table.Splash.bmp_address.hi         = (UINT32)((UINT64)(UINTN)Bmp.data () >> 32);
    Table.Splash.bmp_size               = (UINT32)Bmp.size ();
    Table.Owner.tag                     = CB_TAG_CBMEM_ENTRY;
    Table.Owner.size                    = sizeof (Table.Owner);
    Table.Owner.id                      = CBMEM_ID_BOOT_SPLASH;
    Table.Owner.address                 = Table.Splash.bmp_address;
    Table.Owner.entry_size              = Table.Splash.bmp_size;
    PatchPcdSet64 (PcdBootloaderParameter, (UINTN)&Table.Header);
  }

  void
  TearDown (
    ) override
  {
    if (mLogoBltBuffer != nullptr) {
      FreePool (mLogoBltBuffer);
      mLogoBltBuffer = nullptr;
    }

    if (mBootGraphicsResourceTableTemplate.ImageAddress != 0) {
      FreePool ((VOID *)(UINTN)mBootGraphicsResourceTableTemplate.ImageAddress);
      mBootGraphicsResourceTableTemplate.ImageAddress = 0;
    }
  }

  void
  Parse (
    )
  {
    EFI_PEI_GRAPHICS_INFO_HOB  Gfx;

    Table.Header.header_checksum = 0;
    Table.Header.table_checksum  = CbCheckSum16 ((UINT16 *)&Table.FrameBuffer, Table.Header.table_bytes);
    Table.Header.header_checksum = CbCheckSum16 ((UINT16 *)&Table.Header, sizeof (Table.Header));
    EXPECT_EQ (ParseGfxInfo (&Gfx), RETURN_SUCCESS);
  }
};

TEST_F (BootSplashTest, AdoptsDisplayedImageAndPublishesUnchangedBmp) {
  Parse ();
  ASSERT_TRUE (mHaveHob);
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  EXPECT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  EXPECT_FALSE (mCursorVisible);
  EXPECT_EQ (mLogoBltBuffer, nullptr);
  EXPECT_EQ (mWrites, (UINTN)0);
  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_EQ (mPublished.Status, EFI_ACPI_5_0_BGRT_STATUS_VALID);
  EXPECT_EQ (mPublished.ImageOffsetX, (UINT32)12);
  EXPECT_EQ (mPublished.ImageOffsetY, (UINT32)10);
  EXPECT_EQ (CompareMem ((VOID *)(UINTN)mPublished.ImageAddress, Bmp.data (), Bmp.size ()), (INTN)0);
}

TEST_F (BootSplashTest, LocationQueryDoesNotDecodeAndRequiresCoordinates) {
  UINTN  X, Y, Width, Height;

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  EXPECT_EQ (
    mBootLogo2ProtocolTemplate.GetBootLogo (
                                 &mBootLogo2ProtocolTemplate,
                                 nullptr,
                                 &X,
                                 &Y,
                                 &Width,
                                 &Height
                                 ),
    EFI_SUCCESS
    );
  EXPECT_EQ (X, (UINTN)12);
  EXPECT_EQ (Y, (UINTN)10);
  EXPECT_EQ (mLogoBltBuffer, nullptr);
  EXPECT_EQ (
    mBootLogo2ProtocolTemplate.GetBootLogo (
                                 &mBootLogo2ProtocolTemplate,
                                 nullptr,
                                 nullptr,
                                 &Y,
                                 &Width,
                                 &Height
                                 ),
    EFI_INVALID_PARAMETER
    );
  EXPECT_EQ (mLogoBltBuffer, nullptr);
}

TEST_F (BootSplashTest, IgnoresUnspecifiedReservedBytesWhenReusingLogo) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  *Current;
  UINTN                          X, Y, Width, Height;

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  ASSERT_EQ (
    mBootLogo2ProtocolTemplate.GetBootLogo (
                                 &mBootLogo2ProtocolTemplate,
                                 &Current,
                                 &X,
                                 &Y,
                                 &Width,
                                 &Height
                                 ),
    EFI_SUCCESS
    );
  // Model allocator residue without changing any of the defined color bytes.
  for (UINTN Index = 0; Index < Width * Height; Index++) {
    mLogoBltBuffer[Index].Reserved = 0x7a;
  }

  EXPECT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  EXPECT_EQ (mWrites, (UINTN)0);
}

TEST_F (BootSplashTest, RestoresInvalidatedLogoBeforeMarkingItDisplayed) {
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  ASSERT_EQ (mBootLogo2ProtocolTemplate.SetBootLogo (&mBootLogo2ProtocolTemplate, nullptr, 0, 0, 0, 0), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  EXPECT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  EXPECT_EQ (mWrites, (UINTN)1);
  EXPECT_TRUE (mIsLogoValid);
}

TEST_F (BootSplashTest, ReadyToBootRedrawKeepsTheRegisteredLogoValid) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };
  EFI_GRAPHICS_OUTPUT_PROTOCOL   *Gop;

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, TRUE);
  ASSERT_NE (Gop, nullptr);
  TestSignalGraphicsReadyToBoot (Gop);
  EXPECT_TRUE (mIsLogoValid);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)102);
  EXPECT_EQ (Pixels[10 * 32 + 12].Green, (UINT8)103);
  EXPECT_EQ (Pixels[10 * 32 + 12].Red, (UINT8)104);
  EXPECT_EQ (Pixels[13 * 32 + 15].Blue, (UINT8)66);
  EXPECT_EQ (Pixels[0].Blue, (UINT8)0);
  EXPECT_EQ (Gop->Mode->Mode, (UINT32)0);
  EXPECT_EQ (Gop->Mode->FrameBufferBase, mGopMode.FrameBufferBase);
  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_EQ (mPublished.Status, EFI_ACPI_5_0_BGRT_STATUS_VALID);
  EXPECT_EQ (CompareMem ((VOID *)(UINTN)mPublished.ImageAddress, Bmp.data (), Bmp.size ()), (INTN)0);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, GopPreservesTheExplicitBootLogoValidityContract) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixel           = { };
  EFI_GRAPHICS_OUTPUT_PROTOCOL   *Gop;

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);
  ASSERT_NE (Gop, nullptr);
  EXPECT_EQ (Gop->Blt (Gop, &Pixel, EfiBltVideoFill, 0, 0, 0, 0, 1, 1, 0), EFI_SUCCESS);
  EXPECT_TRUE (mIsLogoValid);
  EXPECT_EQ (Gop->Blt (Gop, &Pixel, EfiBltVideoToBltBuffer, 12, 10, 0, 0, 1, 1, 0), EFI_SUCCESS);
  EXPECT_TRUE (mIsLogoValid);
  // UI owners invalidate through the standard protocol before erasing a logo.
  ASSERT_EQ (mBootLogo2ProtocolTemplate.SetBootLogo (&mBootLogo2ProtocolTemplate, nullptr, 0, 0, 0, 0), EFI_SUCCESS);
  EXPECT_EQ (Gop->Blt (Gop, &Pixel, EfiBltVideoFill, 0, 0, 12, 10, 1, 1, 0), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, ClearsNonoverlappingPromptWithoutDecodingLogo) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);

  ASSERT_NE (Gop, nullptr);
  mSelectedGop              = Gop;
  Pixels[10 * 32 + 12].Blue = 102;
  TestClearBootPrompt (0, 0, 1, 1);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)102);
  EXPECT_EQ (mLogoBltBuffer, nullptr);
  EXPECT_TRUE (mIsLogoValid);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, RestoresLogoPixelsOverlappedByCountdown) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);

  ASSERT_NE (Gop, nullptr);
  mSelectedGop              = Gop;
  Pixels[10 * 32 + 12].Blue = 0xee;
  TestClearBootPrompt (12, 10, 1, 1);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)102);
  EXPECT_TRUE (mIsLogoValid);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, InitialTextConsolePreservesHandedOffPixels) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);

  ASSERT_NE (Gop, nullptr);
  auto  Console = TestCreateConsole (Gop);

  ASSERT_NE (Console, nullptr);
  Pixels[10 * 32 + 12].Blue = 102;
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)102);
  EXPECT_TRUE (mIsLogoValid);
  EXPECT_EQ (mLogoBltBuffer, nullptr);
  // A later explicit SetMode still has the ordinary clear-screen contract.
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)0);
  EXPECT_FALSE (mIsLogoValid);
  TestFreeConsole (Console);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, ConsoleClearAndTextInvalidateTheDisplayedLogo) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);

  ASSERT_NE (Gop, nullptr);
  auto  Console = TestCreateConsole (Gop);

  ASSERT_NE (Console, nullptr);
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  ASSERT_EQ (Console->ClearScreen (Console), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  mSelectedGop = Gop;
  ASSERT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  ASSERT_EQ (Console->OutputString (Console, (CHAR16 *)L""), EFI_SUCCESS);
  EXPECT_TRUE (mIsLogoValid);
  ASSERT_EQ (Console->OutputString (Console, (CHAR16 *)L"\r"), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  TestFreeConsole (Console);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, AddingMatchingConsoleDoesNotClearHandedOffSplash) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);

  ASSERT_NE (Gop, nullptr);
  auto  Console = TestCreateConsole (Gop);

  ASSERT_NE (Console, nullptr);
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  Pixels[10 * 32 + 12].Blue = 102;
  ASSERT_EQ (Console->SetCursorPosition (Console, 3, 0), EFI_SUCCESS);
  ASSERT_EQ (TestSyncConsole (Console, TRUE), EFI_SUCCESS);
  EXPECT_EQ (Console->Mode->CursorColumn, 0);
  EXPECT_EQ (Console->Mode->CursorRow, 0);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)102);
  EXPECT_TRUE (mIsLogoValid);
  ASSERT_EQ (TestSyncConsole (Console, FALSE), EFI_SUCCESS);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)0);
  EXPECT_FALSE (mIsLogoValid);
  TestFreeConsole (Console);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, RejectsWrongFramebufferAndOutOfBoundsGeometry) {
  Table.Splash.framebuffer_address.lo++;
  Parse ();
  EXPECT_FALSE (mHaveHob);
  Table.Splash.framebuffer_address.lo--;
  Table.Splash.image_width = 33;
  Parse ();
  EXPECT_FALSE (mHaveHob);
}

TEST_F (BootSplashTest, RejectsUnownedAndTruncatedImagesBeforeReadingThem) {
  Table.Owner.entry_size--;
  Parse ();
  EXPECT_FALSE (mHaveHob);
  Table.Owner.entry_size++;
  Table.Splash.bmp_address.lo = 1;
  Table.Splash.bmp_address.hi = 0;
  Parse ();
  EXPECT_FALSE (mHaveHob);
}

TEST_F (BootSplashTest, RejectsTruncatedTableAndMalformedBmp) {
  Table.Header.table_bytes--;
  Parse ();
  EXPECT_FALSE (mHaveHob);
  Table.Header.table_bytes++;
  WriteUnaligned32 ((UINT32 *)&Bmp[10], (UINT32)Bmp.size ());
  Parse ();
  EXPECT_FALSE (mHaveHob);
}

TEST_F (BootSplashTest, RejectsTrailingBytesUnsupportedByRestorationDecoder) {
  Bmp.push_back (0);
  WriteUnaligned32 ((UINT32 *)&Bmp[2], (UINT32)Bmp.size ());
  Table.Splash.bmp_address.lo = (UINT32)(UINTN)Bmp.data ();
  Table.Splash.bmp_address.hi = (UINT32)((UINT64)(UINTN)Bmp.data () >> 32);
  Table.Splash.bmp_size       = (UINT32)Bmp.size ();
  Table.Owner.address         = Table.Splash.bmp_address;
  Table.Owner.entry_size      = Table.Splash.bmp_size;
  Parse ();
  EXPECT_FALSE (mHaveHob);
}

TEST_F (BootSplashTest, RejectsUnsupportedRevisionAndIndexedBgrt) {
  Table.Splash.revision = 1;
  Parse ();
  EXPECT_FALSE (mHaveHob);
  Table.Splash.revision = 2;
  WriteUnaligned16 ((UINT16 *)&Bmp[28], 8);
  Parse ();
  EXPECT_FALSE (mHaveHob);
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}

TEST_F (BootSplashTest, PublishedConsoleFirstExplicitModeChangeClears) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop     = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);
  auto  Console = TestCreateConsole (Gop);

  ASSERT_NE (Console, nullptr);
  // DriverStart publishes a valid mode even when no line buffer exists.
  TestPublishConsoleMode (Console);
  Pixels[10 * 32 + 12].Blue = 102;
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  EXPECT_EQ (Pixels[10 * 32 + 12].Blue, (UINT8)0);
  EXPECT_FALSE (mIsLogoValid);
  TestFreeConsole (Console);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, CursorDrawingInvalidatesAndRestorationHidesBeforePainting) {
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Pixels[32 * 32] = { };

  Table.Splash.image_offset_x = 0;
  Table.Splash.image_offset_y = 16;
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop     = TestCreateGraphics (Pixels, mGopMode.FrameBufferBase, FALSE);
  auto  Console = TestCreateConsole (Gop);

  ASSERT_NE (Console, nullptr);
  ASSERT_EQ (Console->SetMode (Console, 0), EFI_SUCCESS);
  mSystemTable.ConOut = Console;
  mSelectedGop        = Gop;
  ASSERT_EQ (Console->EnableCursor (Console, TRUE), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  // A failed/overwritten screen may still contain a visible hardware cursor.
  mIsLogoValid = FALSE;
  ASSERT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  EXPECT_FALSE (Console->Mode->CursorVisible);
  EXPECT_TRUE (mIsLogoValid);
  for (UINTN Y = 0; Y < 4; Y++) {
    for (UINTN X = 0; X < 4; X++) {
      auto   &Pixel = Pixels[(Y + 16) * 32 + X];
      UINTN  Index  = 54 + ((3 - Y) * 4 + X) * 4;
      EXPECT_EQ (Pixel.Blue, Bmp[Index]);
      EXPECT_EQ (Pixel.Green, Bmp[Index + 1]);
      EXPECT_EQ (Pixel.Red, Bmp[Index + 2]);
    }
  }

  TestFreeConsole (Console);
  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, FailedLogoReplacementPreservesOwnedBuffersAndRetries) {
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  UINT64                         Original = mBootGraphicsResourceTableTemplate.ImageAddress;
  std::vector<UINT8>             OriginalBytes ((UINT8 *)(UINTN)Original, (UINT8 *)(UINTN)Original + Bmp.size ());
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Replacement[16] = { };

  mFailCopy = TRUE;
  EXPECT_EQ (mBootLogo2ProtocolTemplate.SetBootLogo (&mBootLogo2ProtocolTemplate, Replacement, 12, 10, 4, 4), EFI_OUT_OF_RESOURCES);
  ASSERT_FALSE (mAcpiBgrtBufferChanged);
  EXPECT_TRUE (mIsLogoValid);
  EXPECT_EQ (mBootGraphicsResourceTableTemplate.ImageAddress, Original);
  EXPECT_EQ (CompareMem ((VOID *)(UINTN)Original, OriginalBytes.data (), Bmp.size ()), 0);
  ASSERT_EQ (mBootLogo2ProtocolTemplate.SetBootLogo (&mBootLogo2ProtocolTemplate, Replacement, 12, 10, 4, 4), EFI_SUCCESS);
  auto  Blt = mLogoBltBuffer;

  mFailBmp = TRUE;
  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_EQ (mBootGraphicsResourceTableTemplate.ImageAddress, Original);
  EXPECT_EQ (mLogoBltBuffer, Blt);
  EXPECT_TRUE (mAcpiBgrtBufferChanged);
  // Reading the retained old image is also checked by ASan.
  EXPECT_EQ (CompareMem ((VOID *)(UINTN)Original, OriginalBytes.data (), Bmp.size ()), 0);
  mFailInstall = TRUE;
  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_FALSE (mAcpiBgrtInstalled);
  EXPECT_EQ (mLogoBltBuffer, nullptr);
  ASSERT_FALSE (mAcpiBgrtBufferChanged);
  auto  Converted = mBootGraphicsResourceTableTemplate.ImageAddress;

  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_TRUE (mAcpiBgrtInstalled);
  EXPECT_EQ (mBootGraphicsResourceTableTemplate.ImageAddress, Converted);
  EXPECT_NE (mBootGraphicsResourceTableTemplate.ImageAddress, Original);
}

TEST_F (BootSplashTest, DriverStartFallsBackFromUnsupportedPreferredTextMode) {
  std::vector<EFI_GRAPHICS_OUTPUT_BLT_PIXEL>  Pixels (640 * 480);

  Table.FrameBuffer.x_resolution   = 640;
  Table.FrameBuffer.y_resolution   = 480;
  Table.FrameBuffer.bytes_per_line = 640 * 4;
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateStandardGraphics (Pixels.data (), mGopMode.FrameBufferBase);

  ASSERT_NE (Gop, nullptr);
  mSelectedGop = Gop;
  PatchPcdSet32 (PcdConOutColumn, 100);
  PatchPcdSet32 (PcdConOutRow, 31);
  PatchPcdSet32 (PcdVideoHorizontalResolution, 640);
  PatchPcdSet32 (PcdVideoVerticalResolution, 480);
  Pixels[10 * 640 + 12].Blue = 102;
  EXPECT_EQ (TestStartConsole (), EFI_SUCCESS);
  EXPECT_NE (mStartedConsole, nullptr);
  if (mStartedConsole != nullptr) {
    EXPECT_GE (mStartedConsole->Mode->Mode, 0);
    EXPECT_FALSE (mStartedConsole->Mode->CursorVisible);
    EXPECT_EQ (Pixels[10 * 640 + 12].Blue, (UINT8)102);
    EXPECT_TRUE (mIsLogoValid);
    // First public mode request after actual driver publication must clear.
    EXPECT_EQ (mStartedConsole->SetMode (mStartedConsole, mStartedConsole->Mode->Mode), EFI_SUCCESS);
    EXPECT_FALSE (mIsLogoValid);
    TestFreeConsole (mStartedConsole);
  }

  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, DriverStartReportsSameAddressFramebufferClear) {
  std::vector<EFI_GRAPHICS_OUTPUT_BLT_PIXEL>  Pixels (640 * 480);

  Table.FrameBuffer.x_resolution   = 640;
  Table.FrameBuffer.y_resolution   = 480;
  Table.FrameBuffer.bytes_per_line = 640 * 4;
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  auto  Gop = TestCreateStandardGraphics (Pixels.data (), mGopMode.FrameBufferBase);

  ASSERT_NE (Gop, nullptr);
  mSelectedGop = Gop;
  // Neither the configured mode nor the required 800x600 fallback exists.
  PatchPcdSet32 (PcdVideoHorizontalResolution, 1024);
  PatchPcdSet32 (PcdVideoVerticalResolution, 768);
  Pixels[10 * 640 + 12].Blue = 102;
  EXPECT_EQ (TestStartConsole (), EFI_SUCCESS);
  EXPECT_FALSE (mIsLogoValid);
  EXPECT_EQ (Pixels[10 * 640 + 12].Blue, (UINT8)0);
  if (mStartedConsole != nullptr) {
    mSystemTable.ConOut = mStartedConsole;
    EXPECT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
    EXPECT_TRUE (mIsLogoValid);
    EXPECT_EQ (Pixels[10 * 640 + 12].Blue, Bmp[54 + 3 * 16]);
    TestFreeConsole (mStartedConsole);
  }

  TestFreeGraphics (Gop);
}

TEST_F (BootSplashTest, FallbackLogoDensityMatchesPublishedPixels) {
  static const struct {
    UINT8   SourceScale;
    UINT32  ScreenWidth;
    UINT32  ScreenHeight;
    UINT16  InputSize;
    UINTN   OutputSize;
  } Cases[] = {
    { 1, 1920, 1080, 4, 4 }, { 1, 3840, 2160, 4, 8 },
    { 2, 1920, 1080, 4, 2 }, { 2, 2160, 1440, 4, 4 }, { 2, 3840, 2160, 468, 468 }
  };

  for (UINTN Index = 0; Index < ARRAY_SIZE (Cases); Index++) {
    if (Index != 0) {
      TearDown ();
      SetUp ();
    }

    PatchPcdSet8 (PcdBootLogoSourceScale, Cases[Index].SourceScale);
    mUsePlatformLogo = TRUE;
    mFallbackWidth = Cases[Index].InputSize;
    mFallbackHeight = Cases[Index].InputSize;
    mFallbackPixels.resize (mFallbackWidth * mFallbackHeight);
    for (UINTN Pixel = 0; Pixel < mFallbackPixels.size (); Pixel++) {
      mFallbackPixels[Pixel].Blue = (UINT8)(Pixel + 1);
      mFallbackPixels[Pixel].Green = (UINT8)((Pixel + 1) * 2);
      mFallbackPixels[Pixel].Red = (UINT8)((Pixel + 1) * 3 + 1);
    }

    mGop.Blt = RecordFallbackBlt;
    mGopInfo.HorizontalResolution = Cases[Index].ScreenWidth;
    mGopInfo.VerticalResolution = Cases[Index].ScreenHeight;
    ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
    ASSERT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
    EXPECT_EQ (mWrites, (UINTN)1);
    ASSERT_EQ (mDrawWidth, Cases[Index].OutputSize);
    ASSERT_EQ (mDrawHeight, Cases[Index].OutputSize);
    EXPECT_EQ (mDrawX, (Cases[Index].ScreenWidth - mDrawWidth) / 2);
    EXPECT_EQ (mDrawY, (Cases[Index].ScreenHeight - mDrawHeight) / 2);
    if (mDrawWidth == 2) {
      static const UINT8 Blue[] = { 3, 5, 11, 13 };
      static const UINT8 Green[] = { 7, 11, 23, 27 };
      static const UINT8 Red[] = { 11, 17, 35, 41 };
      for (UINTN Pixel = 0; Pixel < 4; Pixel++) {
        EXPECT_EQ (mDrawnPixels[Pixel].Blue, Blue[Pixel]);
        EXPECT_EQ (mDrawnPixels[Pixel].Green, Green[Pixel]);
        EXPECT_EQ (mDrawnPixels[Pixel].Red, Red[Pixel]);
      }
    } else {
      for (UINTN Y = 0; Y < mDrawHeight; Y++) {
        for (UINTN X = 0; X < mDrawWidth; X++) {
          UINTN Source = mDrawWidth == 8 ? (Y / 2) * 4 + X / 2 : Y * mFallbackWidth + X;
          EXPECT_EQ (CompareMem (&mDrawnPixels[Y * mDrawWidth + X],
                                 &mFallbackPixels[Source], sizeof (mFallbackPixels[Source])), (INTN)0);
        }
      }
    }

    BgrtReadyToBootEventNotify (nullptr, nullptr);
    EXPECT_EQ (mPublished.Status, EFI_ACPI_5_0_BGRT_STATUS_VALID);
    EXPECT_EQ (mPublished.ImageOffsetX, mDrawX);
    EXPECT_EQ (mPublished.ImageOffsetY, mDrawY);
    EFI_GRAPHICS_OUTPUT_BLT_PIXEL *Decoded = nullptr;
    UINTN Size = 0, Height = 0, Width = 0;
    auto Header = (UINT8 *)(UINTN)mPublished.ImageAddress;
    ASSERT_EQ (TranslateBmpToGopBlt (Header, ReadUnaligned32 ((UINT32 *)(Header + 2)),
                                   &Decoded, &Size, &Height, &Width), RETURN_SUCCESS);
    EXPECT_EQ (Width, mDrawWidth);
    EXPECT_EQ (Height, mDrawHeight);
    ASSERT_EQ (Size, mDrawnPixels.size () * sizeof (*Decoded));
    for (UINTN Pixel = 0; Pixel < mDrawnPixels.size (); Pixel++) {
      // A 24-bit BMP does not preserve the BLT reserved byte.
      EXPECT_EQ (Decoded[Pixel].Blue, mDrawnPixels[Pixel].Blue);
      EXPECT_EQ (Decoded[Pixel].Green, mDrawnPixels[Pixel].Green);
      EXPECT_EQ (Decoded[Pixel].Red, mDrawnPixels[Pixel].Red);
    }
    FreePool (Decoded);
  }
}

TEST_F (BootSplashTest, SourceDensityDoesNotResizeRetainedImage) {
  PatchPcdSet8 (PcdBootLogoSourceScale, 2);
  Parse ();
  ASSERT_EQ (BootGraphicsDxeEntryPoint (nullptr, nullptr), EFI_SUCCESS);
  EXPECT_EQ (BootLogoEnableLogo (), EFI_SUCCESS);
  EXPECT_EQ (mWrites, (UINTN)0);
  BgrtReadyToBootEventNotify (nullptr, nullptr);
  EXPECT_EQ (CompareMem ((VOID *)(UINTN)mPublished.ImageAddress, Bmp.data (), Bmp.size ()), (INTN)0);
}

TEST_F (BootSplashTest, RejectsIncompleteDoubleDensityImageBeforeDrawing) {
  PatchPcdSet8 (PcdBootLogoSourceScale, 2);
  mUsePlatformLogo = TRUE;
  mFallbackWidth = 3;
  mFallbackHeight = 4;
  mFallbackPixels.resize (12);
  mGop.Blt = RecordFallbackBlt;
  EXPECT_EQ (BootLogoEnableLogo (), EFI_UNSUPPORTED);
  EXPECT_EQ (mWrites, (UINTN)0);
  EXPECT_FALSE (mIsLogoValid);
}
