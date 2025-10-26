/** @file
  This file include all platform action which can be customized
  by IBV/OEM.

Copyright (c) 2015 - 2023, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "PlatformBootManager.h"
#include "PlatformConsole.h"
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h>

// Forward declaration
STATIC
VOID
PlatformScanEspVendorsAndRegisterLoaders (
  VOID
  );

/**
  Signal EndOfDxe event and install SMM Ready to lock protocol.

**/
VOID
InstallReadyToLock (
  VOID
  )
{
  EFI_STATUS                Status;
  EFI_HANDLE                Handle;
  EFI_SMM_ACCESS2_PROTOCOL  *SmmAccess;

  DEBUG ((DEBUG_INFO, "InstallReadyToLock  entering......\n"));
  //
  // Inform the SMM infrastructure that we're entering BDS and may run 3rd party code hereafter
  // Since PI1.2.1, we need signal EndOfDxe as ExitPmAuth
  //
  EfiEventGroupSignal (&gEfiEndOfDxeEventGroupGuid);
  DEBUG ((DEBUG_INFO, "All EndOfDxe callbacks have returned successfully\n"));

  //
  // Install DxeSmmReadyToLock protocol in order to lock SMM
  //
  Status = gBS->LocateProtocol (&gEfiSmmAccess2ProtocolGuid, NULL, (VOID **)&SmmAccess);
  if (!EFI_ERROR (Status)) {
    Handle = NULL;
    Status = gBS->InstallProtocolInterface (
                    &Handle,
                    &gEfiDxeSmmReadyToLockProtocolGuid,
                    EFI_NATIVE_INTERFACE,
                    NULL
                    );
    ASSERT_EFI_ERROR (Status);
  }

  DEBUG ((DEBUG_INFO, "InstallReadyToLock  end\n"));
  return;
}

/**
  Return the index of the load option in the load option array.

  The function consider two load options are equal when the
  OptionType, Attributes, Description, FilePath and OptionalData are equal.

  @param Key    Pointer to the load option to be found.
  @param Array  Pointer to the array of load options to be found.
  @param Count  Number of entries in the Array.

  @retval -1          Key wasn't found in the Array.
  @retval 0 ~ Count-1 The index of the Key in the Array.
**/
INTN
PlatformFindLoadOption (
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Key,
  IN CONST EFI_BOOT_MANAGER_LOAD_OPTION  *Array,
  IN UINTN                               Count
  )
{
  UINTN  Index;

  for (Index = 0; Index < Count; Index++) {
    if ((Key->OptionType == Array[Index].OptionType) &&
        (Key->Attributes == Array[Index].Attributes) &&
        (StrCmp (Key->Description, Array[Index].Description) == 0) &&
        (CompareMem (Key->FilePath, Array[Index].FilePath, GetDevicePathSize (Key->FilePath)) == 0) &&
        (Key->OptionalDataSize == Array[Index].OptionalDataSize) &&
        (CompareMem (Key->OptionalData, Array[Index].OptionalData, Key->OptionalDataSize) == 0))
    {
      return (INTN)Index;
    }
  }

  return -1;
}

/**
  Get the FV device path for the shell file.

  @return   A pointer to device path structure.
**/
EFI_DEVICE_PATH_PROTOCOL *
BdsGetShellFvDevicePath (
  VOID
  )
{
  UINTN                          FvHandleCount;
  EFI_HANDLE                     *FvHandleBuffer;
  UINTN                          Index;
  EFI_STATUS                     Status;
  EFI_FIRMWARE_VOLUME2_PROTOCOL  *Fv;
  UINTN                          Size;
  UINT32                         AuthenticationStatus;
  EFI_DEVICE_PATH_PROTOCOL       *DevicePath;
  EFI_FV_FILETYPE                FoundType;
  EFI_FV_FILE_ATTRIBUTES         FileAttributes;

  Status = EFI_SUCCESS;
  gBS->LocateHandleBuffer (
         ByProtocol,
         &gEfiFirmwareVolume2ProtocolGuid,
         NULL,
         &FvHandleCount,
         &FvHandleBuffer
         );

  for (Index = 0; Index < FvHandleCount; Index++) {
    Size = 0;
    gBS->HandleProtocol (
           FvHandleBuffer[Index],
           &gEfiFirmwareVolume2ProtocolGuid,
           (VOID **)&Fv
           );
    Status = Fv->ReadFile (
                   Fv,
                   &gUefiShellFileGuid,
                   NULL,
                   &Size,
                   &FoundType,
                   &FileAttributes,
                   &AuthenticationStatus
                   );
    if (!EFI_ERROR (Status)) {
      //
      // Found the shell file
      //
      break;
    }
  }

  if (EFI_ERROR (Status)) {
    if (FvHandleCount) {
      FreePool (FvHandleBuffer);
    }

    return NULL;
  }

  DevicePath = DevicePathFromHandle (FvHandleBuffer[Index]);

  if (FvHandleCount) {
    FreePool (FvHandleBuffer);
  }

  return DevicePath;
}

/**
  Register a boot option using a file GUID in the FV.

  @param FileGuid     The file GUID name in FV.
  @param Description  The boot option description.
  @param Attributes   The attributes used for the boot option loading.
**/
VOID
PlatformRegisterFvBootOption (
  EFI_GUID  *FileGuid,
  CHAR16    *Description,
  UINT32    Attributes
  )
{
  EFI_STATUS                         Status;
  UINTN                              OptionIndex;
  EFI_BOOT_MANAGER_LOAD_OPTION       NewOption;
  EFI_BOOT_MANAGER_LOAD_OPTION       *BootOptions;
  UINTN                              BootOptionCount;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH  FileNode;
  EFI_DEVICE_PATH_PROTOCOL           *DevicePath;

  EfiInitializeFwVolDevicepathNode (&FileNode, FileGuid);
  DevicePath = AppendDevicePathNode (
                 BdsGetShellFvDevicePath (),
                 (EFI_DEVICE_PATH_PROTOCOL *)&FileNode
                 );

  Status = EfiBootManagerInitializeLoadOption (
             &NewOption,
             LoadOptionNumberUnassigned,
             LoadOptionTypeBoot,
             Attributes,
             Description,
             DevicePath,
             NULL,
             0
             );
  if (!EFI_ERROR (Status)) {
    BootOptions = EfiBootManagerGetLoadOptions (&BootOptionCount, LoadOptionTypeBoot);

    OptionIndex = PlatformFindLoadOption (&NewOption, BootOptions, BootOptionCount);

    if (OptionIndex == -1) {
      Status = EfiBootManagerAddLoadOptionVariable (&NewOption, (UINTN)-1);
      ASSERT_EFI_ERROR (Status);
    }

    EfiBootManagerFreeLoadOption (&NewOption);
    EfiBootManagerFreeLoadOptions (BootOptions, BootOptionCount);
  }
}

/**
  Do the platform specific action before the console is connected.

  Such as:
    Update console variable;
    Register new Driver#### or Boot####;
    Signal ReadyToLock event.
**/
VOID
EFIAPI
PlatformBootManagerBeforeConsole (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_INPUT_KEY                 Enter;
  EFI_INPUT_KEY                 CustomKey;
  EFI_INPUT_KEY                 Down;
  EFI_BOOT_MANAGER_LOAD_OPTION  BootOption;

  //
  // Register ENTER as CONTINUE key
  //
  Enter.ScanCode    = SCAN_NULL;
  Enter.UnicodeChar = CHAR_CARRIAGE_RETURN;
  EfiBootManagerRegisterContinueKeyOption (0, &Enter, NULL);

  if (FixedPcdGetBool (PcdBootManagerEscape)) {
    //
    // Map Esc to Boot Manager Menu
    //
    CustomKey.ScanCode    = SCAN_ESC;
    CustomKey.UnicodeChar = CHAR_NULL;
  } else {
    //
    // Map Esc to Boot Manager Menu
    //
    CustomKey.ScanCode    = SCAN_F2;
    CustomKey.UnicodeChar = CHAR_NULL;
  }

  EfiBootManagerGetBootManagerMenu (&BootOption);
  EfiBootManagerAddKeyOptionVariable (NULL, (UINT16)BootOption.OptionNumber, 0, &CustomKey, NULL);

  //
  // Also add Down key to Boot Manager Menu since some serial terminals don't support F2 key.
  //
  Down.ScanCode    = SCAN_DOWN;
  Down.UnicodeChar = CHAR_NULL;
  EfiBootManagerGetBootManagerMenu (&BootOption);
  EfiBootManagerAddKeyOptionVariable (NULL, (UINT16)BootOption.OptionNumber, 0, &Down, NULL);

  //
  // Process update capsules that don't contain embedded drivers.
  //
  if (GetBootModeHob () == BOOT_ON_FLASH_UPDATE) {
    // TODO: when enabling capsule support for laptops, add a battery check here
    Status = ProcessCapsules ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a(): ProcessCapsule() failed with: %r\n", __func__, Status));
    }
  }

  //
  // Install ready to lock.
  // This needs to be done before option rom dispatched.
  //
  InstallReadyToLock ();

  //
  // Dispatch deferred images after EndOfDxe event and ReadyToLock installation.
  //
  EfiBootManagerDispatchDeferredImages ();

  PlatformConsoleInit ();
}

/**
  Do the platform specific action after the console is connected.

  Such as:
    Dynamically switch output mode;
    Signal console ready platform customized event;
    Run diagnostics like memory testing;
    Connect certain devices;
    Dispatch additional option roms.
**/
VOID
EFIAPI
PlatformBootManagerAfterConsole (
  VOID
  )
{
  EFI_STATUS                     Status;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  Black;
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL  White;
  EDKII_PLATFORM_LOGO_PROTOCOL   *PlatformLogo;

  Black.Blue = Black.Green = Black.Red = Black.Reserved = 0;
  White.Blue = White.Green = White.Red = White.Reserved = 0xFF;

  Status = gBS->LocateProtocol (&gEdkiiPlatformLogoProtocolGuid, NULL, (VOID **)&PlatformLogo);

  if (!EFI_ERROR (Status)) {
    gST->ConOut->ClearScreen (gST->ConOut);
    BootLogoEnableLogo ();
  }

  EfiBootManagerConnectAll ();
  EfiBootManagerRefreshAllBootOption ();

  // Case-insensitive scan of ESP vendor directories under EFI/ and
  // register common distro loaders even if the directory name contains capitals.
  PlatformScanEspVendorsAndRegisterLoaders ();

  //
  // Active BOOT_ON_FLASH_UPDATE mode means that at least one capsule has been
  // discovered by a bootloader and passed for further processing into EDK which
  // created EFI_HOB_TYPE_UEFI_CAPSULE HOB(s).
  //
  // Process update capsules that weren't processed on the first call to
  // ProcessCapsules() in PlatformBootManagerBeforeConsole().
  //
  if (GetBootModeHob () == BOOT_ON_FLASH_UPDATE) {
    // TODO: when enabling capsule support for laptops, add a battery check here
    Status = ProcessCapsules ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a(): ProcessCapsule() failed with: %r\n", __func__, Status));
    }

    //
    // Reset the system to disable SMI handler in order to exclude the
    // possibility of it being used outside of the firmware.
    //
    // In practice, this will rarely execute because even the first
    // ProcessCapsules() invocation might do a reset if all capsules were
    // processed and at least one of them needed a reset.  This is just to catch
    // a case when this doesn't happen which is possible on error.
    //
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }

  //
  // Register UEFI Shell
  //
  PlatformRegisterFvBootOption (&gUefiShellFileGuid, L"UEFI Shell", LOAD_OPTION_ACTIVE);

  if (FixedPcdGetBool (PcdBootManagerEscape)) {
    Print (
      L"\n"
      L"    Esc or Down      to enter Boot Manager Menu.\n"
      L"    ENTER            to boot directly.\n"
      L"\n"
      );
  } else {
    Print (
      L"\n"
      L"    F2 or Down      to enter Boot Manager Menu.\n"
      L"    ENTER           to boot directly.\n"
      L"\n"
      );
  }
}

/**
  Simple case-insensitive compare for Unicode strings.
**/
STATIC
BOOLEAN
StriEquals (
  IN CONST CHAR16  *A,
  IN CONST CHAR16  *B
  )
{
  CHAR16  ca;
  CHAR16  cb;

  while ((*A != L'\0') && (*B != L'\0')) {
    ca = *A;
    cb = *B;
    if ((ca >= L'A') && (ca <= L'Z')) {
      ca = (CHAR16)(ca - L'A' + L'a');
    }
    if ((cb >= L'A') && (cb <= L'Z')) {
      cb = (CHAR16)(cb - L'A' + L'a');
    }
    if (ca != cb) {
      return FALSE;
    }
    A++;
    B++;
  }

  return (*A == L'\0') && (*B == L'\0');
}

/**
  Open a child directory by name (case-insensitive) under a given directory.
**/
STATIC
EFI_STATUS
OpenDirCaseInsensitive (
  IN  EFI_FILE_PROTOCOL  *Parent,
  IN  CONST CHAR16       *DirName,
  OUT EFI_FILE_PROTOCOL  **OutDir
  )
{
  EFI_STATUS    Status;
  EFI_FILE_INFO *Info;
  UINTN         InfoSize;
  EFI_FILE_PROTOCOL *Dir;

  if ((Parent == NULL) || (DirName == NULL) || (OutDir == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  // Iterate entries in Parent to find a directory with matching name (case-insensitive)
  InfoSize = SIZE_OF_EFI_FILE_INFO + 512;
  Info     = AllocateZeroPool (InfoSize);
  if (Info == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Parent->SetPosition (Parent, 0);
  while (TRUE) {
    UINTN ReadSize = InfoSize;
    Status = Parent->Read (Parent, &ReadSize, Info);
    if (EFI_ERROR (Status) || (ReadSize == 0)) {
      Status = EFI_NOT_FOUND;
      break;
    }

    if ((Info->Attribute & EFI_FILE_DIRECTORY) != 0) {
      // Skip . and .. entries
      if ((StrCmp (Info->FileName, L".") == 0) || (StrCmp (Info->FileName, L"..") == 0)) {
        continue;
      }
      if (StriEquals (Info->FileName, DirName)) {
        Status = Parent->Open (
                                Parent,
                                &Dir,
                                Info->FileName,
                                EFI_FILE_MODE_READ,
                                EFI_FILE_DIRECTORY
                                );
        if (!EFI_ERROR (Status)) {
          *OutDir = Dir;
        }
        break;
      }
    }
  }

  FreePool (Info);
  return Status;
}

/**
  Test if a file exists within a directory (case-insensitive on FAT).
**/
STATIC
BOOLEAN
DirHasFile (
  IN  EFI_FILE_PROTOCOL  *Dir,
  IN  CONST CHAR16       *FileName
  )
{
  EFI_STATUS         Status;
  EFI_FILE_PROTOCOL  *Handle;

  Status = Dir->Open (
                        Dir,
                        &Handle,
                        (CHAR16 *)FileName,
                        EFI_FILE_MODE_READ,
                        0
                        );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }
  Handle->Close (Handle);
  return TRUE;
}

/**
  Compose a device path for a file on a filesystem handle.
**/
STATIC
EFI_DEVICE_PATH_PROTOCOL *
FsFileDevicePath (
  IN EFI_HANDLE   FsHandle,
  IN CONST CHAR16 *FilePath
  )
{
  return FileDevicePath (FsHandle, (CHAR16 *)FilePath);
}

/**
  Add a boot option if one with same attributes/description/filepath doesn’t already exist.
**/
STATIC
VOID
AddBootOptionIfAbsent (
  IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  IN CONST CHAR16              *Description
  )
{
  EFI_STATUS                    Status;
  EFI_BOOT_MANAGER_LOAD_OPTION  NewOption;
  EFI_BOOT_MANAGER_LOAD_OPTION  *Existing;
  UINTN                         ExistingCount;
  BOOLEAN                       PathExists;

  Status = EfiBootManagerInitializeLoadOption (
             &NewOption,
             LoadOptionNumberUnassigned,
             LoadOptionTypeBoot,
             LOAD_OPTION_ACTIVE,
             (CHAR16 *)Description,
             DevicePath,
             NULL,
             0
             );
  if (EFI_ERROR (Status)) {
    return;
  }

  Existing   = EfiBootManagerGetLoadOptions (&ExistingCount, LoadOptionTypeBoot);
  PathExists = FALSE;
  // Prefer deduplication by file path regardless of description differences.
  for (UINTN I = 0; I < ExistingCount; I++) {
    if (GetDevicePathSize (Existing[I].FilePath) == GetDevicePathSize (NewOption.FilePath) &&
        CompareMem (Existing[I].FilePath, NewOption.FilePath, GetDevicePathSize (NewOption.FilePath)) == 0)
    {
      PathExists = TRUE;
      break;
    }
  }
  if (!PathExists) {
    EfiBootManagerAddLoadOptionVariable (&NewOption, (UINTN)-1);
  }
  EfiBootManagerFreeLoadOptions (Existing, ExistingCount);
  EfiBootManagerFreeLoadOption (&NewOption);
}

/**
  Scan ESPs for vendor directories under EFI/, case-insensitively, and add
  boot options for common distro loaders regardless of directory capitalization.
**/
STATIC
VOID
PlatformScanEspVendorsAndRegisterLoaders (
  VOID
  )
{
  EFI_STATUS                          Status;
  EFI_HANDLE                          *Handles;
  UINTN                               HandleCount;
  UINTN                               Index;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL     *Sfs;
  EFI_FILE_PROTOCOL                   *Root;
  EFI_FILE_PROTOCOL                   *EfiDir;
  EFI_FILE_INFO                       *Info;
  UINTN                               InfoSize;

  // Candidates per-arch
#if defined (MDE_CPU_X64)
  CONST CHAR16 *Loaders[] = { L"shimx64.efi", L"grubx64.efi" };
#elif defined (MDE_CPU_IA32)
  CONST CHAR16 *Loaders[] = { L"shimia32.efi", L"grubia32.efi" };
#elif defined (MDE_CPU_AARCH64)
  CONST CHAR16 *Loaders[] = { L"shimaa64.efi", L"grubaa64.efi" };
#elif defined (MDE_CPU_RISCV64)
  CONST CHAR16 *Loaders[] = { L"bootriscv64.efi" };
#else
  CONST CHAR16 *Loaders[] = { L"bootx64.efi" }; // Fallback
#endif

  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
  if (EFI_ERROR (Status)) {
    return;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    if (gBS->HandleProtocol (Handles[Index], &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Sfs) != EFI_SUCCESS) {
      continue;
    }
    if (Sfs->OpenVolume (Sfs, &Root) != EFI_SUCCESS) {
      continue;
    }

    // Find EFI directory case-insensitively
    if (OpenDirCaseInsensitive (Root, L"EFI", &EfiDir) != EFI_SUCCESS) {
      Root->Close (Root);
      continue;
    }

    // Enumerate vendor subdirectories
    InfoSize = SIZE_OF_EFI_FILE_INFO + 512;
    Info     = AllocateZeroPool (InfoSize);
    if (Info == NULL) {
      EfiDir->Close (EfiDir);
      Root->Close (Root);
      continue;
    }

    EfiDir->SetPosition (EfiDir, 0);
    while (TRUE) {
      UINTN ReadSize = InfoSize;
      Status = EfiDir->Read (EfiDir, &ReadSize, Info);
      if (EFI_ERROR (Status) || (ReadSize == 0)) {
        break;
      }

      if ((Info->Attribute & EFI_FILE_DIRECTORY) == 0) {
        continue;
      }
      // Skip . and ..
      if ((StrCmp (Info->FileName, L".") == 0) || (StrCmp (Info->FileName, L"..") == 0)) {
        continue;
      }

      // Open the vendor directory
      EFI_FILE_PROTOCOL *VendorDir;
      if (EfiDir->Open (EfiDir, &VendorDir, Info->FileName, EFI_FILE_MODE_READ, EFI_FILE_DIRECTORY) != EFI_SUCCESS) {
        continue;
      }

      // Try loader candidates
      for (UINTN L = 0; L < ARRAY_SIZE (Loaders); L++) {
        if (DirHasFile (VendorDir, Loaders[L])) {
          // Build a file path like \EFI\<Vendor>\<Loader>
          UINTN PathLen = StrLen (L"\\EFI\\") + StrLen (Info->FileName) + 1 + StrLen (Loaders[L]) + 1;
          CHAR16 *Path  = AllocateZeroPool (PathLen * sizeof (CHAR16));
          if (Path != NULL) {
            UnicodeSPrint (Path, PathLen * sizeof (CHAR16), L"\\EFI\\%s\\%s", Info->FileName, Loaders[L]);
            EFI_DEVICE_PATH_PROTOCOL *Dp = FsFileDevicePath (Handles[Index], Path);
            if (Dp != NULL) {
              // Description: use vendor directory name as-is.
              AddBootOptionIfAbsent (Dp, Info->FileName);
              FreePool (Dp);
            }
            FreePool (Path);
          }
          // Don't add multiple loaders per vendor; first hit wins.
          break;
        }
      }

      VendorDir->Close (VendorDir);
    }

    FreePool (Info);
    EfiDir->Close (EfiDir);
    Root->Close (Root);
  }

  if (Handles != NULL) {
    FreePool (Handles);
  }
}


/**
  This function is called each second during the boot manager waits the timeout.

  @param TimeoutRemain  The remaining timeout.
**/
VOID
EFIAPI
PlatformBootManagerWaitCallback (
  UINT16  TimeoutRemain
  )
{
  /* Clear text from screen once timeout expires */
  if (TimeoutRemain == 0) {
    gST->ConOut->ClearScreen (gST->ConOut);
    BootLogoEnableLogo ();
  }
  return;
}

/**
  The function is called when no boot option could be launched,
  including platform recovery options and options pointing to applications
  built into firmware volumes.

  If this function returns, BDS attempts to enter an infinite loop.
**/
VOID
EFIAPI
PlatformBootManagerUnableToBoot (
  VOID
  )
{
  return;
}
