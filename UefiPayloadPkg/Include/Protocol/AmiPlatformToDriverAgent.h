/** @file
  AMI platform-to-driver agent protocol (structure from AMI firmware; protocol GUID
  is a published interface used by AMD GOP platform configuration).
**/

#ifndef AMI_PLATFORM_TO_DRIVER_AGENT_H_
#define AMI_PLATFORM_TO_DRIVER_AGENT_H_

#include <Uefi.h>

#define AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL_GUID \
  { 0x1dcfbaca, 0x6ada, 0x4c0d, { 0x86, 0xed, 0xaf, 0x65, 0x8b, 0xdf, 0xec, 0xc } }

extern EFI_GUID  gAmiPlatformToDriverAgentProtocolGuid;

typedef struct _AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL;

typedef EFI_STATUS (EFIAPI *AMI_PLATFORM_TO_DRIVER_AGENT_SUPPORTED)(
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL
  );

typedef EFI_STATUS (EFIAPI *AMI_PLATFORM_TO_DRIVER_AGENT_QUERY)(
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL,
  IN UINTN                                  *Instance,
  OUT EFI_GUID                              **ParameterTypeGuid,
  OUT VOID                                  **ParameterBlock,
  OUT UINTN                                 *ParameterBlockSize
  );

typedef EFI_STATUS (EFIAPI *AMI_PLATFORM_TO_DRIVER_AGENT_RESPONSE)(
  IN AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL  *This,
  IN EFI_HANDLE                             ControllerHandle,
  IN EFI_HANDLE                             ChildHandle OPTIONAL,
  IN UINTN                                  *Instance,
  IN EFI_GUID                               *ParameterTypeGuid,
  IN VOID                                   *ParameterBlock,
  IN UINTN                                  ParameterBlockSize,
  IN UINT32                                 ConfigurationAction
  );

struct _AMI_PLATFORM_TO_DRIVER_AGENT_PROTOCOL {
  AMI_PLATFORM_TO_DRIVER_AGENT_SUPPORTED  Supported;
  AMI_PLATFORM_TO_DRIVER_AGENT_QUERY      Query;
  AMI_PLATFORM_TO_DRIVER_AGENT_RESPONSE   Response;
};

#endif
