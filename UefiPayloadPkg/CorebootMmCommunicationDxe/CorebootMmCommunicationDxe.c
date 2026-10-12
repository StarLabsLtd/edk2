/** @file
  MM communication transport for the coreboot-owned variable service.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>

#include <Coreboot.h>
#include <Guid/CorebootVariableService.h>
#include <Guid/EventGroup.h>
#include <Guid/SmmVariableCommon.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BlParseLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/IoLib.h>
#include <Library/SafeIntLib.h>
#include <Library/SynchronizationLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiRuntimeLib.h>
#include <Protocol/MmCommunication.h>
#include <Protocol/MmCommunication2.h>
#include <Protocol/SmmVariable.h>
#include <Protocol/VariablePolicy.h>

#include <Guid/VarCheckPolicyMmi.h>

#define SMM_DATA_PORT     0xB3
#define SMM_CONTROL_PORT  0xB2

#define CB_TAG_EFI_VARIABLE_SERVICE  0x004c

#define MM_CALL_RETRY_COUNT     8
#define MM_CALL_RETRY_STALL_US  250

struct cb_efi_variable_service {
  UINT32    tag;
  UINT32    size;
  UINT16    revision;
  UINT8     apm_command;
  UINT8     flags;
  UINT64    communication_buffer;
  UINT32    communication_buffer_size;
} __attribute__ ((packed));

STATIC_ASSERT (OFFSET_OF (struct cb_efi_variable_service, communication_buffer) == 12, "Coreboot table ABI");
STATIC_ASSERT (sizeof (struct cb_efi_variable_service) == 24, "Coreboot table ABI");

STATIC COREBOOT_VARIABLE_SERVICE_BUFFER  *mBuffer;
STATIC UINT32                            mBufferSize;
STATIC UINT8                             mApmCommand;
STATIC UINT32                            mTransaction;
STATIC SPIN_LOCK                         mCommunicationLock;
STATIC EFI_EVENT                         mVirtualAddressChangeEvent;

#pragma pack(1)
typedef struct {
  EFI_GUID    HeaderGuid;
  UINT32      MessageLength;
  UINT8       Data[];
} MM_COMMUNICATE_HEADER32;

typedef struct {
  UINT32       Function;
  UINT32       ReturnStatus;
  UINT8        Data[];
} SMM_VARIABLE_HEADER32;

typedef struct {
  EFI_GUID    Guid;
  UINT32      DataSize;
  UINT32      NameSize;
  UINT32      Attributes;
  CHAR16      Name[];
} SMM_VARIABLE_ACCESS32;

typedef struct {
  EFI_GUID    Guid;
  UINT32      NameSize;
  CHAR16      Name[];
} SMM_VARIABLE_GET_NEXT32;

typedef struct {
  UINT16    Revision;
  UINT16    Property;
  UINT32    Attributes;
  UINT32    MinSize;
  UINT32    MaxSize;
} VAR_CHECK_PROPERTY32;

typedef struct {
  EFI_GUID                 Guid;
  UINT32                   NameSize;
  VAR_CHECK_PROPERTY32     VariableProperty;
  CHAR16                   Name[];
} SMM_VARIABLE_PROPERTY32;

typedef struct {
  UINT32    Signature;
  UINT32    Revision;
  UINT32    Command;
  UINT32    Result;
} VAR_CHECK_POLICY_HEADER32;
#pragma pack()

STATIC_ASSERT (OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) == 20, "IA32 MM header ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_HEADER32, Data) == 8, "IA32 variable header ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_ACCESS32, Name) == 28, "IA32 variable access ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_GET_NEXT32, Name) == 20, "IA32 get-next ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_PROPERTY32, Name) == 36, "IA32 variable property ABI");
STATIC_ASSERT (sizeof (VAR_CHECK_POLICY_HEADER32) == 16, "IA32 variable policy ABI");

#if defined (MDE_CPU_X64)
STATIC_ASSERT (SMM_VARIABLE_COMMUNICATE_HEADER_SIZE == 16, "X64 variable header ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) == 36, "X64 variable access ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name) == 24, "X64 get-next ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name) == 48, "X64 variable property ABI");
STATIC_ASSERT (sizeof (VAR_CHECK_POLICY_COMM_HEADER) == 20, "X64 variable policy ABI");
#elif defined (MDE_CPU_IA32)
STATIC_ASSERT (SMM_VARIABLE_COMMUNICATE_HEADER_SIZE == 8, "IA32 variable header ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) == 28, "IA32 variable access ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name) == 20, "IA32 get-next ABI");
STATIC_ASSERT (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name) == 36, "IA32 variable property ABI");
STATIC_ASSERT (sizeof (VAR_CHECK_POLICY_COMM_HEADER) == 16, "IA32 variable policy ABI");
#else
#error Unsupported payload architecture
#endif

typedef struct {
  EFI_GUID    MessageGuid;
  UINT8       *Message;
  UINTN       MessageSize;
  UINTN       BufferSize;
  UINTN       MessageCapacity;
} COMMUNICATION_CONTEXT;

STATIC
BOOLEAN
UintnToUint32 (
  IN UINTN   Value,
  OUT UINT32 *Result
  )
{
  if (Value > MAX_UINT32) {
    return FALSE;
  }

  *Result = (UINT32)Value;
  return TRUE;
}

STATIC
BOOLEAN
StatusToUint32 (
  IN EFI_STATUS  Status,
  OUT UINT32     *Result
  )
{
  UINTN  Value;

  Value = Status;
  if ((Value & ~(MAX_UINT32 | MAX_BIT)) != 0) {
    return FALSE;
  }

  *Result = (UINT32)(Value & MAX_INT32);
  if (EFI_ERROR (Status)) {
    *Result |= BIT31;
  }

  return TRUE;
}

STATIC
EFI_STATUS
StatusFromUint32 (
  IN UINT32  Status
  )
{
  UINTN  Value;

  Value = Status & MAX_INT32;
  if ((Status & BIT31) != 0) {
    Value |= MAX_BIT;
  }

  return (EFI_STATUS)Value;
}

STATIC
EFI_STATUS
ParseCommunicationBuffer (
  IN OUT VOID                  *CommunicationBuffer,
  IN OUT UINTN                 *CommunicationSize OPTIONAL,
  OUT COMMUNICATION_CONTEXT    *Context
  )
{
  EFI_MM_COMMUNICATE_HEADER  *Header;
  EFI_STATUS                 Status;
  UINTN                      Size;

  Header = CommunicationBuffer;
  Status = SafeUintnAdd (OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data), Header->MessageLength, &Size);
  if (EFI_ERROR (Status)) {
    return EFI_INVALID_PARAMETER;
  }

  Context->MessageGuid = Header->HeaderGuid;
  Context->Message     = Header->Data;
  Context->MessageSize = Header->MessageLength;
  Context->BufferSize  = Size;

  if (CommunicationSize != NULL) {
    if (*CommunicationSize < Context->BufferSize) {
      return EFI_INVALID_PARAMETER;
    }

    Context->BufferSize = *CommunicationSize;
  }

  Context->MessageCapacity = Context->BufferSize - OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CopyVariablePayloadTo32 (
  IN UINTN        Function,
  IN CONST UINT8  *Source,
  IN UINTN        SourceSize,
  OUT UINT8       *Destination,
  IN UINTN        DestinationSize,
  OUT UINTN       *ResultSize
  )
{
  SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE             *Access;
  SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME      *GetNext;
  SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY *Property;
  SMM_VARIABLE_ACCESS32                                *Access32;
  SMM_VARIABLE_GET_NEXT32                              *GetNext32;
  SMM_VARIABLE_PROPERTY32                              *Property32;
  UINT32                                               DataSize;
  UINT32                                               NameSize;
  UINTN                                                Size;

  switch (Function) {
    case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    case SMM_VARIABLE_FUNCTION_SET_VARIABLE:
      if (SourceSize < OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      Access = (VOID *)Source;
      if (!UintnToUint32 (Access->DataSize, &DataSize) ||
          !UintnToUint32 (Access->NameSize, &NameSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name),
                       Access->NameSize, &Size)) ||
          EFI_ERROR (SafeUintnAdd (Size, Access->DataSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_ACCESS32, Name),
                       Access->NameSize, &Size)) ||
          EFI_ERROR (SafeUintnAdd (Size, Access->DataSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      Access32             = (VOID *)Destination;
      Access32->Guid       = Access->Guid;
      Access32->DataSize   = DataSize;
      Access32->NameSize   = NameSize;
      Access32->Attributes = Access->Attributes;
      CopyMem (Access32->Name, Access->Name, Access->NameSize + Access->DataSize);
      *ResultSize = Size;
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME:
    case SMM_VARIABLE_FUNCTION_LOCK_VARIABLE:
      if (SourceSize < OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      GetNext = (VOID *)Source;
      if (!UintnToUint32 (GetNext->NameSize, &NameSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name),
                       GetNext->NameSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_GET_NEXT32, Name),
                       GetNext->NameSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      GetNext32           = (VOID *)Destination;
      GetNext32->Guid     = GetNext->Guid;
      GetNext32->NameSize = NameSize;
      CopyMem (GetNext32->Name, GetNext->Name, GetNext->NameSize);
      *ResultSize = Size;
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO:
      if ((SourceSize < sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO)) ||
          (DestinationSize < sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO)))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      CopyMem (Destination, Source, sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO));
      *ResultSize = sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO);
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_READY_TO_BOOT:
    case SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE:
      *ResultSize = 0;
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET:
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET:
      if (SourceSize < OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      Property = (VOID *)Source;
      if (!UintnToUint32 (Property->NameSize, &NameSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name),
                       Property->NameSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_PROPERTY32, Name),
                       Property->NameSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      Property32                              = (VOID *)Destination;
      Property32->Guid                        = Property->Guid;
      Property32->NameSize                    = NameSize;
      if (Function == SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET) {
        if (!UintnToUint32 (Property->VariableProperty.MinSize, &DataSize) ||
            (Property->VariableProperty.MaxSize > MAX_UINT32))
        {
          return EFI_BAD_BUFFER_SIZE;
        }

        Property32->VariableProperty.Revision   = Property->VariableProperty.Revision;
        Property32->VariableProperty.Property   = Property->VariableProperty.Property;
        Property32->VariableProperty.Attributes = Property->VariableProperty.Attributes;
        Property32->VariableProperty.MinSize    = DataSize;
        Property32->VariableProperty.MaxSize    = (UINT32)Property->VariableProperty.MaxSize;
      } else {
        ZeroMem (&Property32->VariableProperty, sizeof (Property32->VariableProperty));
      }

      CopyMem (Property32->Name, Property->Name, Property->NameSize);
      *ResultSize = Size;
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE:
      if ((SourceSize < sizeof (SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE)) ||
          (DestinationSize < sizeof (UINT32)))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      if (!UintnToUint32 (((SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE *)Source)->VariablePayloadSize,
            (UINT32 *)Destination))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      *ResultSize = sizeof (UINT32);
      return EFI_SUCCESS;

    default:
      return EFI_UNSUPPORTED;
  }
}

STATIC
EFI_STATUS
CopyVariablePayloadFrom32 (
  IN UINTN        Function,
  IN BOOLEAN      Success,
  IN CONST UINT8  *Source,
  IN UINTN        SourceSize,
  OUT UINT8       *Destination,
  IN UINTN        DestinationSize
  )
{
  SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE              *Access;
  SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME       *GetNext;
  SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY  *Property;
  SMM_VARIABLE_ACCESS32                                 *Access32;
  SMM_VARIABLE_GET_NEXT32                               *GetNext32;
  SMM_VARIABLE_PROPERTY32                               *Property32;
  UINTN                                                 Size;

  switch (Function) {
    case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    case SMM_VARIABLE_FUNCTION_SET_VARIABLE:
      if (SourceSize < OFFSET_OF (SMM_VARIABLE_ACCESS32, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      Access32 = (VOID *)Source;
      Access   = (VOID *)Destination;
      Access->Guid       = Access32->Guid;
      Access->DataSize   = Access32->DataSize;
      Access->NameSize   = Access32->NameSize;
      Access->Attributes = Access32->Attributes;
      if (!Success) {
        return EFI_SUCCESS;
      }

      if (EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_ACCESS32, Name),
                       Access32->NameSize, &Size)) ||
          EFI_ERROR (SafeUintnAdd (Size, Access32->DataSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name),
                       Access32->NameSize, &Size)) ||
          EFI_ERROR (SafeUintnAdd (Size, Access32->DataSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      CopyMem (Access->Name, Access32->Name, Access32->NameSize + Access32->DataSize);
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME:
    case SMM_VARIABLE_FUNCTION_LOCK_VARIABLE:
      if (SourceSize < OFFSET_OF (SMM_VARIABLE_GET_NEXT32, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      GetNext32 = (VOID *)Source;
      GetNext           = (VOID *)Destination;
      GetNext->Guid     = GetNext32->Guid;
      GetNext->NameSize = GetNext32->NameSize;
      if (!Success) {
        return EFI_SUCCESS;
      }

      if (EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_GET_NEXT32, Name),
                       GetNext32->NameSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name),
                       GetNext32->NameSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      CopyMem (GetNext->Name, GetNext32->Name, GetNext32->NameSize);
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO:
      if (!Success) {
        return EFI_SUCCESS;
      }

      if ((SourceSize < sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO)) ||
          (DestinationSize < sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO)))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      CopyMem (Destination, Source, sizeof (SMM_VARIABLE_COMMUNICATE_QUERY_VARIABLE_INFO));
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_READY_TO_BOOT:
    case SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE:
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET:
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET:
      if (!Success) {
        return EFI_SUCCESS;
      }

      if (SourceSize < OFFSET_OF (SMM_VARIABLE_PROPERTY32, Name)) {
        return EFI_INVALID_PARAMETER;
      }

      Property32 = (VOID *)Source;
      if (EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_PROPERTY32, Name),
                       Property32->NameSize, &Size)) ||
          (Size > SourceSize) ||
          EFI_ERROR (SafeUintnAdd (OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name),
                       Property32->NameSize, &Size)) ||
          (Size > DestinationSize))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      Property                              = (VOID *)Destination;
      Property->Guid                        = Property32->Guid;
      Property->NameSize                    = Property32->NameSize;
      Property->VariableProperty.Revision   = Property32->VariableProperty.Revision;
      Property->VariableProperty.Property   = Property32->VariableProperty.Property;
      Property->VariableProperty.Attributes = Property32->VariableProperty.Attributes;
      Property->VariableProperty.MinSize    = Property32->VariableProperty.MinSize;
      Property->VariableProperty.MaxSize    = Property32->VariableProperty.MaxSize;
      CopyMem (Property->Name, Property32->Name, Property32->NameSize);
      return EFI_SUCCESS;

    case SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE:
      if (!Success) {
        return EFI_SUCCESS;
      }

      if ((SourceSize < sizeof (UINT32)) ||
          (DestinationSize < sizeof (SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE)))
      {
        return EFI_BAD_BUFFER_SIZE;
      }

      ((SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE *)Destination)->VariablePayloadSize =
        *(CONST UINT32 *)Source;
      return EFI_SUCCESS;

    default:
      return EFI_UNSUPPORTED;
  }
}

STATIC
BOOLEAN
VariableFunctionSupported (
  IN UINTN  Function
  )
{
  switch (Function) {
    case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    case SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME:
    case SMM_VARIABLE_FUNCTION_SET_VARIABLE:
    case SMM_VARIABLE_FUNCTION_QUERY_VARIABLE_INFO:
    case SMM_VARIABLE_FUNCTION_READY_TO_BOOT:
    case SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE:
    case SMM_VARIABLE_FUNCTION_LOCK_VARIABLE:
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET:
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET:
    case SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
UINTN
NativeMessageExpansion (
  IN CONST COMMUNICATION_CONTEXT  *Context
  )
{
  SMM_VARIABLE_COMMUNICATE_HEADER  *Header;
  UINTN                           Expansion;

  if (CompareGuid (&Context->MessageGuid, &gVarCheckPolicyLibMmiHandlerGuid)) {
    return sizeof (VAR_CHECK_POLICY_COMM_HEADER) - sizeof (VAR_CHECK_POLICY_HEADER32);
  }

  if (!CompareGuid (&Context->MessageGuid, &gEfiSmmVariableProtocolGuid) ||
      (Context->MessageSize < SMM_VARIABLE_COMMUNICATE_HEADER_SIZE))
  {
    return 0;
  }

  Header    = (VOID *)Context->Message;
  Expansion = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE - OFFSET_OF (SMM_VARIABLE_HEADER32, Data);
  switch (Header->Function) {
    case SMM_VARIABLE_FUNCTION_GET_VARIABLE:
    case SMM_VARIABLE_FUNCTION_SET_VARIABLE:
      return Expansion + OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) -
             OFFSET_OF (SMM_VARIABLE_ACCESS32, Name);
    case SMM_VARIABLE_FUNCTION_GET_NEXT_VARIABLE_NAME:
    case SMM_VARIABLE_FUNCTION_LOCK_VARIABLE:
      return Expansion + OFFSET_OF (SMM_VARIABLE_COMMUNICATE_GET_NEXT_VARIABLE_NAME, Name) -
             OFFSET_OF (SMM_VARIABLE_GET_NEXT32, Name);
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_SET:
    case SMM_VARIABLE_FUNCTION_VAR_CHECK_VARIABLE_PROPERTY_GET:
      return Expansion + OFFSET_OF (SMM_VARIABLE_COMMUNICATE_VAR_CHECK_VARIABLE_PROPERTY, Name) -
             OFFSET_OF (SMM_VARIABLE_PROPERTY32, Name);
    case SMM_VARIABLE_FUNCTION_GET_PAYLOAD_SIZE:
      return Expansion + sizeof (SMM_VARIABLE_COMMUNICATE_GET_PAYLOAD_SIZE) - sizeof (UINT32);
    default:
      return Expansion;
  }
}

STATIC
VOID
SetCommunicationSize (
  IN OUT VOID                         *CommunicationBuffer,
  IN OUT UINTN                        *CommunicationSize OPTIONAL,
  IN UINTN                            MessageSize
  )
{
  EFI_MM_COMMUNICATE_HEADER  *Header;

  Header = CommunicationBuffer;
  Header->MessageLength = MessageSize;
  if (CommunicationSize != NULL) {
    *CommunicationSize = OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + MessageSize;
  }
}

STATIC
EFI_STATUS
MarshalPolicyRequest (
  IN CONST UINT8  *Source,
  IN UINTN        SourceSize,
  OUT UINT8       *Destination,
  IN UINTN        DestinationSize,
  OUT UINTN       *ResultSize
  )
{
  VAR_CHECK_POLICY_COMM_HEADER  *Header;
  VAR_CHECK_POLICY_HEADER32     *Header32;
  UINTN                         ParameterSize;

  if ((SourceSize < sizeof (*Header)) ||
      (DestinationSize < sizeof (*Header32)))
  {
    return EFI_INVALID_PARAMETER;
  }

  Header        = (VOID *)Source;
  ParameterSize = SourceSize - sizeof (*Header);
  if (ParameterSize > DestinationSize - sizeof (*Header32)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Header32            = (VOID *)Destination;
  Header32->Signature = Header->Signature;
  Header32->Revision  = Header->Revision;
  Header32->Command   = Header->Command;
  Header32->Result    = 0;
  // Policy parameters and entries are packed and use fixed-width fields.
  CopyMem (Header32 + 1, Header + 1, ParameterSize);
  *ResultSize = sizeof (*Header32) + ParameterSize;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
MarshalPolicyResponse (
  IN CONST UINT8  *Source,
  IN UINTN        SourceSize,
  OUT UINT8       *Destination,
  IN UINTN        DestinationSize
  )
{
  VAR_CHECK_POLICY_COMM_HEADER  *Header;
  VAR_CHECK_POLICY_HEADER32     *Header32;
  UINTN                         ParameterSize;

  if ((SourceSize < sizeof (*Header32)) ||
      (DestinationSize < sizeof (*Header)))
  {
    return EFI_INVALID_PARAMETER;
  }

  ParameterSize = SourceSize - sizeof (*Header32);
  if (ParameterSize > DestinationSize - sizeof (*Header)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Header32          = (VOID *)Source;
  Header            = (VOID *)Destination;
  Header->Signature = Header32->Signature;
  Header->Revision  = Header32->Revision;
  Header->Command   = Header32->Command;
  Header->Result    = StatusFromUint32 (Header32->Result);
  CopyMem (Header + 1, Header32 + 1, ParameterSize);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
MarshalRequest (
  IN CONST COMMUNICATION_CONTEXT  *Context,
  OUT UINT8                       *Destination,
  IN UINTN                        DestinationSize,
  OUT UINTN                       *ResultSize
  )
{
  SMM_VARIABLE_COMMUNICATE_HEADER  *Header;
  SMM_VARIABLE_HEADER32            *Header32;
  MM_COMMUNICATE_HEADER32          *Outer32;
  EFI_STATUS                       Status;
  UINT32                           Function;
  UINT32                           ReturnStatus;
  UINTN                            PayloadSize;

  if (DestinationSize < OFFSET_OF (MM_COMMUNICATE_HEADER32, Data)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Outer32             = (VOID *)Destination;
  Outer32->HeaderGuid = Context->MessageGuid;

  if (CompareGuid (&Context->MessageGuid, &gVarCheckPolicyLibMmiHandlerGuid)) {
    Status = MarshalPolicyRequest (
               Context->Message,
               Context->MessageSize,
               Outer32->Data,
               DestinationSize - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data),
               &PayloadSize
               );
    if (EFI_ERROR (Status) || (PayloadSize > MAX_UINT32)) {
      return EFI_ERROR (Status) ? Status : EFI_BAD_BUFFER_SIZE;
    }

    Outer32->MessageLength = (UINT32)PayloadSize;
    *ResultSize = OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) + PayloadSize;
    return EFI_SUCCESS;
  }

  if (!CompareGuid (&Context->MessageGuid, &gEfiSmmVariableProtocolGuid)) {
    if ((Context->MessageSize > MAX_UINT32) ||
        (Context->MessageSize > DestinationSize - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data)))
    {
      return EFI_BAD_BUFFER_SIZE;
    }

    Outer32->MessageLength = (UINT32)Context->MessageSize;
    CopyMem (Outer32->Data, Context->Message, Context->MessageSize);
    *ResultSize = OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) + Context->MessageSize;
    return EFI_SUCCESS;
  }

  if ((Context->MessageSize < SMM_VARIABLE_COMMUNICATE_HEADER_SIZE) ||
      (DestinationSize < OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) +
                         OFFSET_OF (SMM_VARIABLE_HEADER32, Data)))
  {
    return EFI_INVALID_PARAMETER;
  }

  Header = (VOID *)Context->Message;
  if (!VariableFunctionSupported (Header->Function) ||
      !UintnToUint32 (Header->Function, &Function) ||
      !StatusToUint32 (Header->ReturnStatus, &ReturnStatus))
  {
    return EFI_UNSUPPORTED;
  }

  Header32               = (VOID *)Outer32->Data;
  Header32->Function     = Function;
  Header32->ReturnStatus = ReturnStatus;
  Status = CopyVariablePayloadTo32 (
             Header->Function,
             Header->Data,
             Context->MessageSize - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE,
             Header32->Data,
             DestinationSize - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) -
             OFFSET_OF (SMM_VARIABLE_HEADER32, Data),
             &PayloadSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (PayloadSize > MAX_UINT32 - OFFSET_OF (SMM_VARIABLE_HEADER32, Data)) {
    return EFI_BAD_BUFFER_SIZE;
  }

  Outer32->MessageLength = (UINT32)(OFFSET_OF (SMM_VARIABLE_HEADER32, Data) + PayloadSize);
  *ResultSize = OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) + Outer32->MessageLength;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
MarshalResponse (
  IN CONST COMMUNICATION_CONTEXT  *Context,
  IN CONST UINT8                  *Source
  )
{
  SMM_VARIABLE_COMMUNICATE_HEADER  *Header;
  SMM_VARIABLE_HEADER32            *Header32;
  MM_COMMUNICATE_HEADER32          *Outer32;
  EFI_STATUS                       VariableStatus;

  Outer32 = (VOID *)Source;

  if (CompareGuid (&Context->MessageGuid, &gVarCheckPolicyLibMmiHandlerGuid)) {
    return MarshalPolicyResponse (
             Outer32->Data,
             Outer32->MessageLength,
             Context->Message,
             Context->MessageCapacity
             );
  }

  if (!CompareGuid (&Context->MessageGuid, &gEfiSmmVariableProtocolGuid)) {
    if (Outer32->MessageLength > Context->MessageCapacity) {
      return EFI_BAD_BUFFER_SIZE;
    }

    CopyMem (Context->Message, Outer32->Data, Outer32->MessageLength);
    return EFI_SUCCESS;
  }

  if ((Outer32->MessageLength < OFFSET_OF (SMM_VARIABLE_HEADER32, Data)) ||
      (Context->MessageSize < SMM_VARIABLE_COMMUNICATE_HEADER_SIZE))
  {
    return EFI_DEVICE_ERROR;
  }

  Header   = (VOID *)Context->Message;
  Header32 = (VOID *)Outer32->Data;
  if (!VariableFunctionSupported (Header->Function) ||
      (Header32->Function != Header->Function))
  {
    return EFI_DEVICE_ERROR;
  }

  VariableStatus       = StatusFromUint32 (Header32->ReturnStatus);
  Header->ReturnStatus = VariableStatus;
  return CopyVariablePayloadFrom32 (
           Header->Function,
           !EFI_ERROR (VariableStatus),
           Header32->Data,
           Outer32->MessageLength - OFFSET_OF (SMM_VARIABLE_HEADER32, Data),
           Header->Data,
           Context->MessageCapacity - SMM_VARIABLE_COMMUNICATE_HEADER_SIZE
           );
}

STATIC
EFI_STATUS
WaitForResponse (
  IN UINT32  Transaction
  )
{
  UINTN  Attempt;

  for (Attempt = 0; Attempt < MM_CALL_RETRY_COUNT; Attempt++) {
    IoWrite8 (SMM_DATA_PORT, 0);
    IoWrite8 (SMM_CONTROL_PORT, mApmCommand);
    MemoryFence ();

    if ((mBuffer->State == COREBOOT_VARIABLE_BUFFER_RESPONSE) &&
        (mBuffer->Transaction == Transaction))
    {
      return EFI_SUCCESS;
    }

    if ((mBuffer->State != COREBOOT_VARIABLE_BUFFER_REQUEST) ||
        (mBuffer->Transaction != Transaction))
    {
      return EFI_DEVICE_ERROR;
    }

    MicroSecondDelay ((Attempt + 1) * MM_CALL_RETRY_STALL_US);
    MemoryFence ();
    if ((mBuffer->State == COREBOOT_VARIABLE_BUFFER_RESPONSE) &&
        (mBuffer->Transaction == Transaction))
    {
      return EFI_SUCCESS;
    }

    if ((mBuffer->State != COREBOOT_VARIABLE_BUFFER_REQUEST) ||
        (mBuffer->Transaction != Transaction))
    {
      return EFI_DEVICE_ERROR;
    }
  }

  return EFI_NO_RESPONSE;
}

STATIC
EFI_STATUS
Communicate (
  IN OUT VOID   *CommunicationBuffer,
  IN OUT UINTN  *CommunicationSize OPTIONAL
  )
{
  EFI_STATUS               Status;
  COMMUNICATION_CONTEXT    Context;
  UINT8                    *Message;
  UINTN                    Capacity;
  UINTN                    MessageSize;
  UINTN                    MaximumMessageSize;
  UINTN                    Expansion;
  MM_COMMUNICATE_HEADER32   *Response;
  UINT32                   Transaction;
  UINT32                   State;

  if (CommunicationBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Capacity = mBufferSize - COREBOOT_VARIABLE_SERVICE_HEADER_SIZE;
  if (((CommunicationSize != NULL) && (*CommunicationSize == 0)) ||
      (((EFI_MM_COMMUNICATE_HEADER *)CommunicationBuffer)->MessageLength == 0))
  {
    SetCommunicationSize (
      CommunicationBuffer,
      CommunicationSize,
      Capacity - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data)
      );
    return EFI_BAD_BUFFER_SIZE;
  }

  ZeroMem (&Context, sizeof (Context));
  Status = ParseCommunicationBuffer (CommunicationBuffer, CommunicationSize, &Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Message            = (UINT8 *)mBuffer + COREBOOT_VARIABLE_SERVICE_HEADER_SIZE;
  Expansion          = NativeMessageExpansion (&Context);
  MaximumMessageSize = Capacity - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data) + Expansion;
  if (Context.MessageSize > MaximumMessageSize) {
    SetCommunicationSize (CommunicationBuffer, CommunicationSize, MaximumMessageSize);
    return EFI_BAD_BUFFER_SIZE;
  }

  AcquireSpinLock (&mCommunicationLock);

  MemoryFence ();
  State = mBuffer->State;
  // Finish an earlier timed-out request before reusing its buffer.
  if ((State == COREBOOT_VARIABLE_BUFFER_REQUEST) &&
      (mTransaction != 0) &&
      (mBuffer->Transaction == mTransaction))
  {
    Status = WaitForResponse (mTransaction);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    State = mBuffer->State;
  }

  if ((State == COREBOOT_VARIABLE_BUFFER_RESPONSE) &&
      (mBuffer->Transaction == mTransaction))
  {
    MemoryFence ();
    State = InterlockedCompareExchange32 (
              &mBuffer->State,
              COREBOOT_VARIABLE_BUFFER_RESPONSE,
              COREBOOT_VARIABLE_BUFFER_IDLE
              );
    if (State != COREBOOT_VARIABLE_BUFFER_RESPONSE) {
      Status = EFI_DEVICE_ERROR;
      goto Done;
    }
  }

  State = InterlockedCompareExchange32 (
            &mBuffer->State,
            COREBOOT_VARIABLE_BUFFER_IDLE,
            COREBOOT_VARIABLE_BUFFER_CONSTRUCTING
            );
  if (State != COREBOOT_VARIABLE_BUFFER_IDLE) {
    Status = EFI_NOT_READY;
    goto Done;
  }

  Transaction = ++mTransaction;
  if (Transaction == 0) {
    Transaction = ++mTransaction;
  }

  Status = MarshalRequest (&Context, Message, Capacity, &MessageSize);
  if (EFI_ERROR (Status)) {
    if (Status == EFI_BAD_BUFFER_SIZE) {
      SetCommunicationSize (CommunicationBuffer, CommunicationSize, MaximumMessageSize);
    }

    goto ReleaseConstructing;
  }

  mBuffer->Transaction  = Transaction;
  mBuffer->MessageSize  = (UINT32)MessageSize;
  mBuffer->ResponseSize = 0;
  mBuffer->Status       = EFI_NOT_READY;
  MemoryFence ();
  mBuffer->State = COREBOOT_VARIABLE_BUFFER_REQUEST;
  MemoryFence ();

  Status = WaitForResponse (Transaction);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  if (mBuffer->ResponseSize > Capacity) {
    Status = EFI_DEVICE_ERROR;
    goto ReleaseResponse;
  }

  if (mBuffer->ResponseSize < OFFSET_OF (MM_COMMUNICATE_HEADER32, Data)) {
    Status = EFI_DEVICE_ERROR;
    goto ReleaseResponse;
  }

  Response = (VOID *)Message;
  if ((Response->MessageLength > mBuffer->ResponseSize - OFFSET_OF (MM_COMMUNICATE_HEADER32, Data)) ||
      !CompareGuid (&Response->HeaderGuid, &Context.MessageGuid))
  {
    Status = EFI_DEVICE_ERROR;
    goto ReleaseResponse;
  }

  MessageSize = Response->MessageLength + Expansion;
  if (MessageSize > Context.MessageCapacity) {
    SetCommunicationSize (CommunicationBuffer, CommunicationSize, MaximumMessageSize);
    Status = EFI_BAD_BUFFER_SIZE;
    goto ReleaseResponse;
  }

  Status = MarshalResponse (&Context, Message);
  if (!EFI_ERROR (Status)) {
    SetCommunicationSize (CommunicationBuffer, CommunicationSize, MessageSize);
    Status = (mBuffer->Status <= MAX_UINT32) ?
             StatusFromUint32 ((UINT32)mBuffer->Status) : EFI_DEVICE_ERROR;
  } else if (Status == EFI_BAD_BUFFER_SIZE) {
    SetCommunicationSize (CommunicationBuffer, CommunicationSize, MaximumMessageSize);
  }

ReleaseResponse:
  MemoryFence ();
  State = InterlockedCompareExchange32 (
            &mBuffer->State,
            COREBOOT_VARIABLE_BUFFER_RESPONSE,
            COREBOOT_VARIABLE_BUFFER_IDLE
            );
  if (State != COREBOOT_VARIABLE_BUFFER_RESPONSE) {
    Status = EFI_DEVICE_ERROR;
  }

  goto Done;

ReleaseConstructing:
  MemoryFence ();
  State = InterlockedCompareExchange32 (
            &mBuffer->State,
            COREBOOT_VARIABLE_BUFFER_CONSTRUCTING,
            COREBOOT_VARIABLE_BUFFER_IDLE
            );
  if (State != COREBOOT_VARIABLE_BUFFER_CONSTRUCTING) {
    Status = EFI_DEVICE_ERROR;
  }

Done:
  ReleaseSpinLock (&mCommunicationLock);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
MmCommunicate2 (
  IN CONST EFI_MM_COMMUNICATION2_PROTOCOL  *This,
  IN OUT VOID                              *CommunicationBufferPhysical,
  IN OUT VOID                              *CommunicationBufferVirtual,
  IN OUT UINTN                             *CommunicationSize OPTIONAL
  )
{
  EFI_MM_COMMUNICATE_HEADER       *Header;
  SMM_VARIABLE_COMMUNICATE_HEADER *VariableHeader;
  EFI_STATUS                      Status;

  if ((CommunicationBufferPhysical == NULL) || (CommunicationBufferVirtual == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Header = CommunicationBufferVirtual;
  VariableHeader = NULL;
  if (CompareGuid (&Header->HeaderGuid, &gEfiSmmVariableProtocolGuid) &&
      (Header->MessageLength >= SMM_VARIABLE_COMMUNICATE_HEADER_SIZE) &&
      ((CommunicationSize == NULL) ||
       (*CommunicationSize >= OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + SMM_VARIABLE_COMMUNICATE_HEADER_SIZE)))
  {
    SMM_VARIABLE_COMMUNICATE_HEADER *Request = (VOID *)Header->Data;

    if ((Request->Function == SMM_VARIABLE_FUNCTION_READY_TO_BOOT) ||
        (Request->Function == SMM_VARIABLE_FUNCTION_EXIT_BOOT_SERVICE))
    {
      VariableHeader = Request;
    }
  }

  Status = Communicate (CommunicationBufferVirtual, CommunicationSize);
  if (VariableHeader != NULL) {
    if (!EFI_ERROR (Status)) {
      Status = VariableHeader->ReturnStatus;
    }

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "MM variable lifecycle notification failed: %r\n", Status));
      CpuDeadLoop ();
    }
  }

  return Status;
}

STATIC EFI_MM_COMMUNICATION2_PROTOCOL  mMmCommunication2 = {
  MmCommunicate2
};

STATIC
EFI_STATUS
CheckVariableServiceReady (
  VOID
  )
{
  UINT8                      Buffer[OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + 1];
  EFI_MM_COMMUNICATE_HEADER  *Header;
  UINTN                      Size;

  Header = (VOID *)Buffer;
  ZeroMem (Buffer, sizeof (Buffer));
  CopyGuid (&Header->HeaderGuid, &gCorebootVariableServiceReadyGuid);
  Header->MessageLength = 1;
  Size                  = sizeof (Buffer);
  return Communicate (Buffer, &Size);
}

STATIC
VOID
EFIAPI
VirtualAddressChange (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EfiConvertPointer (0, (VOID **)&mBuffer);
  EfiConvertPointer (0, (VOID **)&mMmCommunication2.Communicate);
}

EFI_STATUS
EFIAPI
CorebootMmCommunicationEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  struct cb_efi_variable_service  *Service;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Descriptor;
  EFI_STATUS                      Status;
  EFI_HANDLE                      Handle;
  UINT64                          Attributes;
  UINT64                          End;

  Service = FindCbTag (CB_TAG_EFI_VARIABLE_SERVICE);
  if ((Service == NULL) || (Service->size != sizeof (*Service)) ||
      (Service->revision != COREBOOT_VARIABLE_SERVICE_REVISION) ||
      (Service->flags != 0) || (Service->apm_command == 0) ||
      (Service->communication_buffer_size != COREBOOT_VARIABLE_SERVICE_BUFFER_SIZE) ||
      (Service->communication_buffer_size > MAX_UINT32 - EFI_PAGE_MASK) ||
      ((Service->communication_buffer & EFI_PAGE_MASK) != 0))
  {
    return EFI_UNSUPPORTED;
  }

  End = Service->communication_buffer + Service->communication_buffer_size;
  if ((End < Service->communication_buffer) || (End > MAX_UINTN)) {
    return EFI_UNSUPPORTED;
  }

  Status = gDS->GetMemorySpaceDescriptor (Service->communication_buffer, &Descriptor);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((Service->communication_buffer < Descriptor.BaseAddress) ||
      (Service->communication_buffer - Descriptor.BaseAddress > Descriptor.Length) ||
      (Service->communication_buffer_size > Descriptor.Length -
       (Service->communication_buffer - Descriptor.BaseAddress)))
  {
    return EFI_UNSUPPORTED;
  }

  if (Descriptor.GcdMemoryType == EfiGcdMemoryTypeNonExistent) {
    Attributes = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME;
    Status = gDS->AddMemorySpace (
                    EfiGcdMemoryTypeReserved,
                    Service->communication_buffer,
                    Service->communication_buffer_size,
                    Attributes
                    );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Descriptor.GcdMemoryType != EfiGcdMemoryTypeReserved) {
    return EFI_UNSUPPORTED;
  } else {
    Attributes = Descriptor.Attributes | EFI_MEMORY_RUNTIME;
  }

  Status = gDS->SetMemorySpaceAttributes (
                  Service->communication_buffer,
                  Service->communication_buffer_size,
                  Attributes
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mBuffer     = (VOID *)(UINTN)Service->communication_buffer;
  mBufferSize = Service->communication_buffer_size;
  mApmCommand = Service->apm_command;
  if ((mBuffer->Signature != COREBOOT_VARIABLE_BUFFER_SIGNATURE) ||
      (mBuffer->Revision != COREBOOT_VARIABLE_SERVICE_REVISION) ||
      (mBuffer->HeaderSize != COREBOOT_VARIABLE_SERVICE_HEADER_SIZE) ||
      (mBuffer->HeaderSize > mBufferSize) ||
      (mBuffer->State != COREBOOT_VARIABLE_BUFFER_IDLE))
  {
    return EFI_UNSUPPORTED;
  }

  InitializeSpinLock (&mCommunicationLock);

  Status = CheckVariableServiceReady ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  VirtualAddressChange,
                  NULL,
                  &gEfiEventVirtualAddressChangeGuid,
                  &mVirtualAddressChangeEvent
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handle = NULL;
  Status = gBS->InstallMultipleProtocolInterfaces (
                  &Handle,
                  &gEfiMmCommunication2ProtocolGuid,
                  &mMmCommunication2,
                  &gEfiSmmVariableProtocolGuid,
                  NULL,
                  &gSmmVariableWriteGuid,
                  NULL,
                  NULL
                  );
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (mVirtualAddressChangeEvent);
    mVirtualAddressChangeEvent = NULL;
    return Status;
  }

  return EFI_SUCCESS;
}
