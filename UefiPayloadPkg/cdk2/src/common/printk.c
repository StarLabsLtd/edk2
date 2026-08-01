/** @file

  Native cdk2 printk-style formatter.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdarg.h>

#include <cdk2/printk.h>

#define CDK2_PRINTK_BUFFER_SIZE  256U

STATIC
VOID
Cdk2PrintkAppendChar (
  OUT CHAR8  *Buffer,
  IN  UINTN  BufferSize,
  IN  OUT UINTN  *Position,
  IN  CHAR8  Character
  )
{
  if (BufferSize == 0 || Position == NULL) {
    return;
  }

  if (*Position + 1U < BufferSize) {
    Buffer[*Position] = Character;
  }

  (*Position)++;
}

STATIC
VOID
Cdk2PrintkAppendString (
  OUT CHAR8        *Buffer,
  IN  UINTN        BufferSize,
  IN  OUT UINTN    *Position,
  IN  CONST CHAR8  *String
  )
{
  if (String == NULL) {
    String = "<null>";
  }

  while (*String != '\0') {
    Cdk2PrintkAppendChar (Buffer, BufferSize, Position, *String);
    String++;
  }
}

STATIC
VOID
Cdk2PrintkAppendUnsigned (
  OUT CHAR8    *Buffer,
  IN  UINTN    BufferSize,
  IN  OUT UINTN  *Position,
  IN  UINT64   Value,
  IN  UINTN    Base,
  IN  BOOLEAN  Uppercase
  )
{
  CHAR8  Digits[sizeof (UINT64) * 8U];
  UINTN  Digit;
  UINTN  Index;

  if (Base < 2U || Base > 16U) {
    return;
  }

  Index = 0;
  do {
    Digit = (UINTN)(Value % Base);
    if (Digit < 10U) {
      Digits[Index] = (CHAR8)('0' + Digit);
    } else if (Uppercase) {
      Digits[Index] = (CHAR8)('A' + Digit - 10U);
    } else {
      Digits[Index] = (CHAR8)('a' + Digit - 10U);
    }

    Index++;
    Value /= Base;
  } while (Value != 0 && Index < ARRAY_SIZE (Digits));

  while (Index > 0) {
    Index--;
    Cdk2PrintkAppendChar (Buffer, BufferSize, Position, Digits[Index]);
  }
}

STATIC
VOID
Cdk2PrintkAppendSigned (
  OUT CHAR8  *Buffer,
  IN  UINTN  BufferSize,
  IN  OUT UINTN  *Position,
  IN  INT64  Value
  )
{
  UINT64  Magnitude;

  if (Value < 0) {
    Cdk2PrintkAppendChar (Buffer, BufferSize, Position, '-');
    Magnitude = (UINT64)(-(Value + 1)) + 1U;
  } else {
    Magnitude = (UINT64)Value;
  }

  Cdk2PrintkAppendUnsigned (Buffer, BufferSize, Position, Magnitude, 10U, FALSE);
}

STATIC
CONST CHAR8 *
Cdk2PrintkStatusName (
  IN EFI_STATUS  Status
  )
{
  switch (Status) {
    case EFI_SUCCESS:
      return "EFI_SUCCESS";
    case EFI_LOAD_ERROR:
      return "EFI_LOAD_ERROR";
    case EFI_INVALID_PARAMETER:
      return "EFI_INVALID_PARAMETER";
    case EFI_UNSUPPORTED:
      return "EFI_UNSUPPORTED";
    case EFI_BAD_BUFFER_SIZE:
      return "EFI_BAD_BUFFER_SIZE";
    case EFI_BUFFER_TOO_SMALL:
      return "EFI_BUFFER_TOO_SMALL";
    case EFI_NOT_FOUND:
      return "EFI_NOT_FOUND";
    case EFI_OUT_OF_RESOURCES:
      return "EFI_OUT_OF_RESOURCES";
    case EFI_DEVICE_ERROR:
      return "EFI_DEVICE_ERROR";
    case EFI_SECURITY_VIOLATION:
      return "EFI_SECURITY_VIOLATION";
    case EFI_COMPROMISED_DATA:
      return "EFI_COMPROMISED_DATA";
    case EFI_ABORTED:
      return "EFI_ABORTED";
    default:
      return NULL;
  }
}

STATIC
VOID
Cdk2PrintkAppendStatus (
  OUT CHAR8       *Buffer,
  IN  UINTN       BufferSize,
  IN  OUT UINTN   *Position,
  IN  EFI_STATUS  Status
  )
{
  CONST CHAR8  *Name;

  Name = Cdk2PrintkStatusName (Status);
  if (Name != NULL) {
    Cdk2PrintkAppendString (Buffer, BufferSize, Position, Name);
    return;
  }

  Cdk2PrintkAppendString (Buffer, BufferSize, Position, "0x");
  Cdk2PrintkAppendUnsigned (Buffer, BufferSize, Position, (UINT64)Status, 16U, FALSE);
}

VOID
EFIAPI
Cdk2NativeLogWrite (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Buffer,
  IN     UINTN                 Length
  )
{
  if (Context == NULL || Buffer == NULL || Length == 0 ||
      Context->Backend.LogWrite == NULL)
  {
    return;
  }

  Context->Backend.LogWrite (Context, Level, Buffer, Length);
}

STATIC
VOID
Cdk2PrintkFormat (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Format,
  IN     va_list               Marker
  )
{
  CHAR8       Buffer[CDK2_PRINTK_BUFFER_SIZE];
  BOOLEAN     LongArgument;
  UINTN       Length;
  UINTN       Position;
  EFI_STATUS  Status;

  if (Context == NULL || Format == NULL) {
    return;
  }

  Position = 0;
  while (*Format != '\0') {
    if (*Format != '%') {
      Cdk2PrintkAppendChar (Buffer, sizeof (Buffer), &Position, *Format);
      Format++;
      continue;
    }

    Format++;
    LongArgument = FALSE;
    if (*Format == 'l') {
      LongArgument = TRUE;
      Format++;
    }

    switch (*Format) {
      case '\0':
        Cdk2PrintkAppendChar (Buffer, sizeof (Buffer), &Position, '%');
        break;
      case '%':
        Cdk2PrintkAppendChar (Buffer, sizeof (Buffer), &Position, '%');
        break;
      case 'a':
      case 's':
        Cdk2PrintkAppendString (
          Buffer,
          sizeof (Buffer),
          &Position,
          va_arg (Marker, CONST CHAR8 *)
          );
        break;
      case 'd':
      case 'i':
        if (LongArgument) {
          Cdk2PrintkAppendSigned (
            Buffer,
            sizeof (Buffer),
            &Position,
            va_arg (Marker, INT64)
            );
        } else {
          Cdk2PrintkAppendSigned (
            Buffer,
            sizeof (Buffer),
            &Position,
            va_arg (Marker, INTN)
            );
        }

        break;
      case 'u':
        Cdk2PrintkAppendUnsigned (
          Buffer,
          sizeof (Buffer),
          &Position,
          LongArgument ? va_arg (Marker, UINT64) : va_arg (Marker, UINTN),
          10U,
          FALSE
          );
        break;
      case 'x':
      case 'X':
        Cdk2PrintkAppendUnsigned (
          Buffer,
          sizeof (Buffer),
          &Position,
          LongArgument ? va_arg (Marker, UINT64) : va_arg (Marker, UINTN),
          16U,
          (*Format == 'X')
          );
        break;
      case 'p':
        Cdk2PrintkAppendString (Buffer, sizeof (Buffer), &Position, "0x");
        Cdk2PrintkAppendUnsigned (
          Buffer,
          sizeof (Buffer),
          &Position,
          (UINT64)(UINTN)va_arg (Marker, CONST VOID *),
          16U,
          FALSE
          );
        break;
      case 'r':
        Status = va_arg (Marker, EFI_STATUS);
        Cdk2PrintkAppendStatus (Buffer, sizeof (Buffer), &Position, Status);
        break;
      default:
        Cdk2PrintkAppendChar (Buffer, sizeof (Buffer), &Position, '%');
        Cdk2PrintkAppendChar (Buffer, sizeof (Buffer), &Position, *Format);
        break;
    }

    if (*Format == '\0') {
      break;
    }

    Format++;
  }

  Length = Position;
  if (Length >= sizeof (Buffer)) {
    Length = sizeof (Buffer) - 1U;
  }

  Buffer[Length] = '\0';
  Cdk2NativeLogWrite (Context, Level, Buffer, Length);
}

VOID
EFIAPI
Cdk2Printk (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Format,
  ...
  )
{
  va_list  Marker;

  va_start (Marker, Format);
  Cdk2PrintkFormat (Context, Level, Format, Marker);
  va_end (Marker);
}
