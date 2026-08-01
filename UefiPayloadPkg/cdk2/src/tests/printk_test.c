/** @file

  Host checks for the native cdk2 printk formatter.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <cdk2/printk.h>

#include <stdio.h>
#include <string.h>

static CHAR8  mLogBuffer[512];
static UINTN  mLogLevel;
static UINTN  mLogLength;
static UINTN  mLogWrites;

static int
Expect (
  int         Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "FAIL: %s\n", Message);
    return 1;
  }

  return 0;
}

static void
ResetLog (
  void
  )
{
  memset (mLogBuffer, 0, sizeof (mLogBuffer));
  mLogLevel  = 0;
  mLogLength = 0;
  mLogWrites = 0;
}

static VOID
EFIAPI
TestLogWrite (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Buffer,
  IN     UINTN                 Length
  )
{
  UINTN  Index;

  (void)Context;
  if (Length >= sizeof (mLogBuffer)) {
    Length = sizeof (mLogBuffer) - 1U;
  }

  for (Index = 0; Index < Length; Index++) {
    mLogBuffer[Index] = Buffer[Index];
  }

  mLogBuffer[Length] = '\0';
  mLogLevel          = Level;
  mLogLength         = Length;
  mLogWrites++;
}

static int
TestBasicFormatting (
  void
  )
{
  CDK2_NATIVE_CONTEXT  Context = { 0 };
  int                  Failures;

  ResetLog ();
  Context.Backend.LogWrite = TestLogWrite;
  Cdk2Printk (
    &Context,
    CDK2_BIOS_INFO,
    "cdk2 %a %d %u %x %p %r %%",
    "boot",
    (INTN)-3,
    (UINTN)7,
    (UINTN)0x2a,
    (CONST VOID *)(UINTN)0x1234,
    EFI_INVALID_PARAMETER
    );

  Failures = 0;
  Failures += Expect (mLogWrites == 1, "basic format emitted one write");
  Failures += Expect (mLogLevel == CDK2_BIOS_INFO, "basic format preserved level");
  Failures += Expect (
                strcmp (
                  mLogBuffer,
                  "cdk2 boot -3 7 2a 0x1234 EFI_INVALID_PARAMETER %"
                  ) == 0,
                "basic format output mismatch"
                );
  Failures += Expect (mLogLength == strlen (mLogBuffer), "basic format length mismatch");
  return Failures;
}

static int
TestMissingSinkIsAllowed (
  void
  )
{
  CDK2_NATIVE_CONTEXT  Context = { 0 };

  ResetLog ();
  Cdk2Printk (&Context, CDK2_BIOS_ERR, "dropped %r", EFI_DEVICE_ERROR);
  return Expect (mLogWrites == 0, "missing sink emitted a write");
}

static int
TestTruncation (
  void
  )
{
  CDK2_NATIVE_CONTEXT  Context = { 0 };
  CHAR8                LongMessage[400];
  UINTN                Index;
  int                  Failures;

  for (Index = 0; Index < sizeof (LongMessage) - 1U; Index++) {
    LongMessage[Index] = 'x';
  }

  LongMessage[sizeof (LongMessage) - 1U] = '\0';

  ResetLog ();
  Context.Backend.LogWrite = TestLogWrite;
  Cdk2Printk (&Context, CDK2_BIOS_DEBUG, "%a", LongMessage);

  Failures = 0;
  Failures += Expect (mLogWrites == 1, "truncation emitted one write");
  Failures += Expect (mLogLength == 255U, "truncation length mismatch");
  Failures += Expect (mLogBuffer[mLogLength] == '\0', "truncation missing terminator");
  return Failures;
}

int
main (
  void
  )
{
  int  Failures;

  Failures = 0;
  Failures += TestBasicFormatting ();
  Failures += TestMissingSinkIsAllowed ();
  Failures += TestTruncation ();
  if (Failures != 0) {
    return 1;
  }

  printf ("printk tests: PASS\n");
  return 0;
}
