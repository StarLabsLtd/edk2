/** @file
  Production console-splitter initialization over the real host graphics console.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "../../../../MdeModulePkg/Universal/Console/ConSplitterDxe/ConSplitter.c"

EFI_STATUS
TestSyncConsole (
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL  *Console,
  BOOLEAN                          Adding
  )
{
  TEXT_OUT_SPLITTER_PRIVATE_DATA  Private = { 0 };
  TEXT_OUT_AND_GOP_DATA           Output  = { .TextOut = Console };
  INT32                           Map     = Console->Mode->Mode;
  TEXT_OUT_SPLITTER_QUERY_DATA    Query   = { .Columns = 8, .Rows = 8 };

  Private.Signature               = TEXT_OUT_SPLITTER_PRIVATE_DATA_SIGNATURE;
  Private.TextOut.Mode            = &Private.TextOutMode;
  Private.TextOutMode.Mode        = 0;
  Private.TextOutMode.MaxMode     = 1;
  Private.CurrentNumberOfConsoles = 1;
  Private.TextOutList             = &Output;
  Private.TextOutListCount        = 1;
  Private.TextOutModeMap          = &Map;
  Private.TextOutQueryData        = &Query;
  Private.TextOutQueryDataCount   = 1;
  Private.AddingConOutDevice      = Adding;
  return ConSplitterTextOutSetMode (&Private.TextOut, 0);
}
