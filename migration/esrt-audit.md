# ESRT native-port admission audit

The admitted `EsrtDxe` file in the baseline retained FV has FFS GUID
`999bd818-7df7-4a9a-a502-9b75033e6a0f`, byte offset `0x519ca8`, byte size
`0x707a`, and file type `0x07` (`EFI_FV_FILETYPE_DRIVER`). Its UI name is
`EsrtDxe`.

The admitted 58-byte DXE DEPEX section contains a four-byte section header and
the exact expression `PUSH VariableArch; PUSH VariableWriteArch; PUSH PCD;
AND; AND; END`:

- `1e5668e2-8481-11d4-bcf1-0080c73c8881` (`EFI_VARIABLE_ARCH_PROTOCOL`);
- `6441f818-6362-4e44-b570-7dba31dd2453`
  (`EFI_VARIABLE_WRITE_ARCH_PROTOCOL`).
- `13a3f0f6-264a-3ef0-f2e0-dec512342f34` (dynamic PCD protocol).

The native FFS replaces that exact admitted envelope at `0x519ca8`. Later
native PCD, Device Path, Partition, and BlSupport layers preserve it; the
composed inventory now has 37 retained modules.
