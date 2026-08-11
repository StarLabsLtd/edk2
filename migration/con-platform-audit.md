# Native ConPlatformDxe admission

The retained `ConPlatformDxe` file has GUID
`51ccf399-4fdf-4e55-a45b-e123f84d456a`, starts at FV offset `0x2c8288`,
and occupies the exact `0x704e` driver envelope. Its sections are PE32
`0x7004`, UI `ConPlatformDxe` (`0x22`), and VERSION `1.0` (`0x0e`), with no
DEPEX or trailing slack.

The native driver publishes separate input and output DriverBinding instances,
tests DevicePath and SimpleText protocol ownership, updates the standard
console variables, installs the selected console marker protocols, expands GOP
sibling paths, and handles USB class and WWID short-form paths. Per-controller
pool-owned state makes Start, Stop, and publication rollback independent.

Executable fixtures cover path validation and matching, variable editing,
multi-controller lifecycle/fault rollback, exact component-name languages, and
the complete admitted FFS envelope. Serial composition replaces only this file
after the exact native FTW predecessor and reduces retained inventory from 20
to 19.
