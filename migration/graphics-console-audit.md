# Graphics console replacement audit

`GraphicsConsoleDxe` remains inventory-neutral while its complete driver model
is implemented and reviewed. The admitted artifact has:

- FFS GUID `cccb0c28-4b24-11d5-9a5a-0090273fc14d`;
- offset `0x2da328`, size `0x9056`, and file type `0x07`;
- UI name `GraphicsConsoleDxe` and version `1.0`;
- a `0x9004` PE32 section and no DEPEX section.

The replacement is a UEFI driver binding, not a boot-time framebuffer shim.
Its Supported/Start/Stop lifecycle consumes Device Path, Graphics Output, and
HII Font protocols and publishes Simple Text Output on each supported GOP
controller. Start must negotiate text modes from GOP resolutions, configured
row/column preferences, and font cell geometry. Stop must uninstall the child
interface and release all mode and rendering resources.

The text protocol implementation must preserve the upstream behavior for
reset, output and test-string validation, mode query/selection, attributes,
screen clearing, cursor positioning, and cursor visibility. Rendering must use
HII font glyphs, GOP BLT operations, foreground/background attributes,
wide/narrow character state, wrapping, scrolling, backspace, carriage return,
line feed, and cursor save/erase/restore. Host fixtures must cover lifecycle,
mode construction, glyph and fallback rendering, scrolling, control
characters, invalid strings and coordinates, clear-screen, and cursor state.

No retained-inventory status changes or FV replacement wiring are permitted
until this complete contract and its fixtures are green.
