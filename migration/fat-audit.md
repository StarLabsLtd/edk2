# Native FAT migration audit

The admitted `Fat` FFS has GUID
`961578fe-b6b7-44c3-af35-6bc705cd2b1f`, offset `0x3516c8`, size
`0xe036`, file type `0x07`, and UI name `Fat`.  Its sections are a PE32
section, UI section, and version section; it has no DXE DEPEX section.

The semantic reference is `FatPkg/EnhancedFatDxe` from
`edk2-stable202302`.  That driver binds controllers exposing Block I/O plus
Disk I/O (optionally Disk I/O 2), consumes either Unicode Collation protocol,
and publishes Simple File System.  Its observable contract includes FAT12,
FAT16, and FAT32 BPB classification, bounded cluster-chain traversal, long and
short filename lookup, directory enumeration, file and volume information,
read/write growth and truncation, flush ordering, media-change handling, and
transactional Driver Binding Start/Stop ownership.

The serial implementation now replaces the admitted envelope and reduces the
retained inventory to 37 modules after the serial PCI Bus replacement. It provides the production Driver Binding,
Simple File System and revision-two File protocols and validates legal open modes and access,
creates files and initialized directories, resolves absolute and relative
paths, maintains long and short names, and queues event-backed revision-two
operations while retaining their handles until completion.

The mutation core uses caller-provided rollback storage so allocation never
depends on hidden global memory.  It mirrors FAT changes, invalidates valid
FAT32 FSInfo hints, flushes, and restores FAT and directory metadata after
write or flush failure.  The standalone package check validates the admitted
GUID, envelope, driver type, PE32/UI/version ordering and absence of DEPEX.
