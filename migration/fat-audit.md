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

The first inventory-neutral slice implements only BPB admission and checked
cluster geometry.  It deliberately publishes no production protocol yet.
Standalone ABI entry, filesystem mutation, asynchronous I/O, and exact FFS
packaging remain blocked on later tested slices; the retained inventory and FV
are unchanged.
