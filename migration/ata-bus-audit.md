# Native ATA bus migration audit

The admitted `AtaBusDxe` FFS has GUID
`19df145a-b1d4-453f-8507-38816676d7f6`, offset `0x314550`, exact envelope
`0x9042`, file type `0x07`, and no DEPEX section.

The native driver consumes the asynchronous ATA Pass Thru parent, publishes
shared-media Block I/O and Block I/O 2 children plus Disk Info and conditional
Storage Security, and owns parent/child protocol relationships transactionally.
It is composed directly after native ATA/ATAPI Pass Thru and reduces the
retained inventory to 34.
