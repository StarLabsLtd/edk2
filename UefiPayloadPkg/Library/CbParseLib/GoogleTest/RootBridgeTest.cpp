/** @file
  Production coreboot root-bridge handoff import tests.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/GoogleTestLib.h>
#include <GoogleTest/Library/MockPcdLib.h>
#include <vector>

extern "C" {
  #include <PiDxe.h>
  #include <Coreboot.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/BlParseLib.h>
  #include <Library/HobLib.h>
  #include <Library/PcdLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <UniversalPayload/PciRootBridges.h>
  #include <Library/PciHostBridgeLib.h>
  #include <Library/PciLib.h>
  #include <Library/DxeServicesTableLib.h>
  RETURN_STATUS
  ParseCbMemTable (
    UINT32  TableId,
    VOID    **MemTable,
    UINT32  *MemTableSize
    );

  UINT16
  CbCheckSum16 (
    UINT16  *Buffer,
    UINTN   Length
    );
}

static std::vector<UINT8>               mHobStorage;
static UINTN                            mVendorReads;
static EFI_DXE_SERVICES                 mDxeServices;
static EFI_GCD_MEMORY_SPACE_DESCRIPTOR  mMemoryDescriptor;
static EFI_STATUS                       mMapStatus;

extern "C" {
  extern VOID  *mHobList;
}

extern "C" {
  static EFI_STATUS EFIAPI
  GetMemorySpaceMap (
    UINTN                            *Count,
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR  **Map
    )
  {
    if (EFI_ERROR (mMapStatus)) {
      return mMapStatus;
    }

    *Count = 1;
    *Map   = (EFI_GCD_MEMORY_SPACE_DESCRIPTOR *)AllocateCopyPool (
                                                  sizeof (mMemoryDescriptor),
                                                  &mMemoryDescriptor
                                                  );
    return *Map != NULL ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
  }

  EFI_DXE_SERVICES  *gDS = &mDxeServices;
  UINT16 EFIAPI
  PciRead16 (
    UINTN  Address
    )
  {
    mVendorReads++;
    return MAX_UINT16;
  }

  UINT32 EFIAPI
  PciRead32 (
    UINTN  Address
    )
  {
    ADD_FAILURE () << "Unexpected BAR read";
    return 0;
  }

  UINT32 EFIAPI
  PciWrite32 (
    UINTN   Address,
    UINT32  Data
    )
  {
    ADD_FAILURE () << "Unexpected BAR write";
    return Data;
  }

  UINTN EFIAPI
  PciReadBuffer (
    UINTN  Address,
    UINTN  Size,
    VOID   *Buffer
    )
  {
    ADD_FAILURE () << "Unexpected header read";
    return 0;
  }

  UINT64 EFIAPI
  GetPerformanceCounter (
    VOID
    )
  {
    return 0;
  }

  UINT64 EFIAPI
  GetPerformanceCounterProperties (
    UINT64  *First,
    UINT64  *Last
    )
  {
    *First = 0;
    *Last  = MAX_UINT64;
    return 1000000;
  }
}

class RootBridgeTest : public ::testing::Test {
protected:
  testing::NiceMock<MockPcdLib> Pcd;
  struct {
    cb_header          Header;
    cb_record          Memory;
    cb_memory_range    Range;
  } Table;
  std::vector<UINT8> Storage;
  imd_root *Root;
  UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES *Info;

  void
  SetUp (
    ) override
  {
    mVendorReads = 0;
    ZeroMem (&mDxeServices, sizeof (mDxeServices));
    mDxeServices.GetMemorySpaceMap = GetMemorySpaceMap;
    ZeroMem (&mMemoryDescriptor, sizeof (mMemoryDescriptor));
    mMemoryDescriptor.BaseAddress   = 0x90000000;
    mMemoryDescriptor.Length        = 0x100000;
    mMemoryDescriptor.GcdMemoryType = EfiGcdMemoryTypeMemoryMappedIo;
    mMapStatus                      = EFI_SUCCESS;
    mHobStorage.assign (73728, 0);
    mHobList = mHobStorage.data ();
    auto  *Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)mHobStorage.data ();

    Handoff->Header.HobType   = EFI_HOB_TYPE_HANDOFF;
    Handoff->Header.HobLength = sizeof (*Handoff);
    Handoff->EfiEndOfHobList  = (UINTN)(Handoff + 1);
    auto  *End = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;

    End->HobType                 = EFI_HOB_TYPE_END_OF_HOB_LIST;
    End->HobLength               = sizeof (*End);
    Handoff->EfiFreeMemoryBottom = (UINTN)(End + 1);
    Handoff->EfiFreeMemoryTop    = (UINTN)mHobStorage.data () + mHobStorage.size ();
    Storage.assign (73728, 0);
    Info                          = (UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES *)Storage.data ();
    Root                          = (imd_root *)(Storage.data () + Storage.size () - 4096);
    Root->max_entries             = 1;
    Root->num_entries             = 1;
    Root->entry_align             = 4096;
    Root->entries[0].magic        = IMD_ENTRY_MAGIC;
    Root->entries[0].start_offset = (UINT32)(INT32)-(INTN)(Storage.size () - 4096);
    Root->entries[0].id           = CBMEM_ID_RB_INFO;
    Root->entries[0].size         = 2048;
    Info->Header.Revision         = UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES_REVISION;
    Info->Header.Length           = sizeof (*Info) + sizeof (Info->RootBridge[0]);
    Info->ResourceAssigned        = TRUE;
    Info->Count                   = 1;
    for (UINTN Index = 0; Index < 2; Index++) {
      auto  &Bridge = Info->RootBridge[Index];
      Bridge.Io.Base          = MAX_UINT64;
      Bridge.Mem.Base         = MAX_UINT64;
      Bridge.MemAbove4G.Base  = MAX_UINT64;
      Bridge.PMem.Base        = MAX_UINT64;
      Bridge.PMemAbove4G.Base = MAX_UINT64;
      Bridge.HID              = 0x0a0341d0; // EISA PNP0A03, matching the existing scan path.
    }

    Info->RootBridge[0].Bus.Limit = 1;
    Info->RootBridge[0].Mem.Base  = 0x80000000;
    Info->RootBridge[0].Mem.Limit = 0xbfffffff;
    ZeroMem (&Table, sizeof (Table));
    Table.Header.signature     = CB_HEADER_SIGNATURE;
    Table.Header.header_bytes  = sizeof (Table.Header);
    Table.Header.table_bytes   = sizeof (Table) - sizeof (Table.Header);
    Table.Header.table_entries = 1;
    Table.Memory.tag           = CB_TAG_MEMORY;
    Table.Memory.size          = sizeof (Table.Memory) + sizeof (Table.Range);
    Table.Range.type           = CB_MEM_TABLE;
    UINT64  Base = (UINTN)Storage.data ();

    Table.Range.start.lo         = (UINT32)Base;
    Table.Range.start.hi         = (UINT32)(Base >> 32);
    Table.Range.size.lo          = (UINT32)Storage.size ();
    Table.Header.table_checksum  = CbCheckSum16 ((UINT16 *)&Table.Memory, Table.Header.table_bytes);
    Table.Header.header_checksum = CbCheckSum16 ((UINT16 *)&Table.Header, sizeof (Table.Header));
    PatchPcdSet64 (PcdBootloaderParameter, (UINTN)&Table);
  }

  void
  Rechecksum (
    )
  {
    Table.Header.table_checksum  = CbCheckSum16 ((UINT16 *)&Table.Memory, Table.Header.table_bytes);
    Table.Header.header_checksum = 0;
    Table.Header.header_checksum = CbCheckSum16 ((UINT16 *)&Table.Header, sizeof (Table.Header));
  }

  void
  PublishEntry (
    )
  {
    auto  *Entry = (cb_cbmem_entry *)&Table.Memory;

    ZeroMem (Entry, sizeof (*Entry));
    Entry->tag               = CB_TAG_CBMEM_ENTRY;
    Entry->size              = sizeof (*Entry);
    Entry->address.lo        = (UINT32)(UINTN)Info;
    Entry->address.hi        = (UINT32)((UINT64)(UINTN)Info >> 32);
    Entry->entry_size        = Info->Header.Length;
    Entry->id                = CBMEM_ID_RB_INFO;
    Table.Header.table_bytes = sizeof (*Entry);
    Rechecksum ();
  }

  EFI_HOB_GUID_TYPE *
  ImportedHob (
    )
  {
    return (EFI_HOB_GUID_TYPE *)(mHobStorage.data () + sizeof (EFI_HOB_HANDOFF_INFO_TABLE));
  }

  BOOLEAN
  HaveImport (
    )
  {
    return ImportedHob ()->Header.HobType == EFI_HOB_TYPE_GUID_EXTENSION;
  }

  void
  ExpectImport (
    )
  {
    ASSERT_TRUE (HaveImport ());
    auto  *Hob = ImportedHob ();

    EXPECT_TRUE (CompareGuid (&Hob->Name, &gUniversalPayloadPciRootBridgeInfoGuid));
    EXPECT_GE (Hob->Header.HobLength, sizeof (*Hob) + Info->Header.Length);
    EXPECT_EQ (CompareMem (GET_GUID_HOB_DATA (Hob), Info, Info->Header.Length), 0);
    auto  *End = (EFI_HOB_GENERIC_HEADER *)((UINT8 *)Hob + Hob->Header.HobLength);

    EXPECT_EQ (End->HobType, EFI_HOB_TYPE_END_OF_HOB_LIST);
  }

  void
  Parse (
    )
  {
    // Root import must not depend on CFR being present or change its result.
    EXPECT_EQ (ParseMiscInfo (), RETURN_NOT_FOUND);
  }
};

TEST_F (RootBridgeTest, ImportsCompleteHandoffWithoutCfr) {
  Parse ();
  ExpectImport ();
}
TEST_F (RootBridgeTest, PreservesMultipleRootsAndAllocationState) {
  Info->Count                   = 2;
  Info->Header.Length          += sizeof (Info->RootBridge[0]);
  Info->ResourceAssigned        = FALSE;
  Info->RootBridge[1].Segment   = 1;
  Info->RootBridge[1].Bus.Base  = 0x40;
  Info->RootBridge[1].Bus.Limit = 0x7f;
  Parse ();
  ExpectImport ();
}
TEST_F (RootBridgeTest, RejectsLengthBeyondActualAllocation) {
  Root->entries[0].size = Info->Header.Length - 1;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, RejectsCountBeyondSerializedRecords) {
  Info->Count = 2;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, RejectsTruncatedHeader) {
  Root->entries[0].size = sizeof (*Info) - 1;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, RejectsShortLength) {
  Info->Header.Length = sizeof (*Info) - 1;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, RejectsUnknownRevisionAndEmptyInfo) {
  Info->Header.Revision++;
  Parse ();
  EXPECT_FALSE (HaveImport ());
  Info->Header.Revision--;
  Info->Count = 0;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, PreservesFallbackOnMissingAllocation) {
  Root->entries[0].id = CBMEM_ID_CONSOLE;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
TEST_F (RootBridgeTest, PreservesFallbackOnHobAllocationFailure) {
  auto  *Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)mHobStorage.data ();

  Handoff->EfiFreeMemoryTop = Handoff->EfiFreeMemoryBottom;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}

TEST_F (RootBridgeTest, AcceptsExactAllocationBoundary) {
  Root->entries[0].size = Info->Header.Length;
  Parse ();
  ExpectImport ();
}

TEST_F (RootBridgeTest, RejectsOversizedHobEvenWithAdequateSourceBacking) {
  Root->entries[0].size = MAX_UINT16;
  Info->Header.Length   = MAX_UINT16;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}

TEST_F (RootBridgeTest, EnforcesAlignedHobLengthBoundary) {
  Root->entries[0].size = MAX_UINT16;
  Info->Header.Length   = MAX_UINT16 - 7 - sizeof (EFI_HOB_GUID_TYPE) + 1;
  Parse ();
  EXPECT_FALSE (HaveImport ());
  Info->Header.Length--;
  Parse ();
  ExpectImport ();
  EXPECT_EQ (ImportedHob ()->Header.HobLength, MAX_UINT16 - 7);
}

TEST_F (RootBridgeTest, UsesPublishedSmallAllocationWithoutImdDirectory) {
  PublishEntry ();
  VOID    *Data = nullptr;
  UINT32  Size  = 0;

  ASSERT_EQ (ParseCbMemTable (CBMEM_ID_RB_INFO, &Data, &Size), RETURN_SUCCESS);
  EXPECT_EQ (Data, Info);
  EXPECT_EQ (Size, Info->Header.Length);
  EXPECT_CALL (Pcd, LibPcdSetBoolS (PcdToken (PcdPciDisableBusEnumeration), TRUE))
    .WillOnce (testing::Return (RETURN_SUCCESS));
  Parse ();
  UINTN            Count    = 0;
  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  ASSERT_NE (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)1);
  EXPECT_EQ (mVendorReads, (UINTN)0);
  EXPECT_EQ (Bridges[0].Mem.Base, Info->RootBridge[0].Mem.Base);
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, PublishedAllocationSizeBoundsTheImport) {
  PublishEntry ();
  ((cb_cbmem_entry *)&Table.Memory)->entry_size--;
  Rechecksum ();
  Parse ();
  EXPECT_FALSE (HaveImport ());
}

TEST_F (RootBridgeTest, RejectsTruncatedPublishedEntry) {
  PublishEntry ();
  Table.Memory.size = sizeof (cb_cbmem_entry) - 1;
  Rechecksum ();
  VOID    *Data = nullptr;
  UINT32  Size  = 0;

  EXPECT_EQ (ParseCbMemTable (CBMEM_ID_RB_INFO, &Data, &Size), RETURN_COMPROMISED_DATA);
  EXPECT_EQ (Data, nullptr);
}

TEST_F (RootBridgeTest, RejectsPublishedEntryBeyondTableExtent) {
  PublishEntry ();
  Table.Memory.size++;
  Rechecksum ();
  VOID    *Data = nullptr;
  UINT32  Size  = 0;

  EXPECT_EQ (ParseCbMemTable (CBMEM_ID_RB_INFO, &Data, &Size), RETURN_COMPROMISED_DATA);
  EXPECT_EQ (Data, nullptr);
}

TEST_F (RootBridgeTest, RejectsDuplicatePublishedOwners) {
  PublishEntry ();
  struct {
    cb_header         Header;
    cb_cbmem_entry    Entries[2];
  } Duplicate;
  ZeroMem (&Duplicate, sizeof (Duplicate));
  Duplicate.Header               = Table.Header;
  Duplicate.Header.table_entries = 2;
  Duplicate.Header.table_bytes   = sizeof (Duplicate.Entries);
  CopyMem (&Duplicate.Entries[0], &Table.Memory, sizeof (cb_cbmem_entry));
  Duplicate.Entries[1]            = Duplicate.Entries[0];
  Duplicate.Header.table_checksum = CbCheckSum16 (
                                      (UINT16 *)Duplicate.Entries,
                                      sizeof (Duplicate.Entries)
                                      );
  Duplicate.Header.header_checksum = 0;
  Duplicate.Header.header_checksum = CbCheckSum16 (
                                       (UINT16 *)&Duplicate.Header,
                                       sizeof (Duplicate.Header)
                                       );
  PatchPcdSet64 (PcdBootloaderParameter, (UINTN)&Duplicate);
  VOID    *Data = nullptr;
  UINT32  Size  = 0;

  EXPECT_EQ (ParseCbMemTable (CBMEM_ID_RB_INFO, &Data, &Size), RETURN_COMPROMISED_DATA);
  EXPECT_EQ (Data, nullptr);
}

TEST_F (RootBridgeTest, RejectsPublishedAddressExtentOverflow) {
  PublishEntry ();
  auto  *Entry = (cb_cbmem_entry *)&Table.Memory;

  Entry->address.lo = 0xfffffff0;
  Entry->address.hi = MAX_UINT32;
  Rechecksum ();
  VOID    *Data = nullptr;
  UINT32  Size  = 0;

  EXPECT_EQ (ParseCbMemTable (CBMEM_ID_RB_INFO, &Data, &Size), RETURN_UNSUPPORTED);
  EXPECT_EQ (Data, nullptr);
}

TEST_F (RootBridgeTest, RealConsumerUsesImportedResourcesWithoutScanning) {
  EXPECT_CALL (Pcd, LibPcdSetBoolS (PcdToken (PcdPciDisableBusEnumeration), TRUE))
    .WillOnce (testing::Return (RETURN_SUCCESS));
  Parse ();
  UINTN            Count    = 0;
  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  ASSERT_NE (Bridges, nullptr);
  ASSERT_EQ (Count, (UINTN)1);
  EXPECT_EQ (mVendorReads, (UINTN)0);
  EXPECT_EQ (Bridges[0].Bus.Base, Info->RootBridge[0].Bus.Base);
  EXPECT_EQ (Bridges[0].Bus.Limit, Info->RootBridge[0].Bus.Limit);
  EXPECT_EQ (Bridges[0].Mem.Base, Info->RootBridge[0].Mem.Base);
  EXPECT_EQ (Bridges[0].Mem.Limit, Info->RootBridge[0].Mem.Limit);
  EXPECT_TRUE (Bridges[0].ResourceAssigned);
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, ReservedHostMemoryForcesScanBeforePcdChange) {
  mMemoryDescriptor.GcdMemoryType = EfiGcdMemoryTypeReserved;
  EXPECT_CALL (Pcd, LibPcdSetBoolS (PcdToken (PcdPciDisableBusEnumeration), TRUE)).Times (0);
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, GcdFailureForcesExistingScan) {
  mMapStatus = EFI_DEVICE_ERROR;
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, ChecksTranslatedHostAddress) {
  Info->RootBridge[0].Mem.Translation = 0x10000000;
  mMemoryDescriptor.BaseAddress       = 0x70000000;
  mMemoryDescriptor.GcdMemoryType     = EfiGcdMemoryTypeReserved;
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, RejectsWrappedHostAperture) {
  Info->RootBridge[0].Mem.Translation = 0x90000000;
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, RealConsumerScansWhenSourceIsRejected) {
  Root->entries[0].size = Info->Header.Length - 1;
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, RealConsumerScansAfterHobExhaustion) {
  auto  *Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)mHobStorage.data ();

  Handoff->EfiFreeMemoryTop = Handoff->EfiFreeMemoryBottom;
  Parse ();
  UINTN  Count = 99;

  PCI_ROOT_BRIDGE  *Bridges = PciHostBridgeGetRootBridges (&Count);

  EXPECT_EQ (Bridges, nullptr);
  EXPECT_EQ (Count, (UINTN)0);
  EXPECT_EQ (mVendorReads, (UINTN)(256 * 32));
  PciHostBridgeFreeRootBridges (Bridges, Count);
}

TEST_F (RootBridgeTest, RejectsNullAllocationAddress) {
  auto  *Classic = (cbmem_root *)Root;

  Classic->entries[0].magic = CBMEM_ENTRY_MAGIC;
  Classic->entries[0].start = 0;
  Classic->entries[0].size  = Info->Header.Length;
  Classic->entries[0].id    = CBMEM_ID_RB_INFO;
  Parse ();
  EXPECT_FALSE (HaveImport ());
}
