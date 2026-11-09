/** @file
  Unit tests for UsbBusDxe descriptor parsing and root hub reset handling.

  Copyright (c) 2026, Intel Corporation. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/GoogleTestLib.h>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseMemoryLib.h>
  #include "../UsbBus.h"

  EFI_STATUS
  EFIAPI
  UsbOnHubInterrupt (
    VOID    *Data,
    UINTN   DataLength,
    VOID    *Context,
    UINT32  Result
    );

  BOOLEAN
  UsbIsSSDevice (
    IN EFI_USB_BOS_DESCRIPTOR  *BosDesc,
    IN UINTN                   Len
    );

  EFI_STATUS
  UsbGetDevBosDesc (
    IN USB_DEVICE  *UsbDev
    );

  EFI_STATUS
  UsbRootHubResetPort (
    IN USB_INTERFACE  *RootIf,
    IN UINT8          Port
    );
}

static EFI_BOOT_SERVICES       mBootServices;
static UINTN                   mFreePoolCount;
static UINTN                   mStallMicroseconds;
static UINTN                   mRootStatusStall;
static EFI_STATUS              mResetStatus;
static UINTN                   mControlTransferCount;
static EFI_STATUS              mControlTransferStatus;
static EFI_USB_PORT_STATUS     mRootHubPortStatus;
static EFI_USB_BOS_DESCRIPTOR  mBosDescriptor;
static EFI_USB_HUB_DESCRIPTOR  mHubDescriptor;
static struct {
  BOOLEAN  Enabled;
  BOOLEAN  Active;
  UINT64   Started;
  UINT64   Duration;
  UINT16   Changes;
  UINT8    FailRequest;
  UINTN    Resets;
  UINTN    Clears;
  UINTN    Reads;
} mHubReset;

static UINT64                  mNow, mCounterBase, mCounterFirst, mCounterLast, mFrequency;
static UINTN                   mPortReads, mEarlyPortReads, mClosedEvents;

// The enumeration fixture models host-controller registers and USB transfers,
// not enumeration decisions. All descriptor/configuration/dispatch code is real.
static BOOLEAN              mEnumerating, mConsumeChanges, mFailRootAllocation;
static EFI_USB_PORT_STATUS  mPorts[3];
static UINTN                mReads[3], mFailRead[3], mResets[3], mResetTime[3];
static UINTN                mConnectedKeyboards, mDebounceWaits;
static UINTN                mInjectAt[3], mFailInitAt[3], mInvalidTransfers, mActivePort;
static UINT16               mInjectChanges[3];
static BOOLEAN              mSlotReady[3];
static VOID                 (*mDuringDebounce)(
  VOID
  );
static EFI_EVENT_NOTIFY  mNotify;
static VOID              *mNotifyContext;
static EFI_STATUS        mCreateStatus, mTimerStatus;
static UINT64            mRootPollInterval;
static EFI_TPL           mTpl;
static const UINT8       mKeyboardDevice[] = {
  18, 1, 0, 2, 0, 0, 0, 64, 0x34, 0x12, 0x78, 0x56, 0, 1, 0, 0, 0, 1
};
static const UINT8       mKeyboardConfig[] = {
  9, 2,    34,   0, 1, 1, 0,    0x80, 50,
  9, 4,    0,    0, 1, 3, 1,    1,    0,
  9, 0x21, 0x11, 1, 0, 1, 0x22, 63,   0,
  7, 5,    0x81, 3, 8, 0, 10
};

extern "C" {
  extern EFI_BOOT_SERVICES  *gBS;

  /**
    Count and free a buffer through the test's mocked boot-services table.

    @param[in] Buffer  Buffer to free.

    @retval EFI_SUCCESS  The buffer was freed.
  **/
  EFI_STATUS
  EFIAPI
  TestFreePool (
    IN VOID  *Buffer
    )
  {
    mFreePoolCount++;
    FreePool (Buffer);
    return EFI_SUCCESS;
  }

  /**
    Mock the boot-services stall function without delaying the test.

    @param[in] Microseconds  Requested delay, ignored by this mock.

    @retval EFI_SUCCESS  The mock completed successfully.
  **/
  EFI_STATUS
  EFIAPI
  TestStall (
    IN UINTN  Microseconds
    )
  {
    mStallMicroseconds += Microseconds;
    mNow               += Microseconds;
    if (mEnumerating && (Microseconds == USB_WAIT_PORT_STABLE_STALL)) {
      mDebounceWaits++;
      if (mDuringDebounce != NULL) {
        VOID  (*Hook)(
          VOID
          )             = mDuringDebounce;
        mDuringDebounce = NULL;
        Hook ();
      }
    }

    return EFI_SUCCESS;
  }

  UINT64 EFIAPI
  GetPerformanceCounter (
    VOID
    )
  {
    if ((mCounterFirst == 0) && (mCounterLast == MAX_UINT64)) {
      return mCounterBase + mNow;
    }

    if ((mCounterFirst == MAX_UINT64) && (mCounterLast == 0)) {
      return mCounterBase - mNow;
    }

    if (mCounterFirst < mCounterLast) {
      return mCounterFirst + (mCounterBase - mCounterFirst + mNow) %
             (mCounterLast - mCounterFirst + 1);
    }

    return mCounterFirst - (mCounterFirst - mCounterBase + mNow) %
           (mCounterFirst - mCounterLast + 1);
  }

  UINT64 EFIAPI
  GetPerformanceCounterProperties (
    UINT64  *Start,
    UINT64  *End
    )
  {
    if (Start != NULL) {
      *Start = mCounterFirst;
    }

    if (End != NULL) {
      *End = mCounterLast;
    }

    return mFrequency;
  }

  UINT64 EFIAPI
  GetTimeInNanoSecond (
    UINT64  Ticks
    )
  {
    return Ticks * 1000;
  }

  EFI_STATUS EFIAPI
  TestCreateEvent (
    UINT32            Type,
    EFI_TPL           Tpl,
    EFI_EVENT_NOTIFY  Notify,
    VOID              *Context,
    EFI_EVENT         *Event
    )
  {
    *Event = (EFI_EVENT)(UINTN)1;
    if (mEnumerating) {
      mNotify        = Notify;
      mNotifyContext = Context;
      return mCreateStatus;
    }

    return EFI_SUCCESS;
  }

  EFI_STATUS EFIAPI
  TestCloseEvent (
    EFI_EVENT  Event
    )
  {
    mClosedEvents++;
    return EFI_SUCCESS;
  }

  EFI_STATUS EFIAPI
  TestAsyncTransfer (
    EFI_USB_IO_PROTOCOL              *This,
    UINT8                            Endpoint,
    BOOLEAN                          NewTransfer,
    UINTN                            Interval,
    UINTN                            Length,
    EFI_ASYNC_USB_TRANSFER_CALLBACK  Callback,
    VOID                             *Context
    )
  {
    return EFI_SUCCESS;
  }

  /**
    Record a USB control-transfer call and return the status selected by the test.

    @param[in]  UsbBus       USB bus, unused by this mock.
    @param[in]  DevAddr      Device address, unused by this mock.
    @param[in]  DevSpeed     Device speed, unused by this mock.
    @param[in]  MaxPacket    Maximum packet size, unused by this mock.
    @param[in]  Request      Transfer request, unused by this mock.
    @param[in]  Direction    Transfer direction, unused by this mock.
    @param[in,out] Data      Transfer buffer, unused by this mock.
    @param[in,out] DataLength Transfer length, unused by this mock.
    @param[in]  TimeOut      Transfer timeout, unused by this mock.
    @param[in]  Translator   Transaction translator, unused by this mock.
    @param[out] UsbResult    USB transfer result, unused by this mock.

    @retval mControlTransferStatus  Status configured by the test.
  **/
  EFI_STATUS
  __wrap_UsbHcControlTransfer (
    IN  USB_BUS                             *UsbBus,
    IN  UINT8                               DevAddr,
    IN  UINT8                               DevSpeed,
    IN  UINTN                               MaxPacket,
    IN  EFI_USB_DEVICE_REQUEST              *Request,
    IN  EFI_USB_DATA_DIRECTION              Direction,
    IN  OUT VOID                            *Data,
    IN  OUT UINTN                           *DataLength,
    IN  UINTN                               TimeOut,
    IN  EFI_USB2_HC_TRANSACTION_TRANSLATOR  *Translator,
    OUT UINT32                              *UsbResult
    )
  {
    mControlTransferCount++;
    if (mHubReset.Enabled) {
      *UsbResult = 0;
      EXPECT_EQ (Request->Index, 1);
      if (Request->Request == mHubReset.FailRequest) {
        return EFI_DEVICE_ERROR;
      }

      if (Request->Request == USB_HUB_REQ_CLEAR_FEATURE) {
        EXPECT_EQ (Request->Value, (DevSpeed == EFI_USB_SPEED_SUPER) ?
                   USB_HUB_C_BH_PORT_RESET : USB_HUB_C_PORT_RESET);
        mHubReset.Changes &= (UINT16) ~USB_PORT_STAT_C_RESET;
        mHubReset.Clears++;
      } else if (Request->Request == USB_HUB_REQ_SET_FEATURE) {
        EXPECT_EQ (Request->Value, (DevSpeed == EFI_USB_SPEED_SUPER) ?
                   USB_HUB_BH_PORT_RESET : USB_HUB_PORT_RESET);
        mHubReset.Active  = TRUE;
        mHubReset.Started = mNow;
        mHubReset.Resets++;
      } else if (Request->Request == USB_HUB_REQ_GET_STATUS) {
        EFI_USB_PORT_STATUS  PortState = { USB_PORT_STAT_CONNECTION, mHubReset.Changes };
        if (mHubReset.Active && ((mNow - mHubReset.Started) >= mHubReset.Duration)) {
          PortState.PortStatus       |= USB_PORT_STAT_ENABLE;
          PortState.PortChangeStatus |= USB_PORT_STAT_C_RESET;
        } else {
          PortState.PortStatus |= USB_PORT_STAT_RESET;
        }

        EXPECT_GE (*DataLength, sizeof (PortState));
        CopyMem (Data, &PortState, sizeof (PortState));
        mHubReset.Reads++;
      } else {
        ADD_FAILURE () << "Unexpected hub request";
        return EFI_UNSUPPORTED;
      }

      return EFI_SUCCESS;
    }

    if (mEnumerating) {
      *UsbResult = 0;
      if (!mSlotReady[mActivePort]) {
        mInvalidTransfers++;
        return EFI_DEVICE_ERROR;
      }

      if (Request->Request == USB_REQ_GET_DESCRIPTOR) {
        const UINT8         *Bytes;
        UINTN               Length;
        static const UINT8  Languages[] = { 4, 3, 9, 4 };
        if ((Request->Value >> 8) == USB_DESC_TYPE_DEVICE) {
          Bytes  = mKeyboardDevice;
          Length = sizeof (mKeyboardDevice);
        } else if ((Request->Value >> 8) == USB_DESC_TYPE_CONFIG) {
          Bytes  = mKeyboardConfig;
          Length = sizeof (mKeyboardConfig);
        } else if ((Request->Value >> 8) == USB_DESC_TYPE_STRING) {
          Bytes  = Languages;
          Length = sizeof (Languages);
        } else {
          return EFI_UNSUPPORTED;
        }

        *DataLength = MIN (*DataLength, Length);
        CopyMem (Data, Bytes, *DataLength);
      }

      return EFI_SUCCESS;
    }

    if ((Request->Value >> 8) == USB_DESC_TYPE_BOS) {
      CopyMem (Data, &mBosDescriptor, MIN (*DataLength, sizeof (mBosDescriptor)));
    } else if (((Request->Value >> 8) == USB_DESC_TYPE_HUB) ||
               ((Request->Value >> 8) == USB_DESC_TYPE_HUB_SUPER_SPEED))
    {
      CopyMem (Data, &mHubDescriptor, MIN (*DataLength, sizeof (mHubDescriptor)));
    } else if ((Request->RequestType == 0xa3) && (Request->Request == 0)) {
      mPortReads++;
      if (mNow < mHubDescriptor.PwrOn2PwrGood * USB_SET_PORT_POWER_STALL) {
        mEarlyPortReads++;
      }

      CopyMem (Data, &mRootHubPortStatus, MIN (*DataLength, sizeof (mRootHubPortStatus)));
    } else if ((Data != NULL) && (*DataLength > 0)) {
      ZeroMem (Data, *DataLength);
    }

    return mControlTransferStatus;
  }

  /**
    Mock retrieval of USB host-controller capabilities.

    @param[in]  UsbBus          USB bus, unused by this mock.
    @param[out] MaxSpeed        Maximum speed output, unused by this mock.
    @param[out] NumOfPort       Port-count output, unused by this mock.
    @param[out] Is64BitCapable  64-bit capability output, unused by this mock.

    @retval EFI_UNSUPPORTED  Capability retrieval is not used by these tests.
  **/
  EFI_STATUS
  __wrap_UsbHcGetCapability (
    IN  USB_BUS  *UsbBus,
    OUT UINT8    *MaxSpeed,
    OUT UINT8    *NumOfPort,
    OUT UINT8    *Is64BitCapable
    )
  {
    if (mEnumerating) {
      *MaxSpeed       = EFI_USB_SPEED_SUPER;
      *NumOfPort      = ARRAY_SIZE (mPorts);
      *Is64BitCapable = TRUE;
      return EFI_SUCCESS;
    }

    return EFI_UNSUPPORTED;
  }

  /**
    Mock setting a root-hub port feature.

    @param[in] UsbBus     USB bus, unused by this mock.
    @param[in] PortIndex  Root-hub port, unused by this mock.
    @param[in] Feature    Feature to set, unused by this mock.

    @retval EFI_SUCCESS  The mock completed successfully.
  **/
  EFI_STATUS
  __wrap_UsbHcSetRootHubPortFeature (
    IN USB_BUS               *UsbBus,
    IN UINT8                 PortIndex,
    IN EFI_USB_PORT_FEATURE  Feature
    )
  {
    if (mEnumerating && (Feature == EfiUsbPortReset)) {
      mResets[PortIndex]++;
      mResetTime[PortIndex]               = mNow;
      mPorts[PortIndex].PortStatus       |= USB_PORT_STAT_ENABLE;
      mPorts[PortIndex].PortChangeStatus |= USB_PORT_STAT_C_RESET;
    }

    return mResetStatus;
  }

  /**
    Mock clearing a root-hub port feature.

    @param[in] UsbBus     USB bus, unused by this mock.
    @param[in] PortIndex  Root-hub port, unused by this mock.
    @param[in] Feature    Feature to clear, unused by this mock.

    @retval EFI_SUCCESS  The mock completed successfully.
  **/
  EFI_STATUS
  __wrap_UsbHcClearRootHubPortFeature (
    IN USB_BUS               *UsbBus,
    IN UINT8                 PortIndex,
    IN EFI_USB_PORT_FEATURE  Feature
    )
  {
    if (mEnumerating && (Feature >= EfiUsbPortConnectChange) &&
        (Feature <= EfiUsbPortResetChange))
    {
      mPorts[PortIndex].PortChangeStatus &= (UINT16) ~(1U << (Feature - EfiUsbPortConnectChange));
    }

    return EFI_SUCCESS;
  }

  /**
    Return the root-hub port status configured by the test.

    @param[in]  UsbBus     USB bus, unused by this mock.
    @param[in]  PortIndex  Root-hub port, unused by this mock.
    @param[out] PortStatus Receives the configured port status.

    @retval EFI_SUCCESS  The configured status was returned.
  **/
  EFI_STATUS
  __wrap_UsbHcGetRootHubPortStatus (
    IN  USB_BUS              *UsbBus,
    IN  UINT8                PortIndex,
    OUT EFI_USB_PORT_STATUS  *PortStatus
    )
  {
    if (mEnumerating) {
      mReads[PortIndex]++;
      if (mReads[PortIndex] == mFailRead[PortIndex]) {
        return EFI_TIMEOUT;
      }

      if (mReads[PortIndex] == mInjectAt[PortIndex]) {
        mPorts[PortIndex].PortChangeStatus = mInjectChanges[PortIndex];
      }

      *PortStatus = mPorts[PortIndex];
      if (PortStatus->PortChangeStatus != 0) {
        // XhcPollPortStatusChange replaces the slot when it consumes an event.
        mActivePort           = PortIndex;
        mSlotReady[PortIndex] = (BOOLEAN)(USB_BIT_IS_SET (PortStatus->PortStatus, USB_PORT_STAT_ENABLE) &&
                                          USB_BIT_IS_SET (PortStatus->PortStatus, USB_PORT_STAT_CONNECTION) &&
                                         USB_BIT_IS_SET (PortStatus->PortChangeStatus, USB_PORT_STAT_C_RESET));
        if (mReads[PortIndex] == mFailInitAt[PortIndex]) {
          mSlotReady[PortIndex] = FALSE;
          // XhcGetRootHubPortStatus requests recovery this way, even on success.
          PortStatus->PortChangeStatus &= (UINT16) ~USB_PORT_STAT_C_RESET;
        }
      }

      if (mConsumeChanges) {
        mPorts[PortIndex].PortChangeStatus = 0;
      }
    } else {
      mRootStatusStall = mStallMicroseconds;
      *PortStatus = mRootHubPortStatus;
    }

    return EFI_SUCCESS;
  }
}

class UsbBusDxeTest : public ::testing::Test {
protected:

  /**
    Reset mocked boot services and per-test USB call state.
  **/
  void
  SetUp (
    ) override
  {
    mEnumerating = FALSE;
    ZeroMem (&mHubReset, sizeof (mHubReset));
    mHubReset.FailRequest = MAX_UINT8;
    mHubReset.Duration    = 10000;
    gBS          = &mBootServices;
    ZeroMem (&mBootServices, sizeof (mBootServices));
    mBootServices.FreePool    = TestFreePool;
    mBootServices.Stall       = TestStall;
    mBootServices.CreateEvent = TestCreateEvent;
    mBootServices.CloseEvent  = TestCloseEvent;
    mNow                      = mCounterBase = mCounterFirst = 0;
    mCounterLast              = MAX_UINT64;
    mFrequency                = 1000000;
    mPortReads                = mEarlyPortReads = mClosedEvents = 0;
    ZeroMem (&mHubDescriptor, sizeof (mHubDescriptor));
    mHubDescriptor.Length        = 9;
    mHubDescriptor.NumPorts      = 4;
    mHubDescriptor.PwrOn2PwrGood = 50;

    mStallMicroseconds     = 0;
    mRootStatusStall       = MAX_UINTN;
    mResetStatus           = EFI_SUCCESS;
    mFreePoolCount         = 0;
    mControlTransferCount  = 0;
    mControlTransferStatus = EFI_DEVICE_ERROR;
    ZeroMem (&mBosDescriptor, sizeof (mBosDescriptor));
    mRootHubPortStatus.PortStatus       = USB_PORT_STAT_ENABLE;
    mRootHubPortStatus.PortChangeStatus = 0;
  }

  USB_BUS HubBus;
  USB_DEVICE HubDevice;
  USB_INTERFACE HubIf;
  USB_INTERFACE_SETTING HubSetting;
  USB_ENDPOINT_DESC HubEndpoint;
  USB_ENDPOINT_DESC *HubEndpointPointer;

  EFI_STATUS
  InitHub (
    UINT8  Speed = EFI_USB_SPEED_HIGH
    )
  {
    ZeroMem (&HubBus, sizeof (HubBus));
    ZeroMem (&HubDevice, sizeof (HubDevice));
    ZeroMem (&HubIf, sizeof (HubIf));
    ZeroMem (&HubSetting, sizeof (HubSetting));
    ZeroMem (&HubEndpoint, sizeof (HubEndpoint));
    HubDevice.Bus                         = &HubBus;
    HubDevice.Speed                       = Speed;
    HubDevice.Tier                        = 1;
    HubDevice.Address                     = 1;
    HubIf.Device                          = &HubDevice;
    HubIf.IfSetting                       = &HubSetting;
    HubIf.UsbIo.UsbAsyncInterruptTransfer = TestAsyncTransfer;
    HubSetting.Desc.NumEndpoints          = 1;
    HubEndpoint.Desc.EndpointAddress      = 0x81;
    HubEndpoint.Desc.Attributes           = USB_ENDPOINT_INTERRUPT;
    HubEndpointPointer                    = &HubEndpoint;
    HubSetting.Endpoints                  = &HubEndpointPointer;
    mControlTransferStatus                = EFI_SUCCESS;
    return mUsbHubApi.Init (&HubIf);
  }

  void
  QueryHubPort (
    UINT64  Elapsed,
    UINTN   ExpectedStall
    )
  {
    ASSERT_EQ (InitHub (), EFI_SUCCESS);
    EXPECT_EQ (mStallMicroseconds, (UINTN)0);
    EXPECT_EQ (HubIf.PowerGoodDelay, (UINTN)100000);
    mNow = Elapsed;
    EFI_USB_PORT_STATUS  PortStatus;

    mRootHubPortStatus.PortStatus       = USB_PORT_STAT_CONNECTION | USB_PORT_STAT_OVERCURRENT;
    mRootHubPortStatus.PortChangeStatus = USB_PORT_STAT_C_CONNECTION | USB_PORT_STAT_C_OVERCURRENT;
    ASSERT_EQ (mUsbHubApi.GetPortStatus (&HubIf, 0, &PortStatus), EFI_SUCCESS);
    EXPECT_EQ (mStallMicroseconds, ExpectedStall);
    EXPECT_EQ (mPortReads, (UINTN)1);
    EXPECT_EQ (mEarlyPortReads, (UINTN)0);
    EXPECT_EQ (PortStatus.PortStatus, mRootHubPortStatus.PortStatus);
    EXPECT_EQ (PortStatus.PortChangeStatus, mRootHubPortStatus.PortChangeStatus);
    EXPECT_EQ (HubIf.PowerGoodDelay, (UINTN)0);
    EXPECT_EQ (mUsbHubApi.GetPortStatus (&HubIf, 1, &PortStatus), EFI_SUCCESS);
    EXPECT_EQ (mStallMicroseconds, ExpectedStall);
    EXPECT_EQ (mUsbHubApi.Release (&HubIf), EFI_SUCCESS);
    EXPECT_EQ (mClosedEvents, (UINTN)1);
  }

  EFI_STATUS
  ResetExternalHub (
    UINT8  Speed = EFI_USB_SPEED_HIGH
    )
  {
    USB_BUS        Bus = {};
    USB_DEVICE     Device = {};
    USB_INTERFACE  Interface = {};

    Device.Bus        = &Bus;
    Device.Speed      = Speed;
    Device.Address    = 1;
    Device.MaxPacket0 = 64;
    Interface.Device  = &Device;
    mHubReset.Enabled = TRUE;
    return mUsbHubApi.ResetPort (&Interface, 0);
  }

  EFI_STATUS
  ResetRootPort (
    UINT8  MajorRevision
    )
  {
    USB_BUS               Bus;
    USB_DEVICE            RootDevice;
    USB_INTERFACE         RootIf;
    EFI_USB2_HC_PROTOCOL  Usb2Hc;

    ZeroMem (&Bus, sizeof (Bus));
    ZeroMem (&RootDevice, sizeof (RootDevice));
    ZeroMem (&RootIf, sizeof (RootIf));
    ZeroMem (&Usb2Hc, sizeof (Usb2Hc));

    Usb2Hc.MajorRevision = MajorRevision;
    Bus.Usb2Hc           = (MajorRevision == 0) ? nullptr : &Usb2Hc;
    RootDevice.Bus       = &Bus;
    RootIf.Device        = &RootDevice;
    return UsbRootHubResetPort (&RootIf, 0);
  }
};

/**
  Verify that a well-formed BOS containing a SuperSpeed capability is accepted.
**/
TEST_F (UsbBusDxeTest, RecognizesValidSuperSpeedCapability) {
  UINT8                       Buffer[sizeof (EFI_USB_BOS_DESCRIPTOR) + sizeof (EFI_USB_DEV_CAP_DESCRIPTOR)] = { 0 };
  EFI_USB_BOS_DESCRIPTOR      *Bos;
  EFI_USB_DEV_CAP_DESCRIPTOR  *Capability;

  Bos                           = (EFI_USB_BOS_DESCRIPTOR *)Buffer;
  Bos->Length                   = sizeof (*Bos);
  Bos->DescriptorType           = USB_DESC_TYPE_BOS;
  Bos->TotalLength              = sizeof (Buffer);
  Bos->NumDeviceCaps            = 1;
  Capability                    = (EFI_USB_DEV_CAP_DESCRIPTOR *)(Buffer + sizeof (*Bos));
  Capability->Length            = sizeof (*Capability);
  Capability->DescriptorType    = USB_DESC_TYPE_DEV_CAP;
  Capability->DevCapabilityType = USB_DEV_CAP_SUPPERSPEED_USB;

  EXPECT_TRUE (UsbIsSSDevice (Bos, sizeof (Buffer)));
}

/**
  Verify that a three-byte PTM capability is accepted before a SuperSpeed capability.
**/
TEST_F (UsbBusDxeTest, AcceptsThreeBytePtmCapability) {
  UINT8                       Buffer[sizeof (EFI_USB_BOS_DESCRIPTOR) + 3 + sizeof (EFI_USB_DEV_CAP_DESCRIPTOR)] = { 0 };
  EFI_USB_BOS_DESCRIPTOR      *Bos;
  UINT8                       *PtmCapability;
  EFI_USB_DEV_CAP_DESCRIPTOR  *SsCapability;

  Bos                             = (EFI_USB_BOS_DESCRIPTOR *)Buffer;
  Bos->Length                     = sizeof (*Bos);
  Bos->DescriptorType             = USB_DESC_TYPE_BOS;
  Bos->TotalLength                = sizeof (Buffer);
  Bos->NumDeviceCaps              = 2;
  PtmCapability                   = Buffer + sizeof (*Bos);
  PtmCapability[0]                = OFFSET_OF (EFI_USB_DEV_CAP_DESCRIPTOR, CapData);
  PtmCapability[1]                = USB_DESC_TYPE_DEV_CAP;
  PtmCapability[2]                = 0x0B;
  SsCapability                    = (EFI_USB_DEV_CAP_DESCRIPTOR *)(PtmCapability + PtmCapability[0]);
  SsCapability->Length            = sizeof (*SsCapability);
  SsCapability->DescriptorType    = USB_DESC_TYPE_DEV_CAP;
  SsCapability->DevCapabilityType = USB_DEV_CAP_SUPPERSPEED_USB;

  EXPECT_TRUE (UsbIsSSDevice (Bos, sizeof (Buffer)));
}

/**
  Verify that a capability extending beyond the BOS total length is rejected.
**/
TEST_F (UsbBusDxeTest, RejectsCapabilityBeyondBosTotalLength) {
  UINT8                       Buffer[sizeof (EFI_USB_BOS_DESCRIPTOR) + sizeof (EFI_USB_DEV_CAP_DESCRIPTOR)] = { 0 };
  EFI_USB_BOS_DESCRIPTOR      *Bos;
  EFI_USB_DEV_CAP_DESCRIPTOR  *Capability;

  Bos                           = (EFI_USB_BOS_DESCRIPTOR *)Buffer;
  Bos->Length                   = sizeof (*Bos);
  Bos->DescriptorType           = USB_DESC_TYPE_BOS;
  Bos->TotalLength              = sizeof (*Bos);
  Bos->NumDeviceCaps            = 1;
  Capability                    = (EFI_USB_DEV_CAP_DESCRIPTOR *)(Buffer + sizeof (*Bos));
  Capability->Length            = sizeof (*Capability);
  Capability->DescriptorType    = USB_DESC_TYPE_DEV_CAP;
  Capability->DevCapabilityType = USB_DEV_CAP_SUPPERSPEED_USB;

  EXPECT_FALSE (UsbIsSSDevice (Bos, sizeof (Buffer)));
}

/**
  Verify that a capability extending beyond the supplied BOS buffer is rejected.
**/
TEST_F (UsbBusDxeTest, RejectsCapabilityLengthBeyondBosBuffer) {
  UINT8                       Buffer[sizeof (EFI_USB_BOS_DESCRIPTOR) + sizeof (EFI_USB_DEV_CAP_DESCRIPTOR)] = { 0 };
  EFI_USB_BOS_DESCRIPTOR      *Bos;
  EFI_USB_DEV_CAP_DESCRIPTOR  *Capability;

  Bos                           = (EFI_USB_BOS_DESCRIPTOR *)Buffer;
  Bos->Length                   = sizeof (*Bos);
  Bos->DescriptorType           = USB_DESC_TYPE_BOS;
  Bos->TotalLength              = sizeof (Buffer);
  Bos->NumDeviceCaps            = 1;
  Capability                    = (EFI_USB_DEV_CAP_DESCRIPTOR *)(Buffer + sizeof (*Bos));
  Capability->Length            = sizeof (*Capability) + 1;
  Capability->DescriptorType    = USB_DESC_TYPE_DEV_CAP;
  Capability->DevCapabilityType = USB_DEV_CAP_SUPPERSPEED_USB;

  EXPECT_FALSE (UsbIsSSDevice (Bos, sizeof (Buffer)));
}

/**
  Verify failed BOS reads free their buffer and short total lengths are rejected.
**/
TEST_F (UsbBusDxeTest, HandlesBosReadFailureAndShortTotalLength) {
  USB_BUS          Bus;
  USB_DEVICE       UsbDevice;
  USB_DEVICE_DESC  DeviceDesc;

  ZeroMem (&Bus, sizeof (Bus));
  ZeroMem (&UsbDevice, sizeof (UsbDevice));
  ZeroMem (&DeviceDesc, sizeof (DeviceDesc));
  UsbDevice.Bus     = &Bus;
  UsbDevice.DevDesc = &DeviceDesc;

  EXPECT_EQ (UsbGetDevBosDesc (&UsbDevice), EFI_DEVICE_ERROR);
  EXPECT_EQ (mControlTransferCount, (UINTN)1);
  EXPECT_EQ (mFreePoolCount, (UINTN)1);
  EXPECT_EQ (DeviceDesc.BosDesc, nullptr);

  mFreePoolCount                = 0;
  mControlTransferCount         = 0;
  mControlTransferStatus        = EFI_SUCCESS;
  mBosDescriptor.Length         = sizeof (mBosDescriptor);
  mBosDescriptor.DescriptorType = USB_DESC_TYPE_BOS;
  mBosDescriptor.TotalLength    = sizeof (mBosDescriptor) - 1;

  EXPECT_EQ (UsbGetDevBosDesc (&UsbDevice), EFI_DEVICE_ERROR);
  EXPECT_EQ (mControlTransferCount, (UINTN)1);
  EXPECT_EQ (mFreePoolCount, (UINTN)1);
  EXPECT_EQ (DeviceDesc.BosDesc, nullptr);
}

/**
  Verify root-hub reset does not dereference a null device descriptor.
**/
TEST_F (UsbBusDxeTest, AvoidsNullDereferenceDuringRootHubReset) {
  USB_BUS               Bus;
  USB_DEVICE            RootDevice;
  USB_DEVICE            Child;
  USB_INTERFACE         RootIf;
  EFI_USB2_HC_PROTOCOL  Usb2Hc;
  CONST UINT8           Port = 1;

  ZeroMem (&Bus, sizeof (Bus));
  ZeroMem (&RootDevice, sizeof (RootDevice));
  ZeroMem (&Child, sizeof (Child));
  ZeroMem (&RootIf, sizeof (RootIf));
  ZeroMem (&Usb2Hc, sizeof (Usb2Hc));

  Usb2Hc.MajorRevision = 0x3;
  Bus.MaxDevices       = 2;
  Bus.Usb2Hc           = &Usb2Hc;
  Bus.Devices[1]       = &Child;

  RootDevice.Bus = &Bus;
  RootIf.Device  = &RootDevice;

  Child.ParentIf   = &RootIf;
  Child.ParentPort = Port;
  Child.Speed      = EFI_USB_SPEED_HIGH;
  Child.IsSSDev    = TRUE;
  Child.DevDesc    = NULL;

  ASSERT_EQ (Child.DevDesc, nullptr);
  EXPECT_EQ (UsbRootHubResetPort (&RootIf, Port), EFI_SUCCESS);
}

/**
  xHCI completes reset in hardware; retain the post-reset recovery delay.
**/
TEST_F (UsbBusDxeTest, DoesNotRepeatCompletedXhciResetDelay) {
  EXPECT_EQ (ResetRootPort (3), EFI_SUCCESS);
  EXPECT_EQ (mStallMicroseconds, (UINTN)USB_SET_PORT_RECOVERY_STALL);
  EXPECT_EQ (mRootStatusStall, (UINTN)USB_SET_PORT_RECOVERY_STALL);
}

/**
  Legacy controllers still need software to hold reset for at least 50 ms.
**/
TEST_F (UsbBusDxeTest, PreservesLegacyRootResetTiming) {
  EXPECT_EQ (ResetRootPort (2), EFI_SUCCESS);
  EXPECT_EQ (mStallMicroseconds, (UINTN)(USB_SET_ROOT_PORT_RESET_STALL + USB_CLR_ROOT_PORT_RESET_STALL));
  EXPECT_EQ (mRootStatusStall, (UINTN)(USB_SET_ROOT_PORT_RESET_STALL + USB_CLR_ROOT_PORT_RESET_STALL));
  mStallMicroseconds = 0;
  EXPECT_EQ (ResetRootPort (0), EFI_SUCCESS);
  EXPECT_EQ (mStallMicroseconds, (UINTN)(USB_SET_ROOT_PORT_RESET_STALL + USB_CLR_ROOT_PORT_RESET_STALL));
  EXPECT_EQ (mRootStatusStall, (UINTN)(USB_SET_ROOT_PORT_RESET_STALL + USB_CLR_ROOT_PORT_RESET_STALL));
}

/**
  A failed reset stops before recovery or port enumeration.
**/
TEST_F (UsbBusDxeTest, PropagatesRootResetFailureWithoutWaiting) {
  mResetStatus = EFI_TIMEOUT;
  EXPECT_EQ (ResetRootPort (3), EFI_TIMEOUT);
  EXPECT_EQ (mStallMicroseconds, (UINTN)0);
  EXPECT_EQ (mRootStatusStall, MAX_UINTN);
}

TEST_F (UsbBusDxeTest, FollowsExternalHubResetCompletion) {
  EXPECT_EQ (ResetExternalHub (), EFI_SUCCESS);
  EXPECT_EQ (mNow, 20000U);
  EXPECT_EQ (mHubReset.Resets, 1U);
  EXPECT_EQ (mHubReset.Clears, 1U);
}

TEST_F (UsbBusDxeTest, FollowsFullSpeedExternalHubResetCompletion) {
  EXPECT_EQ (ResetExternalHub (EFI_USB_SPEED_FULL), EFI_SUCCESS);
  EXPECT_EQ (mNow, 20000U);
}

TEST_F (UsbBusDxeTest, WaitsForSlowerExternalHubReset) {
  mHubReset.Duration = 20000;
  EXPECT_EQ (ResetExternalHub (), EFI_SUCCESS);
  EXPECT_EQ (mNow, 30000U);
}

TEST_F (UsbBusDxeTest, DoesNotAcceptStaleExternalHubResetCompletion) {
  mHubReset.Duration = 25000;
  mHubReset.Changes  = USB_PORT_STAT_C_RESET;
  EXPECT_EQ (ResetExternalHub (), EFI_SUCCESS);
  EXPECT_EQ (mNow, 35000U);
  EXPECT_EQ (mHubReset.Clears, 1U);
}

TEST_F (UsbBusDxeTest, TimesOutWithoutFreshExternalHubResetCompletion) {
  mHubReset.Duration = MAX_UINT64;
  mHubReset.Changes  = USB_PORT_STAT_C_RESET;
  EXPECT_EQ (ResetExternalHub (), EFI_TIMEOUT);
  EXPECT_EQ (mHubReset.Reads, (UINTN)USB_WAIT_PORT_STS_CHANGE_LOOP);
  EXPECT_EQ (mNow, (UINT64)(10000 + USB_WAIT_PORT_STS_CHANGE_LOOP * USB_WAIT_PORT_STS_CHANGE_STALL));
}

TEST_F (UsbBusDxeTest, DoesNotAcceptOtherExternalHubChangesAsResetCompletion) {
  mHubReset.Duration = MAX_UINT64;
  mHubReset.Changes  = USB_PORT_STAT_C_CONNECTION;
  EXPECT_EQ (ResetExternalHub (), EFI_TIMEOUT);
  EXPECT_EQ (mHubReset.Changes, USB_PORT_STAT_C_CONNECTION);
}

TEST_F (UsbBusDxeTest, PreservesSuperSpeedWarmResetCompletion) {
  EXPECT_EQ (ResetExternalHub (EFI_USB_SPEED_SUPER), EFI_SUCCESS);
  EXPECT_EQ (mNow, 20000U);
  EXPECT_EQ (mHubReset.Resets, 1U);
  EXPECT_EQ (mHubReset.Clears, 2U);
}

TEST_F (UsbBusDxeTest, PropagatesExternalHubResetTransferFailures) {
  for (UINT8 Request : { USB_HUB_REQ_CLEAR_FEATURE, USB_HUB_REQ_SET_FEATURE, USB_HUB_REQ_GET_STATUS }) {
    mNow                  = 0;
    mHubReset.Active      = FALSE;
    mHubReset.FailRequest = Request;
    EXPECT_EQ (ResetExternalHub (), EFI_DEVICE_ERROR);
    EXPECT_EQ (mNow, (Request == USB_HUB_REQ_GET_STATUS) ? 10000U : 0U);
  }
}

/**
  Initialize GoogleTest and return the aggregate result of the test suite.

  @param[in,out] argc  Number of command-line arguments.
  @param[in,out] argv  Command-line arguments.

  @retval GoogleTest test-suite result.
**/
int
main (
  int   argc,
  char  *argv[]
  )
{
  testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}

TEST_F (UsbBusDxeTest, OverlapsHubPowerDelayWithOtherInitialization) {
  QueryHubPort (150000, 0);
}

TEST_F (UsbBusDxeTest, WaitsOnlyForRemainingHubPowerDelay) {
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, WaitsFullHubDelayWhenNoOtherWorkIntervenes) {
  QueryHubPort (0, 100000);
}

TEST_F (UsbBusDxeTest, AcceptsExactHubPowerDeadline) {
  QueryHubPort (100000, 0);
}

TEST_F (UsbBusDxeTest, PreservesDelayAcrossUpCounterWrap) {
  mCounterBase = MAX_UINT64 - 9999;
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, PreservesDelayWithDownCounter) {
  mCounterFirst = MAX_UINT64;
  mCounterLast  = 0;
  mCounterBase  = 500000;
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, PreservesDelayAcrossDownCounterWrap) {
  mCounterFirst = MAX_UINT64;
  mCounterLast  = 0;
  mCounterBase  = 10000;
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, PreservesFullDelayWithoutPerformanceCounter) {
  mFrequency = 0;
  QueryHubPort (40000, 100000);
}

TEST_F (UsbBusDxeTest, DoesNotCreateUnneededPowerDelays) {
  mHubDescriptor.PwrOn2PwrGood = 0;
  ASSERT_EQ (InitHub (), EFI_SUCCESS);
  EXPECT_EQ (HubIf.PowerGoodDelay, (UINTN)0);
  EXPECT_EQ (mStallMicroseconds, (UINTN)0);
  EXPECT_EQ (mUsbHubApi.Release (&HubIf), EFI_SUCCESS);
  ASSERT_EQ (InitHub (EFI_USB_SPEED_SUPER), EFI_SUCCESS);
  EXPECT_EQ (HubIf.PowerGoodDelay, (UINTN)0);
  EXPECT_EQ (mStallMicroseconds, (UINTN)0);
  EXPECT_EQ (mUsbHubApi.Release (&HubIf), EFI_SUCCESS);
}

TEST_F (UsbBusDxeTest, PreservesDelayAcrossBoundedUpCounterWrap) {
  mCounterFirst = 100;
  mCounterLast  = 1000099;
  mCounterBase  = 1000000;
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, PreservesDelayAcrossBoundedDownCounterWrap) {
  mCounterFirst = 1000099;
  mCounterLast  = 100;
  mCounterBase  = 5000;
  QueryHubPort (40000, 60000);
}

TEST_F (UsbBusDxeTest, UsesAdvertisedHubPowerDelay) {
  for (UINT8 Delay : { 1, 50, 255 }) {
    SetUp ();
    mHubDescriptor.PwrOn2PwrGood = Delay;
    ASSERT_EQ (InitHub (), EFI_SUCCESS);
    EXPECT_EQ (mStallMicroseconds, (UINTN)0);
    EXPECT_EQ (HubIf.PowerGoodDelay, (UINTN)Delay * USB_SET_PORT_POWER_STALL);
    EFI_USB_PORT_STATUS  PortStatus;
    EXPECT_EQ (mUsbHubApi.GetPortStatus (&HubIf, 0, &PortStatus), EFI_SUCCESS);
    EXPECT_EQ (mStallMicroseconds, (UINTN)Delay * USB_SET_PORT_POWER_STALL);
    EXPECT_EQ (mEarlyPortReads, (UINTN)0);
    EXPECT_EQ (mUsbHubApi.Release (&HubIf), EFI_SUCCESS);
  }
}

extern "C" {
  VOID *EFIAPI
  __real_AllocateZeroPool (
    UINTN  Size
    );

  VOID *EFIAPI
  __wrap_AllocateZeroPool (
    UINTN  Size
    )
  {
    if (mFailRootAllocation && (Size == sizeof (USB_PORT_STATE) * ARRAY_SIZE (mPorts))) {
      mFailRootAllocation = FALSE;
      return NULL;
    }

    return __real_AllocateZeroPool (Size);
  }

  static EFI_TPL EFIAPI
  EnumRaiseTpl (
    EFI_TPL  Tpl
    )
  {
    EFI_TPL  Old = mTpl;

    mTpl = Tpl;
    return Old;
  }

  static VOID EFIAPI
  EnumRestoreTpl (
    EFI_TPL  Tpl
    )
  {
    mTpl = Tpl;
  }

  static EFI_STATUS EFIAPI
  EnumInstall (
    EFI_HANDLE  *Handle,
    ...
    )
  {
    VA_LIST   Args;
    EFI_GUID  *Guid;
    VOID      *Interface;

    VA_START (Args, Handle);
    while ((Guid = VA_ARG (Args, EFI_GUID *)) != NULL) {
      Interface = VA_ARG (Args, VOID *);
      if (CompareGuid (Guid, &gEfiUsbIoProtocolGuid)) {
        *Handle = Interface;
      }
    }

    VA_END (Args);
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumUninstall (
    EFI_HANDLE  Handle,
    ...
    )
  {
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumOpen (
    EFI_HANDLE  Handle,
    EFI_GUID    *Guid,
    VOID        **Interface,
    EFI_HANDLE  Agent,
    EFI_HANDLE  Child,
    UINT32      Attributes
    )
  {
    *Interface = NULL;
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumClose (
    EFI_HANDLE  Handle,
    EFI_GUID    *Guid,
    EFI_HANDLE  Agent,
    EFI_HANDLE  Child
    )
  {
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumConnect (
    EFI_HANDLE                Handle,
    EFI_HANDLE                *Drivers,
    EFI_DEVICE_PATH_PROTOCOL  *Path,
    BOOLEAN                   Recursive
    )
  {
    EFI_USB_INTERFACE_DESCRIPTOR  Desc;
    auto                          Io = (EFI_USB_IO_PROTOCOL *)Handle;

    EXPECT_EQ (Io->UsbGetInterfaceDescriptor (Io, &Desc), EFI_SUCCESS);
    EXPECT_EQ (Desc.InterfaceClass, 3);
    EXPECT_EQ (Desc.InterfaceSubClass, 1);
    EXPECT_EQ (Desc.InterfaceProtocol, 1);
    mConnectedKeyboards++;
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumDisconnect (
    EFI_HANDLE  Handle,
    EFI_HANDLE  Driver,
    EFI_HANDLE  Child
    )
  {
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumSignal (
    EFI_EVENT  Event
    )
  {
    mNotify (Event, mNotifyContext);
    return EFI_SUCCESS;
  }

  static EFI_STATUS EFIAPI
  EnumTimer (
    EFI_EVENT        Event,
    EFI_TIMER_DELAY  Type,
    UINT64           Time
    )
  {
    if (Type == TimerPeriodic) {
      mRootPollInterval = Time;
    }

    return (Type == TimerCancel) ? EFI_SUCCESS : mTimerStatus;
  }
}

class UsbRootEnumerationTest : public UsbBusDxeTest {
protected:
  USB_BUS Bus;
  USB_DEVICE RootDevice;
  USB_INTERFACE Root;
  EFI_USB2_HC_PROTOCOL Hc;
  EFI_DEVICE_PATH_PROTOCOL End;

  void
  SetUp (
    ) override
  {
    UsbBusDxeTest::SetUp ();
    mEnumerating        = TRUE;
    mConsumeChanges     = TRUE;
    mFailRootAllocation = FALSE;
    mCreateStatus       = mTimerStatus = EFI_SUCCESS;
    mConnectedKeyboards = mDebounceWaits = 0;
    mRootPollInterval = 0;
    mDuringDebounce     = NULL;
    mInvalidTransfers   = mActivePort = 0;
    ZeroMem (mInjectAt, sizeof (mInjectAt));
    ZeroMem (mInjectChanges, sizeof (mInjectChanges));
    ZeroMem (mFailInitAt, sizeof (mFailInitAt));
    ZeroMem (mSlotReady, sizeof (mSlotReady));
    mTpl = TPL_CALLBACK;
    ZeroMem (mPorts, sizeof (mPorts));
    ZeroMem (mReads, sizeof (mReads));
    ZeroMem (mFailRead, sizeof (mFailRead));
    ZeroMem (mResets, sizeof (mResets));
    ZeroMem (mResetTime, sizeof (mResetTime));
    ZeroMem (&Bus, sizeof (Bus));
    ZeroMem (&RootDevice, sizeof (RootDevice));
    ZeroMem (&Root, sizeof (Root));
    ZeroMem (&Hc, sizeof (Hc));
    SetDevicePathEndNode (&End);
    Bus.Signature    = USB_BUS_SIGNATURE;
    Bus.Usb2Hc       = &Hc;
    Hc.MajorRevision = 3;
    Bus.MaxDevices   = ARRAY_SIZE (Bus.Devices);
    InitializeListHead (&Bus.WantedUsbIoDPList);
    ASSERT_EQ (UsbBusAddWantedUsbIoDP (&Bus.BusId, NULL), EFI_SUCCESS);
    RootDevice.Bus                                    = &Bus;
    RootDevice.NumOfInterface                         = 1;
    RootDevice.Interfaces[0]                          = &Root;
    Root.Device                                       = &RootDevice;
    Root.DevicePath                                   = &End;
    Bus.Devices[0]                                    = &RootDevice;
    mBootServices.RaiseTPL                            = EnumRaiseTpl;
    mBootServices.RestoreTPL                          = EnumRestoreTpl;
    mBootServices.InstallMultipleProtocolInterfaces   = EnumInstall;
    mBootServices.UninstallMultipleProtocolInterfaces = EnumUninstall;
    mBootServices.OpenProtocol                        = EnumOpen;
    mBootServices.CloseProtocol                       = EnumClose;
    mBootServices.ConnectController                   = EnumConnect;
    mBootServices.DisconnectController                = EnumDisconnect;
    mBootServices.SignalEvent                         = EnumSignal;
    mBootServices.SetTimer                            = EnumTimer;
  }

  void
  TearDown (
    ) override
  {
    for (UINTN Id = 1; Id < Bus.MaxDevices; Id++) {
      if (Bus.Devices[Id] != NULL) {
        EXPECT_EQ (UsbRemoveDevice (Bus.Devices[Id]), EFI_SUCCESS);
      }
    }

    if (!EFI_ERROR (mCreateStatus) && !EFI_ERROR (mTimerStatus)) {
      EXPECT_EQ (mUsbRootHubApi.Release (&Root), EFI_SUCCESS);
    }

    EXPECT_EQ (UsbBusFreeUsbDPList (&Bus.WantedUsbIoDPList), EFI_SUCCESS);
    EXPECT_EQ (Root.Ports, nullptr);
    mEnumerating = FALSE;
  }

  void
  Attach (
    UINTN  Port
    )
  {
    mPorts[Port].PortStatus       = USB_PORT_STAT_CONNECTION | USB_PORT_STAT_HIGH_SPEED;
    mPorts[Port].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
  }

  void
  Init (
    )
  {
    ASSERT_EQ (mUsbRootHubApi.Init (&Root), EFI_SUCCESS);
  }

  void
  Poll (
    )
  {
    UsbRootHubEnumeration (Root.HubNotify, &Root);
  }
};

TEST_F (UsbRootEnumerationTest, SharesDebounceAndConnectsAllHidInterfacesBeforeReturning) {
  Attach (0);
  Attach (1);
  Attach (2);
  Init ();
  EXPECT_EQ (mDebounceWaits, 1U);
  EXPECT_EQ (mConnectedKeyboards, 3U);
  for (UINTN Port = 0; Port < ARRAY_SIZE (mPorts); Port++) {
    EXPECT_EQ (mResets[Port], 1U);
    EXPECT_GE (mResetTime[Port], (UINTN)USB_WAIT_PORT_STABLE_STALL);
  }

  Poll ();
  EXPECT_EQ (mConnectedKeyboards, 3U);
}

TEST_F (UsbRootEnumerationTest, RetainsSerialTimingForNonConsumingController) {
  mConsumeChanges = FALSE;
  Attach (0);
  Attach (1);
  Attach (2);
  Init ();
  EXPECT_EQ (mDebounceWaits, 3U);
  EXPECT_EQ (mConnectedKeyboards, 3U);
}

TEST_F (UsbRootEnumerationTest, RestartsDebounceForReconnectDuringSharedWait) {
  Attach (0);
  Attach (1);
  mDuringDebounce = [] () {
                      mPorts[1].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
                    };
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 2U);
  EXPECT_GE (mResetTime[1], (UINTN)(2 * USB_WAIT_PORT_STABLE_STALL));
}

TEST_F (UsbRootEnumerationTest, DebouncesAttachmentArrivingAfterCollection) {
  Attach (0);
  mDuringDebounce = [] () {
                      mPorts[2].PortStatus       = USB_PORT_STAT_CONNECTION | USB_PORT_STAT_HIGH_SPEED;
                      mPorts[2].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
                    };
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 2U);
  EXPECT_GE (mResetTime[2], (UINTN)(2 * USB_WAIT_PORT_STABLE_STALL));
}

TEST_F (UsbRootEnumerationTest, RetainsConsumedAttachmentAcrossStatusError) {
  Attach (0);
  mFailRead[0] = 3;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 0U);
  EXPECT_EQ (mResets[0], 0U);
  ASSERT_NE (Root.Ports, nullptr);
  EXPECT_EQ (Root.Ports[0].Changes, USB_PORT_STAT_C_CONNECTION);
  Poll ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mResets[0], 1U);
}

TEST_F (UsbRootEnumerationTest, RetainsOvercurrentUntilHardwareRecovers) {
  Attach (0);
  mPorts[0].PortStatus       |= USB_PORT_STAT_OVERCURRENT;
  mPorts[0].PortChangeStatus |= USB_PORT_STAT_C_OVERCURRENT;
  Init ();
  EXPECT_EQ (mDebounceWaits, 0U);
  EXPECT_EQ (mConnectedKeyboards, 0U);
  EXPECT_EQ (mResets[0], 0U);
  EXPECT_NE (Root.Ports[0].Changes & USB_PORT_STAT_C_OVERCURRENT, 0);
  mPorts[0].PortStatus &= (UINT16) ~USB_PORT_STAT_OVERCURRENT;
  Poll ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mDebounceWaits, 1U);
}

TEST_F (UsbRootEnumerationTest, ProcessesConsumedEnableRecovery) {
  Attach (0);
  mPorts[0].PortChangeStatus |= USB_PORT_STAT_C_ENABLE;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mResets[0], 1U);
  EXPECT_EQ (mDebounceWaits, 1U);
}

TEST_F (UsbRootEnumerationTest, DoesNotUseOldResetCompletionForReplacementDevice) {
  Attach (0);
  Attach (1);
  mPorts[1].PortChangeStatus = USB_PORT_STAT_C_RESET;
  mDuringDebounce            = [] () {
                                 mPorts[1].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
                               };
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mResets[1], 1U);
}

TEST_F (UsbRootEnumerationTest, RechecksResetCompletionAfterCollection) {
  Attach (0);
  mPorts[0].PortChangeStatus = USB_PORT_STAT_C_RESET;
  mPorts[0].PortStatus      |= USB_PORT_STAT_ENABLE;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mResets[0], 1U);
  EXPECT_EQ (mDebounceWaits, 1U);
}

TEST_F (UsbRootEnumerationTest, AllocationFailureKeepsLegacyEnumeration) {
  Attach (0);
  Attach (1);
  mFailRootAllocation = TRUE;
  Init ();
  EXPECT_EQ (Root.Ports, nullptr);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 2U);
}

TEST_F (UsbRootEnumerationTest, EmptyHubDoesNotWait) {
  Init ();
  EXPECT_EQ (mDebounceWaits, 0U);
  EXPECT_EQ (mConnectedKeyboards, 0U);
}

TEST_F (UsbRootEnumerationTest, ReleasesPendingStorageOnCreateEventFailure) {
  mCreateStatus = EFI_OUT_OF_RESOURCES;
  EXPECT_EQ (mUsbRootHubApi.Init (&Root), EFI_OUT_OF_RESOURCES);
  EXPECT_EQ (Root.Ports, nullptr);
}

TEST_F (UsbRootEnumerationTest, ReleasesPendingStorageOnSetTimerFailure) {
  mTimerStatus = EFI_DEVICE_ERROR;
  EXPECT_EQ (mUsbRootHubApi.Init (&Root), EFI_DEVICE_ERROR);
  EXPECT_EQ (Root.Ports, nullptr);
}

TEST_F (UsbRootEnumerationTest, SavedResetDoesNotOverrideFreshEnableRecovery) {
  Attach (0);
  mPorts[0].PortStatus      |= USB_PORT_STAT_ENABLE;
  mPorts[0].PortChangeStatus = USB_PORT_STAT_C_RESET;
  mInjectAt[0]               = 2;
  mInjectChanges[0]          = USB_PORT_STAT_C_ENABLE;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
  EXPECT_EQ (mResets[0], 1U);
}

TEST_F (UsbRootEnumerationTest, SavedResetDoesNotOverrideFreshOvercurrentRecovery) {
  Attach (0);
  mPorts[0].PortStatus      |= USB_PORT_STAT_ENABLE;
  mPorts[0].PortChangeStatus = USB_PORT_STAT_C_RESET;
  mInjectAt[0]               = 2;
  mInjectChanges[0]          = USB_PORT_STAT_C_OVERCURRENT;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
  EXPECT_EQ (mResets[0], 1U);
}

TEST_F (UsbRootEnumerationTest, SavedResetDoesNotHideInitializationFailureWithNoChangeBits) {
  Attach (0);
  mPorts[0].PortStatus      |= USB_PORT_STAT_ENABLE;
  mPorts[0].PortChangeStatus = USB_PORT_STAT_C_RESET;
  mInjectAt[0]               = 2;
  mInjectChanges[0]          = USB_PORT_STAT_C_RESET;
  mFailInitAt[0]             = 2;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
  EXPECT_EQ (mResets[0], 1U);
}

TEST_F (UsbRootEnumerationTest, OvercurrentDuringDebounceDoesNotResetOrConnect) {
  Attach (0);
  mDuringDebounce = [] () {
                      mPorts[0].PortStatus      |= USB_PORT_STAT_OVERCURRENT;
                      mPorts[0].PortChangeStatus = USB_PORT_STAT_C_OVERCURRENT;
                    };
  Init ();
  EXPECT_EQ (mResets[0], 0U);
  EXPECT_EQ (mConnectedKeyboards, 0U);
  EXPECT_NE (Root.Ports[0].Changes & USB_PORT_STAT_C_OVERCURRENT, 0);
}

TEST_F (UsbRootEnumerationTest, DisconnectDuringDebounceDoesNotResetOrConnect) {
  Attach (0);
  mDuringDebounce = [] () {
                      mPorts[0].PortStatus       = 0;
                      mPorts[0].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
                    };
  Init ();
  EXPECT_EQ (mResets[0], 0U);
  EXPECT_EQ (mConnectedKeyboards, 0U);
  EXPECT_EQ (Root.Ports[0].Changes, 0);
}

TEST_F (UsbRootEnumerationTest, FreshResetCompletionCanStillSkipAnotherReset) {
  Attach (0);
  mDuringDebounce = [] () {
                      mPorts[0].PortStatus      |= USB_PORT_STAT_ENABLE;
                      mPorts[0].PortChangeStatus = USB_PORT_STAT_C_RESET;
                    };
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mResets[0], 0U);
  EXPECT_EQ (mInvalidTransfers, 0U);
}

TEST_F (UsbRootEnumerationTest, StatusErrorDuringCollectionDoesNotLoseTheAttachment) {
  Attach (0);
  mFailRead[0] = 2;
  Init ();
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mDebounceWaits, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
}

TEST_F (UsbRootEnumerationTest, UsesTenMillisecondPollWithoutShorteningDebounce) {
  Attach (0);
  Attach (1);
  Init ();
  EXPECT_EQ (mRootPollInterval, 10U * 10000U);
  EXPECT_EQ (mDebounceWaits, 1U);
  EXPECT_EQ (mConnectedKeyboards, 2U);
}

class UsbHubBatchTest : public UsbRootEnumerationTest {
protected:
  USB_ENDPOINT_DESC Endpoint;

  void
  SetUp (
    ) override
  {
    UsbRootEnumerationTest::SetUp ();
    ZeroMem (&Endpoint, sizeof (Endpoint));
    Root.HubEp       = &Endpoint;
    Root.HubApi      = &mUsbRootHubApi;
    Root.NumOfPort   = ARRAY_SIZE (mPorts);
    Root.MaxSpeed    = EFI_USB_SPEED_HIGH;
    RootDevice.Speed = EFI_USB_SPEED_HIGH;
    Root.Ports       = (USB_PORT_STATE *)AllocateZeroPool (Root.NumOfPort * sizeof (*Root.Ports));
    ASSERT_NE (Root.Ports, nullptr);
  }

  void
  Notify (
    UINT8  Map
    )
  {
    Root.ChangeMap = (UINT8 *)AllocateZeroPool (1);
    ASSERT_NE (Root.ChangeMap, nullptr);
    *Root.ChangeMap = Map;
    UsbHubEnumeration (Root.HubNotify, &Root);
  }
};

TEST_F (UsbHubBatchTest, ConnectsBothPortsBeforeReturningAfterOneSharedWait) {
  Attach (0);
  Attach (1);
  Notify (6);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
  EXPECT_EQ (Root.ChangeMap, nullptr);
}

TEST_F (UsbHubBatchTest, MissingPortStorageKeepsTheSerialWait) {
  FreePool (Root.Ports);
  Root.Ports = nullptr;
  Attach (0);
  Attach (1);
  Notify (6);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 2U);
}

TEST_F (UsbHubBatchTest, NewEdgeDuringTheSharedWaitRequiresFreshDebounce) {
  Attach (0);
  Attach (1);
  mInjectAt[0]      = 3;
  mInjectChanges[0] = USB_PORT_STAT_C_CONNECTION;
  Notify (6);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 2U);
  EXPECT_EQ (mInvalidTransfers, 0U);
}

static EFI_STATUS EFIAPI
DeferBatchSignal (
  EFI_EVENT  Event
  )
{
  return EFI_SUCCESS;
}

static VOID
ReportSecondBatchPort (
  VOID
  )
{
  UINT8  Map = 4;

  mPorts[1].PortStatus       = USB_PORT_STAT_CONNECTION | USB_PORT_STAT_HIGH_SPEED;
  mPorts[1].PortChangeStatus = USB_PORT_STAT_C_CONNECTION;
  EXPECT_EQ (UsbOnHubInterrupt (&Map, sizeof (Map), mNotifyContext, EFI_USB_NOERROR), EFI_SUCCESS);
}

TEST_F (UsbHubBatchTest, KeepsNewInterruptSeparateFromTheAcknowledgedSnapshot) {
  mNotifyContext            = &Root;
  mBootServices.SignalEvent = DeferBatchSignal;
  mDuringDebounce           = ReportSecondBatchPort;
  Attach (0);
  Notify (2);
  EXPECT_EQ (mConnectedKeyboards, 1U);
  ASSERT_NE (Root.ChangeMap, nullptr);
  EXPECT_EQ (*Root.ChangeMap, 4U);
  UsbHubEnumeration (Root.HubNotify, &Root);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (Root.ChangeMap, nullptr);
}

TEST_F (UsbHubBatchTest, MergesQueuedInterruptBitsWithinTheHubBitmap) {
  UINT8  First[] = { 2, 0xff };
  UINT8  Second  = 4;

  mBootServices.SignalEvent = DeferBatchSignal;
  Attach (0);
  Attach (1);
  EXPECT_EQ (UsbOnHubInterrupt (First, sizeof (First), &Root, EFI_USB_NOERROR), EFI_SUCCESS);
  EXPECT_EQ (UsbOnHubInterrupt (&Second, sizeof (Second), &Root, EFI_USB_NOERROR), EFI_SUCCESS);
  ASSERT_NE (Root.ChangeMap, nullptr);
  EXPECT_EQ (*Root.ChangeMap, 6U);
  UsbHubEnumeration (Root.HubNotify, &Root);
  EXPECT_EQ (mConnectedKeyboards, 2U);
  EXPECT_EQ (mDebounceWaits, 1U);
}

TEST_F (UsbHubBatchTest, RetriesTheRetainedConnectionAfterAProcessingReadFailure) {
  Attach (0);
  mFailRead[0] = 3;
  Notify (2);
  EXPECT_EQ (mConnectedKeyboards, 1U);
  EXPECT_EQ (mInvalidTransfers, 0U);
  EXPECT_EQ (Root.Ports[0].Changes, 0U);
}
