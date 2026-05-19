/** @file
  AMD GOP platform configuration blocks passed via platform-to-driver.
**/

#ifndef AMD_PLATFORM_GOP_POLICY_H_
#define AMD_PLATFORM_GOP_POLICY_H_

#include <Uefi.h>
#include <Protocol/PlatformToDriverConfiguration.h>
#include <Protocol/AmiPlatformToDriverAgent.h>

#define ATI_VGA_VID  0x1002

extern EFI_GUID  gEfiPlatformToAmdGopConfigurationGuid;

typedef enum {
  DisplayDeviceCRT  = (UINT32)0x80010100,
  DisplayDeviceLCD  = (UINT32)0x80010400,
  DisplayDeviceCRT2 = (UINT32)0x80010101,
  DisplayDeviceDFP1 = (UINT32)0x80010300,
  DisplayDeviceDFP2 = (UINT32)0x80010301,
  DisplayDeviceDFP3 = (UINT32)0x80010302,
  DisplayDeviceDFP4 = (UINT32)0x80010303,
  DisplayDeviceDFP5 = (UINT32)0x80010304,
  DisplayDeviceDFP6 = (UINT32)0x80010305,
  DisplayDeviceDFP7 = (UINT32)0x80010306,
} DISPLAY_DEVICE_TYPE_NUMBER;

typedef struct {
  UINT32    Revision;
  UINT32    Priority1ActiveDisplay;
  UINT32    Priority2ActiveDisplay;
  UINT32    Priority3ActiveDisplay;
  UINT32    Priority4ActiveDisplay;
  UINT32    Priority5ActiveDisplay;
  UINT32    Priority6ActiveDisplay;
  UINT32    Reserved1[6];
  UINT32    PlatformFeatureEnabled;
  UINT32    Reserved2[3];
} PLATFORM_TO_AMDGOP_CONFIGURATION;

typedef struct {
  UINT32    Revision;
  UINT32    GPU_Controlled_LCD_PWM_FREQ_InHz;
  UINT8     LCD_BootUp_BL_Level;
  UINT8     Reserved;
  UINT8     LCD_Min_BL_Level;
  UINT8     Reserved2;
  UINT32    LVDSMiscConfiguration;
  UINT8     LVDSPwrOnDIGONtoDE_in4Ms;
  UINT8     LVDSPwrOnDEtoVARY_BL_in4Ms;
  UINT8     LVDSPwrOnVARY_BLtoBLON_in4Ms;
  UINT8     LVDSPwrOffBLOFFtoVARY_BL_in4Ms;
  UINT8     LVDSPwrOffVARY_BLtoDE_in4Ms;
  UINT8     LVDSPwrOffDEtoDIGON_in4Ms;
  UINT8     LCDOffToOnDelay_in4Ms;
  UINT8     Reserved3[7];
  UINT16    LVDSSpreadSpectrumRateIn10Hz;
  UINT16    LVDSSpreadSpectrumPercentage;
  UINT32    Reserved4[12];
} PLATFORM_TO_AMDGOP_CONFIGURATION1;

#endif
