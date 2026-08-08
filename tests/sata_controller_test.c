/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/sata_controller.h>
#include <stdio.h>
static int check(int c,const char*m){if(!c)fprintf(stderr,"sata: %s\n",m);return !c;}
int main(void){struct cdk2_sata_geometry g;struct cdk2_ata_identify id={2U<<8,6,3,120,0x3f};
	struct cdk2_ata_mode mode,bad={4,5,1};struct cdk2_sata_controller ctl;int f=0;UINT16 d=2,s;BOOLEAN enabled;UINT8 devices;
	f+=check(cdk2_sata_geometry(1,1,0,0,&g)==EFI_SUCCESS&&g.channels==2&&g.devices==2,"IDE geometry");
	f+=check(cdk2_sata_geometry(1,6,3,0xf,&g)==EFI_SUCCESS&&g.channels==4&&g.devices==1,"AHCI geometry");
	f+=check(cdk2_sata_geometry(1,6,0,0x10,&g)==EFI_SUCCESS&&g.channels==5,"sparse PI highest port");
	f+=check(cdk2_sata_geometry(1,6,0,0,&g)==EFI_DEVICE_ERROR,"empty PI rejected");
	f+=check(cdk2_sata_best_pio(&id,NULL,&s)==EFI_SUCCESS&&s==4,"best PIO4");
	f+=check(cdk2_sata_best_pio(&id,&d,&s)==EFI_SUCCESS&&s==1,"PIO disqualification");
	f+=check(cdk2_sata_calculate_mode(&id,&bad,&mode)==EFI_SUCCESS&&mode.pio_mode==3&&mode.udma_mode==4&&mode.udma_valid,"collective mode");
	id.field_validity=2;f+=check(cdk2_sata_calculate_mode(&id,NULL,&mode)==EFI_SUCCESS&&!mode.udma_valid,"UDMA optional");
	f+=check(cdk2_sata_controller_init(&ctl,&g)==EFI_SUCCESS&&cdk2_sata_get_channel(&ctl,3,&enabled,&devices)==EFI_SUCCESS&&enabled&&devices==1,"channel ABI");
	f+=check(cdk2_sata_mode(&ctl,0,0,&mode)==EFI_NOT_READY,"identify required");
	id.field_validity=6;f+=check(cdk2_sata_submit(&ctl,0,0,&id)==EFI_SUCCESS&&cdk2_sata_disqualify(&ctl,0,0,&bad)==EFI_SUCCESS&&cdk2_sata_mode(&ctl,0,0,&mode)==EFI_SUCCESS&&mode.pio_mode==3,"submit disqualify calculate lifecycle");
	f+=check(cdk2_sata_submit(&ctl,32,0,&id)==EFI_INVALID_PARAMETER,"channel bounds");
	return f!=0;}
