/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_mouse.h>
struct system_table_view;
EFI_STATUS CDK2_MS_ABI cdk2_usb_mouse_entry(void *, struct system_table_view *);
int main(void)
{ return cdk2_usb_mouse_entry((void *)1, NULL) == EFI_INVALID_PARAMETER ? 0 : 1; }
