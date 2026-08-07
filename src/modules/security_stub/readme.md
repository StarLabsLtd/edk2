<!-- SPDX-License-Identifier: BSD-2-Clause-Patent -->

# Native SecurityStubDxe

This module is derived from the SecurityStubDxe implementation at cdk2 commit
`e803a856f1^`. The original Intel copyright and BSD-2-Clause-Patent license are
retained in the source.

It installs the UEFI Security and Security2 architectural protocols. With no
image-policy handlers linked, both callbacks preserve the original
empty-handler behavior and return success. Verification or measurement policy
must be supplied by an explicit CDK2 security module rather than hidden package
metadata resolution.
