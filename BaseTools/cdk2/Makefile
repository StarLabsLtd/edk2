## SPDX-License-Identifier: BSD-2-Clause-Patent

# Build only the native BaseTools closure needed by the cdk2 EDK II backend.
# Python build/autogen modules remain shared until the cdk2 descriptor is
# converted to direct Make rules.

SHELL := /bin/bash

CDK2_BASETOOLS_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
CDK2_SOURCE_DIR := $(CDK2_BASETOOLS_DIR)/Source/C
CDK2_BUILD_DIR ?= $(CDK2_BASETOOLS_DIR)/../Build/cdk2-basetools
CDK2_OUTPUT_ROOT ?= $(CDK2_BUILD_DIR)/C
CDK2_HOST_ARCH ?= X64

# This is the closure observed from the current cdk2 descriptor and build
# rules. The remaining C tools are for other EDK II platforms or workflows.
CDK2_TOOLS ?= \
	GenFfs \
	GenFv \
	GenFw \
	GenSec \
	VfrCompile

.PHONY: all build check clean print

all: build

build:
	$(MAKE) -C "$(CDK2_SOURCE_DIR)" \
		CDK2_TOOLS="$(CDK2_TOOLS)" \
		CDK2_OUTPUT_ROOT="$(CDK2_OUTPUT_ROOT)" \
		HOST_ARCH="$(CDK2_HOST_ARCH)"

check: build
	@set -e; for tool in $(CDK2_TOOLS); do \
		test -x "$(CDK2_OUTPUT_ROOT)/bin/$$tool" || { \
			echo "missing cdk2 BaseTools executable: $$tool" >&2; exit 1; \
		}; \
	done
	@printf '%s\n' "cdk2 BaseTools C closure: $(words $(CDK2_TOOLS)) tools"
	@printf '%s\n' "cdk2 BaseTools output: $(CDK2_OUTPUT_ROOT)/bin"

print:
	@printf '%s\n' "cdk2 BaseTools C tools: $(CDK2_TOOLS)"
	@printf '%s\n' "cdk2 BaseTools output: $(CDK2_OUTPUT_ROOT)/bin"

clean:
	$(MAKE) -C "$(CDK2_SOURCE_DIR)" \
		CDK2_TOOLS="$(CDK2_TOOLS)" \
		CDK2_OUTPUT_ROOT="$(CDK2_OUTPUT_ROOT)" \
		HOST_ARCH="$(CDK2_HOST_ARCH)" clean
