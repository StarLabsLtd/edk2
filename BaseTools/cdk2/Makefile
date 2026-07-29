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
CDK2_PYTHON_STAGE_ROOT ?= $(CDK2_BUILD_DIR)/Python
CDK2_PYTHON_SOURCE_ROOT := $(CDK2_PYTHON_STAGE_ROOT)/Source/Python
CDK2_PYTHON_WRAPPER_ROOT := $(CDK2_PYTHON_STAGE_ROOT)/BinWrappers/PosixLike
CDK2_REJECT_WRAPPER_ROOT := $(CDK2_PYTHON_STAGE_ROOT)/BinWrappers/cdk2-denied

# These packages form the Python closure of the cdk2 build/autogen/FDF path.
# Keep this staged tree separate from the shared EDK II source tree so optional
# BaseTools commands are not silently pulled into cdk2 builds.
CDK2_PYTHON_PACKAGES := \
	AutoGen \
	Capsule \
	Common \
	Common/Edk2 \
	Common/Edk2/Capsule \
	CommonDataClass \
	GenFds \
	GenPatchPcdTable \
	PatchPcdValue \
	Trim \
	Common/Uefi \
	Common/Uefi/Capsule \
	Workspace \
	build
CDK2_PYTHON_WRAPPERS := \
	build \
	GenerateCapsule \
	GenDepex \
	GenFds \
	GenPatchPcdTable \
	PatchPcdValue \
	Trim

# This is the closure observed from the current cdk2 descriptor and build
# rules. The remaining C tools are for other EDK II platforms or workflows.
CDK2_TOOLS ?= \
	GenFfs \
	GenFv \
	GenFw \
	GenSec \
	VfrCompile
CDK2_SOURCE_WRAPPERS := $(sort $(notdir $(wildcard $(CDK2_BASETOOLS_DIR)/BinWrappers/PosixLike/*)))
CDK2_ALLOWED_WRAPPERS := $(CDK2_PYTHON_WRAPPERS) $(CDK2_TOOLS)
CDK2_REJECT_WRAPPERS := $(filter-out $(CDK2_ALLOWED_WRAPPERS) posix_path_env.yaml,$(CDK2_SOURCE_WRAPPERS))

.PHONY: all build check python-stage python-check path-check clean print

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

python-stage:
	@mkdir -p "$(CDK2_PYTHON_SOURCE_ROOT)" "$(CDK2_PYTHON_WRAPPER_ROOT)" "$(CDK2_REJECT_WRAPPER_ROOT)"
	@install -m 0644 "$(CDK2_BASETOOLS_DIR)/Source/Python/sitecustomize.py" "$(CDK2_PYTHON_SOURCE_ROOT)/sitecustomize.py"
	@set -e; for package in $(CDK2_PYTHON_PACKAGES); do \
		mkdir -p "$(CDK2_PYTHON_SOURCE_ROOT)/$$package"; \
		find "$(CDK2_BASETOOLS_DIR)/Source/Python/$$package" -maxdepth 1 -type f -exec install -m 0644 {} "$(CDK2_PYTHON_SOURCE_ROOT)/$$package/" \;; \
	done
	@set -e; for wrapper in $(CDK2_PYTHON_WRAPPERS); do \
		install -m 0755 "$(CDK2_BASETOOLS_DIR)/BinWrappers/PosixLike/$$wrapper" "$(CDK2_PYTHON_WRAPPER_ROOT)/$$wrapper"; \
	done
	@find "$(CDK2_REJECT_WRAPPER_ROOT)" -mindepth 1 -maxdepth 1 -type f -delete
	@set -e; for wrapper in $(CDK2_REJECT_WRAPPERS); do \
		{ \
			printf '%s\n' '#!/usr/bin/env bash'; \
			printf '%s\n' 'tool=$$(basename "$$0")'; \
			printf '%s\n' 'echo "cdk2 BaseTools closure rejects unstaged BaseTools command: $$tool" >&2'; \
			printf '%s\n' 'exit 127'; \
		} > "$(CDK2_REJECT_WRAPPER_ROOT)/$$wrapper"; \
		chmod 0755 "$(CDK2_REJECT_WRAPPER_ROOT)/$$wrapper"; \
	done

python-check: python-stage
	@set -e; for wrapper in $(CDK2_PYTHON_WRAPPERS); do \
		test -x "$(CDK2_PYTHON_WRAPPER_ROOT)/$$wrapper" || { \
			echo "missing cdk2 BaseTools Python wrapper: $$wrapper" >&2; exit 1; \
		}; \
	done
	@PYTHONPATH="$(CDK2_PYTHON_SOURCE_ROOT):$(CDK2_PYTHON_SOURCE_ROOT)/build" python3 -c \
		"from AutoGen import AutoGen, GenMake; from Common import Misc, EdkLogger; from CommonDataClass import FdfClass; from GenFds import GenFds; from GenPatchPcdTable import GenPatchPcdTable; from PatchPcdValue import PatchPcdValue; from Trim import Trim; from Workspace import WorkspaceDatabase; import buildoptions"
	@WORKSPACE="$(CDK2_BASETOOLS_DIR)/../.." EDK_TOOLS_PATH="$(CDK2_BASETOOLS_DIR)" \
		PATH="$(CDK2_PYTHON_WRAPPER_ROOT):$(CDK2_OUTPUT_ROOT)/bin:$$PATH" \
		"$(CDK2_PYTHON_WRAPPER_ROOT)/build" --help >/dev/null
	@printf '%s\n' "cdk2 BaseTools Python closure: $(words $(CDK2_PYTHON_PACKAGES)) packages, $(words $(CDK2_PYTHON_WRAPPERS)) wrappers"
	@printf '%s\n' "cdk2 BaseTools Python output: $(CDK2_PYTHON_STAGE_ROOT)"

path-check: check python-check
	@PATH="$(CDK2_OUTPUT_ROOT)/bin:$(CDK2_PYTHON_WRAPPER_ROOT):$(CDK2_REJECT_WRAPPER_ROOT):$$PATH"; export PATH; \
	set -e; for tool in $(CDK2_TOOLS); do \
		actual=$$(command -v "$$tool") || { echo "missing cdk2 BaseTools executable on PATH: $$tool" >&2; exit 1; }; \
		expected="$(CDK2_OUTPUT_ROOT)/bin/$$tool"; \
		test "$$actual" = "$$expected" || { echo "wrong cdk2 BaseTools executable for $$tool: $$actual" >&2; exit 1; }; \
	done; \
	for wrapper in $(CDK2_PYTHON_WRAPPERS); do \
		actual=$$(command -v "$$wrapper") || { echo "missing cdk2 BaseTools Python wrapper on PATH: $$wrapper" >&2; exit 1; }; \
		expected="$(CDK2_PYTHON_WRAPPER_ROOT)/$$wrapper"; \
		test "$$actual" = "$$expected" || { echo "wrong cdk2 BaseTools Python wrapper for $$wrapper: $$actual" >&2; exit 1; }; \
	done; \
	denied=$$(printf '%s\n' $(CDK2_REJECT_WRAPPERS) | sed -n '1p'); \
	test -n "$$denied"; \
	actual=$$(command -v "$$denied") || { echo "missing cdk2 BaseTools deny wrapper on PATH: $$denied" >&2; exit 1; }; \
	expected="$(CDK2_REJECT_WRAPPER_ROOT)/$$denied"; \
	test "$$actual" = "$$expected" || { echo "wrong cdk2 BaseTools deny wrapper for $$denied: $$actual" >&2; exit 1; }; \
	if "$(CDK2_REJECT_WRAPPER_ROOT)/$$denied" >/dev/null 2>&1; then \
		echo "cdk2 BaseTools deny wrapper unexpectedly allowed $$denied" >&2; exit 1; \
	else \
		status=$$?; test "$$status" -eq 127 || { echo "cdk2 BaseTools deny wrapper returned $$status for $$denied" >&2; exit 1; }; \
	fi
	@printf '%s\n' "cdk2 BaseTools path guard: $(words $(CDK2_REJECT_WRAPPERS)) unstaged wrappers blocked"

print:
	@printf '%s\n' "cdk2 BaseTools C tools: $(CDK2_TOOLS)"
	@printf '%s\n' "cdk2 BaseTools output: $(CDK2_OUTPUT_ROOT)/bin"

clean:
	$(MAKE) -C "$(CDK2_SOURCE_DIR)" \
		CDK2_TOOLS="$(CDK2_TOOLS)" \
		CDK2_OUTPUT_ROOT="$(CDK2_OUTPUT_ROOT)" \
		HOST_ARCH="$(CDK2_HOST_ARCH)" clean
