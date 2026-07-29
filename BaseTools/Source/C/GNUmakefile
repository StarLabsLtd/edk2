## @file
#  GNU/Linux makefile for C tools build.
#
#  Copyright (c) 2007 - 2025, Intel Corporation. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

ifeq (Windows, $(findstring Windows,$(OS)))
  SHELL := cmd.exe
  MAKEROOT := $(shell echo %CD%)
else
  MAKEROOT := .
endif

include Makefiles/header.makefile

export PYTHON_COMMAND
export HOST_ARCH

all: makerootdir subdirs
	@echo Finished building BaseTools C Tools with HOST_ARCH=$(HOST_ARCH)

LIBRARIES = Common
APPLICATIONS = \
  BrotliCompress \
  VfrCompile \
  EfiRom \
  GenFfs \
  GenFv \
  GenFw \
  GenSec \
  GenCrc32 \
  LzmaCompress \
  TianoCompress \
  VolInfo \
  DevicePath

CDK2_APPLICATIONS ?= $(APPLICATIONS)
ifneq ($(strip $(CDK2_TOOLS)),)
  CDK2_APPLICATIONS := $(CDK2_TOOLS)
endif

SUBDIRS := $(LIBRARIES) $(CDK2_APPLICATIONS)

$(LIBRARIES): $(CDK2_LIB_DIR)
$(CDK2_APPLICATIONS): $(LIBRARIES) $(CDK2_BIN_DIR)

.PHONY: outputdirs
makerootdir:
	-$(MD) $(CDK2_OUTPUT_ROOT)
	-$(MD) $(CDK2_LIB_DIR)
	-$(MD) $(CDK2_BIN_DIR)

.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@

.PHONY: $(patsubst %,%-clean,$(sort $(SUBDIRS)))
$(patsubst %,%-clean,$(sort $(SUBDIRS))):
	-$(MAKE) -C $(@:-clean=) clean

clean:  $(patsubst %,%-clean,$(sort $(SUBDIRS)))

clean: localClean

localClean:
	$(RM) $(CDK2_BIN_DIR)/*
	-$(RD) $(CDK2_LIB_DIR) $(CDK2_BIN_DIR)

include Makefiles/footer.makefile
