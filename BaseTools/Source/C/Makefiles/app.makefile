## @file
# Makefiles
#
# Copyright (c) 2007 - 2025, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

MAKEROOT ?= ../..

include $(MAKEROOT)/Makefiles/header.makefile

APPLICATION = $(CDK2_BIN_DIR)/$(APPNAME)

.PHONY:all
all: $(CDK2_BIN_DIR) $(APPLICATION)

$(APPLICATION): $(OBJECTS)
	$(LINKER) -o $(APPLICATION) $(LDFLAGS) $(OBJECTS) -L$(CDK2_LIB_DIR) $(LIBS)
ifeq (Windows, $(findstring Windows,$(OS)))
	$(CP) $(APPLICATION).exe $(BIN_PATH)
endif

$(OBJECTS): $(MAKEROOT)/Include/Common/BuildVersion.h

clean: appClean

appClean:
ifeq (Windows, $(findstring Windows,$(OS)))
	$(RM) $(BIN_PATH)/$(APPNAME).exe
endif

include $(MAKEROOT)/Makefiles/footer.makefile
