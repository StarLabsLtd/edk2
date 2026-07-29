## @file
# Makefiles
#
# Copyright (c) 2007 - 2014, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

include $(MAKEROOT)/Makefiles/header.makefile

LIBRARY = $(CDK2_LIB_DIR)/lib$(LIBNAME).a

all: $(CDK2_LIB_DIR) $(LIBRARY)

include $(MAKEROOT)/Makefiles/footer.makefile
