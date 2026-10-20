# SPDX-License-Identifier: GPL-2.0

CFLAGS += -O3 -Wl,-no-as-needed -Wall $(KHDR_INCLUDES) -static

# Build a debuggable binary (symbols + no optimization) with `make DEBUG=1`.
# The -g -O0 flags come after -O3 above and therefore override it.
ifdef DEBUG
CFLAGS += -g -O0
endif

TEST_GEN_PROGS := tdx_guest_test tdx_seal

include ../lib.mk
