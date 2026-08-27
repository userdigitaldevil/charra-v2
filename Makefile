################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Main Makefile for CHARRA.                                                    #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Date Modified: 2023-05-22T13:37:42+02:00                                     #
# Date Created:  2019-06-26T09:23:15+02:00                                     #
################################################################################

# ------------------------------------------------------------------------------
# --- arguments + variables ----------------------------------------------------
# ------------------------------------------------------------------------------

## TCTI module
## (typically, TCTI implementations are stored at /usr/local/lib/libtss2-*.so*)
TCTI_MODULE ?= tcti-mssim
tcti_module := tss2-$(TCTI_MODULE)

## logging
enable_logging := 1
flags_logging :=
ifeq ($(ENABLE_LOGGING),0)
	enable_logging := 0
	flags_logging := -DCHARRA_LOG_DISABLE
endif

## colored logging
enable_logging_color := 1
flags_logging_color :=
ifeq ($(ENABLE_LOGGING_COLOR),0)
	enable_logging_color := 0
	flags_logging_color := -DCHARRA_LOG_DISABLE_COLOR
endif

## AddressSanitizer (ASan)
enable_address_sanitizer := 0
flags_address_sanitizer :=
ifeq ($(ENABLE_ADDRESS_SANITIZER),)
	enable_address_sanitizer := 0
	flags_address_sanitizer :=
else ifneq ($(ENABLE_ADDRESS_SANITIZER),0)
	enable_address_sanitizer := 1
	flags_address_sanitizer := -fsanitize=address
endif

## LeakSanitizer (LSan)
enable_leak_sanitizer := 0
flags_leak_sanitizer :=
ifeq ($(ENABLE_LEAK_SANITIZER),)
	enable_leak_sanitizer := 0
	flags_leak_sanitizer :=
else ifneq ($(ENABLE_LEAK_SANITIZER),0)
	enable_leak_sanitizer := 1
	flags_leak_sanitizer := -fsanitize=leak
endif

## position-independent code (PIC)
enable_pic := 1
flags_pic := -fPIC
ifeq ($(ENABLE_PIC),0)
	enable_pic := 0
	flags_pic :=
endif

## strip unneeded
enable_stripping := 1
ifeq ($(ENABLE_STRIPPING),0)
	enable_stripping := 0
endif

## link mode
LINK_MODE ?= dynamic
link_mode := $(if $(filter static,$(LINK_MODE)), -static)

# ------------------------------------------------------------------------------
# --- directories --------------------------------------------------------------
# ------------------------------------------------------------------------------

SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin

# ------------------------------------------------------------------------------
# --- arguments + flags --------------------------------------------------------
# ------------------------------------------------------------------------------

# -MMD -MP emits a .d file beside each object listing the headers it used,
# pulled in at the bottom of this file. Without it nothing recompiles when a
# header changes -- editing a shared header left stale objects linking against
# symbols that no longer existed.
CFLAGS =     -std=gnu99 -g -pedantic -Wall -Wextra -Wimplicit-fallthrough \
             -MMD -MP \
             -Wno-missing-field-initializers -Wl,--gc-sections \
             -fdata-sections -ffunction-sections -lpthread \
             $(flags_pic) \
             $(flags_address_sanitizer) \
             $(flags_leak_sanitizer) \
             $(flags_logging) \
             $(flags_logging_color)

LIBINCLUDE = -I/usr/include \
             -I/usr/local/include

LDPATH =     -L/usr/local/lib/ \
             -L/usr/lib/x86_64-linux-gnu

LIBS =       coap-3-tinydtls \
             qcbor m \
             crypto ssl \
             mbedx509 mbedcrypto \
             util \
             tss2-esys tss2-sys tss2-mu tss2-tctildr \
             $(tcti_module)

LDFLAGS =    $(addprefix -l, $(LIBS))

# ------------------------------------------------------------------------------
# --- sources + targets --------------------------------------------------------
# ------------------------------------------------------------------------------

SOURCES = $(shell find $(SRCDIR) -name '*.c')

INCLUDE = -I$(INCDIR)

OBJECTS =  $(addsuffix .o, $(addprefix $(OBJDIR)/common/, charra_log))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/core/, charra_helper charra_key_mgr charra_rim_mgr charra_marshaling charra_event_log charra_synthetic_log charra_sdk charra_rp_qualification charra_trusted_keys charra_verdict))
OBJECTS += $(addsuffix .o, $(addprefix $(OBJDIR)/util/, cbor_util charra_util coap_util crypto_util hex_util io_util tpm2_util cli_util parser_util))

# Relying-Party-only modules (src/rp/). Kept out of $(OBJECTS) on purpose:
# that list is linked into every binary, and these carry RP-specific state
# the Attester/Verifier/Trust Manager have no business pulling in.
RP_OBJECTS = $(addsuffix .o, $(addprefix $(OBJDIR)/rp/, rp_stats rp_config rp_coap rp_signing_key rp_qualification rp_evidence rp_attestation))
# src/core/TEE.c lives in core/ but links only here: it holds a process-wide
# keypair and only the RP calls it, so the reasoning above applies to it too.
RP_OBJECTS += $(OBJDIR)/core/TEE.o

# Verifier-only modules (src/verifier/), kept out of $(OBJECTS) for the same
# reason as RP_OBJECTS above.
VERIFIER_OBJECTS = $(addsuffix .o, $(addprefix $(OBJDIR)/verifier/, verifier_util verifier_nonce verifier_qualified_rps verifier_qualify verifier_appraise))

# Attester-only modules (src/attester/), kept out of $(OBJECTS) for the same
# reason as RP_OBJECTS above.
ATTESTER_OBJECTS = $(addsuffix .o, $(addprefix $(OBJDIR)/attester/, attester_util attester_ima_log attester_result attester_attest))

TARGETS = $(addprefix $(BINDIR)/, attester verifier verifier_old relying_party trust_manager provision_trusted_keys)

# Every test suite, named once. The .PHONY list, the per-suite shortcuts,
# and the `test` target below are all derived from this, because keeping
# three hand-written lists in step is exactly the drift that let three
# suites build individually while `make test` silently skipped them.
TEST_SUITES = test_event_log \
              test_synthetic_log \
              test_sdk \
              test_rp_qualification \
              test_marshaling_bounds \
              test_trusted_keys \
              test_qualified_rps \
              test_get_verifiers_marshaling \
              test_rp_evidence_marshaling \
              test_verdict \
              test_hex_util \
              test_pcr_selection \
              test_message_marshaling \
              test_key_mgr \
              test_crypto_util \
              test_parser_util \
              test_tee

.PHONY: all attester verifier verifier_old relying_party trust_manager \
        provision_trusted_keys test $(TEST_SUITES) clean

all: $(TARGETS)
attester: $(BINDIR)/attester
verifier: $(BINDIR)/verifier
verifier_server: $(BINDIR)/verifier_old
relying_party: $(BINDIR)/relying_party
trust_manager: $(BINDIR)/trust_manager
provision_trusted_keys: $(BINDIR)/provision_trusted_keys
# `make test_sdk` builds bin/test_sdk, and so on for each suite.
$(TEST_SUITES): %: $(BINDIR)/%

## run the test suite -- every suite, stopping at the first failure
test: $(addprefix $(BINDIR)/, $(TEST_SUITES))
	@for t in $(TEST_SUITES); do ./$(BINDIR)/$$t || exit 1; done

# ------------------------------------------------------------------------------
# --- productions --------------------------------------------------------------
# ------------------------------------------------------------------------------

## --- apps --------------------------------------------------------------------

$(BINDIR)/attester: $(SRCDIR)/attester.c $(OBJECTS) $(ATTESTER_OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

$(BINDIR)/verifier: $(SRCDIR)/verifier.c $(OBJECTS) $(VERIFIER_OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

$(BINDIR)/verifier_old: $(SRCDIR)/verifier_old.c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

$(BINDIR)/relying_party: $(SRCDIR)/relying_party.c $(OBJECTS) $(RP_OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

$(BINDIR)/trust_manager: $(SRCDIR)/trust_manager.c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

# Offline setup, not a protocol role: reads the TPM's public signing keys
# and writes keys/trusted_keys.txt. See keys/gen-trusted-keys.sh.
$(BINDIR)/provision_trusted_keys: $(SRCDIR)/provision_trusted_keys.c $(OBJECTS)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ -Wl,--gc-sections $(link_mode)
ifeq ($(enable_stripping),1)
	strip --strip-unneeded $@
endif

## --- tests -------------------------------------------------------------------

$(BINDIR)/test_qualified_rps: tests/test_qualified_rps.c $(VERIFIER_OBJECTS) $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

# TEE.o is an RP-only object (see RP_OBJECTS), so it is not in $(OBJECTS)
# and this suite has to name it.
$(BINDIR)/test_tee: tests/test_tee.c $(OBJDIR)/core/TEE.o $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

# One rule for every suite in TEST_SUITES. test_qualified_rps and test_tee
# additionally link objects outside $(OBJECTS), which their own rules supply.
$(BINDIR)/test_%: tests/test_%.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

## --- objects -----------------------------------------------------------------

$(OBJDIR)/common/%.o: $(SRCDIR)/common/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/core/%.o: $(SRCDIR)/core/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/attester/%.o: $(SRCDIR)/attester/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/verifier/%.o: $(SRCDIR)/verifier/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/rp/%.o: $(SRCDIR)/rp/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

$(OBJDIR)/util/%.o: $(SRCDIR)/util/%.c
	@mkdir -p $(@D)
	$(CC) $< $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) $(CFLAGS) -g -o $@ -c $(link_mode)

# ------------------------------------------------------------------------------
# --- clean --------------------------------------------------------------------
# ------------------------------------------------------------------------------

clean:
	$(RM) bin/*
	$(RM) obj/common/*.*
	$(RM) obj/core/*.*
	$(RM) obj/util/*.*
	$(RM) obj/rp/*.*
	$(RM) obj/verifier/*.*
	$(RM) obj/attester/*.*
	$(RM) obj/*.*

# Header dependencies generated by -MMD (see CFLAGS). The dash keeps a clean
# tree quiet: on the first build no .d files exist yet.
-include $(shell find $(OBJDIR) -name '*.d' 2>/dev/null)
