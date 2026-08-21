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

# Verifier-only modules (src/verifier/), kept out of $(OBJECTS) for the same
# reason as RP_OBJECTS above.
VERIFIER_OBJECTS = $(addsuffix .o, $(addprefix $(OBJDIR)/verifier/, verifier_util verifier_nonce verifier_qualified_rps verifier_qualify verifier_appraise))

# Attester-only modules (src/attester/), kept out of $(OBJECTS) for the same
# reason as RP_OBJECTS above.
ATTESTER_OBJECTS = $(addsuffix .o, $(addprefix $(OBJDIR)/attester/, attester_util attester_ima_log attester_result attester_attest))

TARGETS = $(addprefix $(BINDIR)/, attester verifier verifier_old relying_party trust_manager provision_trusted_keys)

.PHONY: all attester verifier verifier_old relying_party trust_manager \
        provision_trusted_keys \
        test test_event_log test_synthetic_log test_sdk test_rp_qualification \
        test_marshaling_bounds test_trusted_keys test_qualified_rps \
        test_get_verifiers_marshaling \
        test_rp_evidence_marshaling test_verdict \
        clean

all: $(TARGETS)
attester: $(BINDIR)/attester
verifier: $(BINDIR)/verifier
verifier_server: $(BINDIR)/verifier_old
relying_party: $(BINDIR)/relying_party
trust_manager: $(BINDIR)/trust_manager
provision_trusted_keys: $(BINDIR)/provision_trusted_keys
test_event_log: $(BINDIR)/test_event_log
test_synthetic_log: $(BINDIR)/test_synthetic_log
test_sdk: $(BINDIR)/test_sdk
test_rp_qualification: $(BINDIR)/test_rp_qualification
test_marshaling_bounds: $(BINDIR)/test_marshaling_bounds
test_trusted_keys: $(BINDIR)/test_trusted_keys
test_qualified_rps: $(BINDIR)/test_qualified_rps
test_rp_evidence_marshaling: $(BINDIR)/test_rp_evidence_marshaling
test_get_verifiers_marshaling: $(BINDIR)/test_get_verifiers_marshaling
test_verdict: $(BINDIR)/test_verdict

## run the test suite
test: $(BINDIR)/test_event_log $(BINDIR)/test_synthetic_log $(BINDIR)/test_sdk $(BINDIR)/test_rp_qualification $(BINDIR)/test_marshaling_bounds $(BINDIR)/test_trusted_keys $(BINDIR)/test_qualified_rps $(BINDIR)/test_get_verifiers_marshaling $(BINDIR)/test_rp_evidence_marshaling $(BINDIR)/test_verdict
	./$(BINDIR)/test_event_log
	./$(BINDIR)/test_synthetic_log
	./$(BINDIR)/test_sdk
	./$(BINDIR)/test_rp_qualification
	./$(BINDIR)/test_marshaling_bounds
	./$(BINDIR)/test_trusted_keys
	./$(BINDIR)/test_qualified_rps
	./$(BINDIR)/test_get_verifiers_marshaling
	./$(BINDIR)/test_rp_evidence_marshaling
	./$(BINDIR)/test_verdict


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

$(BINDIR)/test_event_log: tests/test_event_log.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_synthetic_log: tests/test_synthetic_log.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_sdk: tests/test_sdk.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_rp_qualification: tests/test_rp_qualification.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_marshaling_bounds: tests/test_marshaling_bounds.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_trusted_keys: tests/test_trusted_keys.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_qualified_rps: tests/test_qualified_rps.c $(VERIFIER_OBJECTS) $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_rp_evidence_marshaling: tests/test_rp_evidence_marshaling.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_get_verifiers_marshaling: tests/test_get_verifiers_marshaling.c $(OBJECTS)
	@mkdir -p $(@D)
	$(CC) $^ $(CFLAGS) $(INCLUDE) $(LIBINCLUDE) $(LDPATH) $(LDFLAGS) -g -o $@ $(link_mode)

$(BINDIR)/test_verdict: tests/test_verdict.c $(OBJECTS)
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
