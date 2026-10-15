# tinymatter host build: unit tests, sanitizers and the seam check.
#
# CC and NM are honoured. On a machine whose default cc or nm is not the tool
# you want, pass both:
#   make test CC=/usr/bin/clang NM="xcrun nm"

NM ?= nm
# Byte order for every sort and comm below, whatever the caller's locale.
export LC_ALL := C
BUILD := build/host

CSTD := -std=c11 -O1
# Zephyr's clang warning_base (zephyr/cmake/compiler/clang/compiler_flags.cmake),
# which is what the source's firmware build compiles these files under, plus
# -Werror.
WARN := -Wall -Wformat -Wformat-security -Wno-format-zero-length \
	-Wno-unused-but-set-variable -Wno-typedef-redefinition \
	-Wno-deprecated-non-prototype -Wdouble-promotion -Wno-pointer-sign \
	-Wpointer-arith -Werror
# Shapes clang merely warns about and GCC rejects outright, promoted so a clang
# run fails where a GCC one would. Probed, because GCC errors on an unknown
# -Werror= name and already treats these as errors.
GCC_PARITY := $(shell $(CC) -Werror=duplicate-decl-specifier -x c -fsyntax-only /dev/null 2>/dev/null && echo -Werror=duplicate-decl-specifier)
SAN := -g -fsanitize=address,undefined -fno-sanitize-recover=all

INCS := -Iinclude
CORE_SRCS := $(wildcard src/*.c)
HDRS := $(wildcard include/tinymatter/*.h tests/host/*.h tests/host/*/*.h)

# The host suite turns every optional surface on, as the source's host build
# did: these tests exist to pin down the encoding of those surfaces, and the
# alternative is a feature whose only proof is on a board.
# _DEFAULT_SOURCE: glibc hides clock_gettime/CLOCK_MONOTONIC under strict
# -std=c11 without it; Darwin headers ignore it.
TEST_DEFS := -D_DEFAULT_SOURCE -DMATTER_FEATURE_DL_ALARMS=1 -DMATTER_FEATURE_CLIENT=1 \
	-DMATTER_FEATURE_MULTI_ADMIN=1 -DTINYMATTER_VENDOR_CLUSTERS=1
TEST_INCS := $(INCS) -Itests/host

# The SPAKE2+ curve under the host suite.
#   SPAKE=mbedtls (default): backends/mbedtls on an installed Mbed TLS 3.6,
#     linked under spakefake_real_* behind spakefake's pass-through, so the
#     recorded exchange still checks every call and the curve is real.
#   SPAKE=fake: spakefake replays the one recorded exchange. No library.
# MBEDTLS_PREFIX is where Mbed TLS 3.6 is installed: include/ and lib/.
SPAKE ?= mbedtls
MBEDTLS_PREFIX ?= $(shell brew --prefix mbedtls@3 2>/dev/null || echo /usr)
SPAKE_RENAME := $(foreach f,reduce check_key get_key_share get_ZV,-Docrypto_spake2p_p256_$(f)=spakefake_real_$(f))
ifeq ($(SPAKE),fake)
TEST_SRCS := $(filter-out tests/host/test_spake2p_mbedtls.c,$(wildcard tests/host/*.c)) tests/host/spakefake/spakefake.c
SPAKE_DEFS :=
SPAKE_LIBS :=
else
TEST_SRCS := $(wildcard tests/host/*.c) tests/host/spakefake/spakefake.c
SPAKE_DEFS := -DSPAKEFAKE_PASSTHROUGH
SPAKE_LIBS := -L$(MBEDTLS_PREFIX)/lib -lmbedcrypto
endif

# Mach-O prefixes every C symbol with an underscore; ELF does not.
SYM_PREFIX := $(if $(filter Darwin,$(shell uname -s)),_,)

.PHONY: test asan seams fuzz fuzz-build clean

SPAKE_SRC := backends/mbedtls/tm_spake2p_mbedtls.c
SPAKE_CFLAGS := $(CSTD) $(WARN) $(GCC_PARITY) $(SPAKE_RENAME) $(INCS) -I$(MBEDTLS_PREFIX)/include

$(BUILD)/spake_mbedtls.o: $(SPAKE_SRC) $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(SPAKE_CFLAGS) -c $< -o $@

$(BUILD)/spake_mbedtls_asan.o: $(SPAKE_SRC) $(HDRS)
	@mkdir -p $(@D)
	$(CC) $(SPAKE_CFLAGS) $(SAN) -c $< -o $@

SPAKE_OBJ := $(if $(filter fake,$(SPAKE)),,$(BUILD)/spake_mbedtls.o)
SPAKE_OBJ_ASAN := $(if $(filter fake,$(SPAKE)),,$(BUILD)/spake_mbedtls_asan.o)

$(BUILD)/host_test_$(SPAKE): $(CORE_SRCS) $(TEST_SRCS) $(HDRS) $(SPAKE_OBJ)
	@mkdir -p $(@D)
	$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(TEST_DEFS) $(SPAKE_DEFS) $(TEST_INCS) $(CORE_SRCS) $(TEST_SRCS) $(SPAKE_OBJ) $(SPAKE_LIBS) -o $@

$(BUILD)/host_test_$(SPAKE)_asan: $(CORE_SRCS) $(TEST_SRCS) $(HDRS) $(SPAKE_OBJ_ASAN)
	@mkdir -p $(@D)
	$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(SAN) $(TEST_DEFS) $(SPAKE_DEFS) $(TEST_INCS) $(CORE_SRCS) $(TEST_SRCS) $(SPAKE_OBJ_ASAN) $(SPAKE_LIBS) -o $@

test: $(BUILD)/host_test_$(SPAKE)
	$(BUILD)/host_test_$(SPAKE)

asan: $(BUILD)/host_test_$(SPAKE)_asan
	$(BUILD)/host_test_$(SPAKE)_asan

# The symbols the core leaves for a backend or a port to provide: everything a
# matter_*.c object references that none of them defines. tm_hash.c is left
# out on purpose, so the hash shows up as the seam it is. libc is printed but
# is not a seam: which libc names appear is the compiler's choice (bzero for a
# zeroing memset, __stack_chk_* for the stack protector). The rest must match
# tests/seams.expected, which PORTING.md's seam table describes.
SEAM_SRCS := $(wildcard src/matter_*.c)
LIBC_RE := ^_*((mem[a-z]*|str[a-z]*|bzero|snprintf)(_chk)?|stack_chk_(fail|guard))$$

seams:
	@mkdir -p $(BUILD)/seams
	@for f in $(SEAM_SRCS); do \
		$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(INCS) -c $$f -o $(BUILD)/seams/$$(basename $$f .c).o || exit 1; \
	done
	@objs="$(patsubst src/%.c,$(BUILD)/seams/%.o,$(SEAM_SRCS))"; \
	if [ -n "$$objs" ]; then \
		$(NM) -A -u $$objs | awk '{ print $$NF }' | sed 's/^$(SYM_PREFIX)//' | sort -u > $(BUILD)/seams/undef.txt; \
		$(NM) -A -g --defined-only $$objs | awk '{ print $$NF }' | sed 's/^$(SYM_PREFIX)//' | sort -u > $(BUILD)/seams/def.txt; \
	else : > $(BUILD)/seams/undef.txt; : > $(BUILD)/seams/def.txt; fi; \
	comm -23 $(BUILD)/seams/undef.txt $(BUILD)/seams/def.txt > $(BUILD)/seams/all.txt; \
	grep -E -v '$(LIBC_RE)' $(BUILD)/seams/all.txt > $(BUILD)/seams/seams.txt || true; \
	cat $(BUILD)/seams/seams.txt; \
	echo "libc, not a seam: $$(grep -E '$(LIBC_RE)' $(BUILD)/seams/all.txt | tr '\n' ' ')"; \
	diff -u tests/seams.expected $(BUILD)/seams/seams.txt && \
	echo "make seams: $$(wc -l < $(BUILD)/seams/seams.txt | tr -d ' ') symbols, matches tests/seams.expected"

# libFuzzer targets in tests/host/fuzz. Apple clang ships no libFuzzer, so the
# default compiler is Homebrew LLVM's. FUZZ_LDFLAGS is for a machine whose
# default linker is not the platform one, e.g. FUZZ_LDFLAGS="--ld-path=<ld>".
# make fuzz runs each target for FUZZ_TIME seconds from its seeds, keeping the
# corpus and any crash under build/fuzz.
FUZZ_CC ?= $(shell brew --prefix llvm 2>/dev/null)/bin/clang
FUZZ_LDFLAGS ?=
FUZZ_TIME ?= 600
FUZZ_TARGETS := tlv msg btp im pase_case
FUZZ_BINS := $(addprefix build/fuzz/fuzz_,$(FUZZ_TARGETS))
# The host stubs stand in for the crypto and Thread seams, so every target
# links the whole core and only exercises the parser it names.
FUZZ_SUPPORT := tests/host/test_matter_attest_stub.c tests/host/test_matter_case_stub.c \
	tests/host/test_matter_thread_stub.c tests/host/aes_ref.c tests/host/spakefake/spakefake.c

build/fuzz/fuzz_%: tests/host/fuzz/fuzz_%.c $(CORE_SRCS) $(FUZZ_SUPPORT) $(HDRS)
	@mkdir -p $(@D)
	$(FUZZ_CC) -std=c11 -g -O1 $(WARN) -fsanitize=fuzzer,address,undefined $(TEST_DEFS) $(TEST_INCS) \
		$(FUZZ_LDFLAGS) $< $(CORE_SRCS) $(FUZZ_SUPPORT) -o $@

fuzz-build: $(FUZZ_BINS)

fuzz: $(FUZZ_BINS)
	@for t in $(FUZZ_TARGETS); do \
		mkdir -p build/fuzz/corpus/$$t build/fuzz/crash/$$t && \
		build/fuzz/fuzz_$$t -max_total_time=$(FUZZ_TIME) -print_final_stats=1 \
			-artifact_prefix=build/fuzz/crash/$$t/ build/fuzz/corpus/$$t \
			tests/host/fuzz/seeds/$$t || exit 1; \
	done

clean:
	rm -rf build
