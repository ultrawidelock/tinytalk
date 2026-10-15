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
WARN := -Wall -Werror
# Shapes clang merely warns about and GCC rejects outright, promoted so a clang
# run fails where a GCC one would. Probed, because GCC errors on an unknown
# -Werror= name and already treats these as errors.
GCC_PARITY := $(shell $(CC) -Werror=duplicate-decl-specifier -x c -fsyntax-only /dev/null 2>/dev/null && echo -Werror=duplicate-decl-specifier)
SAN := -g -fsanitize=address,undefined -fno-sanitize-recover=all

INCS := -Iinclude
CORE_SRCS := $(wildcard src/*.c)
TEST_SRCS := $(wildcard tests/host/*.c)

# Mach-O prefixes every C symbol with an underscore; ELF does not.
SYM_PREFIX := $(if $(filter Darwin,$(shell uname -s)),_,)

.PHONY: test asan seams clean

test:
	@if [ -z "$(strip $(TEST_SRCS))" ]; then echo "make test: no host tests yet"; exit 0; fi; \
	mkdir -p $(BUILD) && \
	$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(INCS) $(CORE_SRCS) $(TEST_SRCS) -o $(BUILD)/host_test && \
	$(BUILD)/host_test

asan:
	@if [ -z "$(strip $(TEST_SRCS))" ]; then echo "make asan: no host tests yet"; exit 0; fi; \
	mkdir -p $(BUILD) && \
	$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(SAN) $(INCS) $(CORE_SRCS) $(TEST_SRCS) -o $(BUILD)/host_test_asan && \
	$(BUILD)/host_test_asan

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

clean:
	rm -rf build
