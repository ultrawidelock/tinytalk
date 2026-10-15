# tinymatter host build: unit tests, sanitizers and the seam check.
#
# CC and NM are honoured. On a machine whose default cc or nm is not the tool
# you want, pass both:
#   make test CC=/usr/bin/clang NM="xcrun nm"

NM ?= nm
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
# core object references that no core object defines. Must match
# tests/seams.expected, which PORTING.md's seam table describes.
seams:
	@mkdir -p $(BUILD)/seams && rm -f $(BUILD)/seams/*.o
	@for f in $(CORE_SRCS); do \
		$(CC) $(CSTD) $(WARN) $(GCC_PARITY) $(INCS) -c $$f -o $(BUILD)/seams/$$(basename $$f .c).o || exit 1; \
	done
	@objs="$(patsubst src/%.c,$(BUILD)/seams/%.o,$(CORE_SRCS))"; \
	if [ -n "$$objs" ]; then \
		$(NM) -A -u $$objs | awk '{ print $$NF }' | sed 's/^$(SYM_PREFIX)//' | sort -u > $(BUILD)/seams/undef.txt; \
		$(NM) -A -g --defined-only $$objs | awk '{ print $$NF }' | sed 's/^$(SYM_PREFIX)//' | sort -u > $(BUILD)/seams/def.txt; \
	else : > $(BUILD)/seams/undef.txt; : > $(BUILD)/seams/def.txt; fi; \
	comm -23 $(BUILD)/seams/undef.txt $(BUILD)/seams/def.txt > $(BUILD)/seams/seams.txt; \
	cat $(BUILD)/seams/seams.txt; \
	diff -u tests/seams.expected $(BUILD)/seams/seams.txt && \
	echo "make seams: $$(wc -l < $(BUILD)/seams/seams.txt | tr -d ' ') symbols, matches tests/seams.expected"

clean:
	rm -rf build
