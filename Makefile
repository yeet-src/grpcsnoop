.DEFAULT_GOAL := all

# Resolve clang, bpftool and the libbpf headers from yeet's vendored toolchain
# cache (fetched on demand by the `toolchain` target) — no system BPF toolchain
# needed. A `make CLANG=…` / `BPFTOOL=…` override still wins.
include build/toolchain.mk

# PATH fallbacks, used only when toolchain.mk resolved nothing (off-Linux).
CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
# Python used for `make schema`. Defaults to python3, but the target falls back
# to the testservice poetry venv (which has grpcio-tools) if python3 lacks it.
PYTHON  ?= python3

# Prefer the vendored libbpf headers; fall back to system libbpf-dev on PATH.
LIBBPF_INCLUDE ?= $(if $(BPF_SYSINCLUDE),$(BPF_SYSINCLUDE),/usr/include)

CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I$(LIBBPF_INCLUDE)

.PHONY: all clean schema

all: grpcsnoop.bpf.o

# Generate schema.js from a .proto for named-field decoding:
#   make schema PROTO=demo/test.proto
schema:
	@test -n "$(PROTO)" || { echo "usage: make schema PROTO=path/to/file.proto"; exit 1; }
	@py="$(PYTHON)"; \
	if ! $$py -c 'import grpc_tools' 2>/dev/null; then \
	  py="$$(cd testservice && poetry env info -p 2>/dev/null)/bin/python"; \
	fi; \
	if ! $$py -c 'import grpc_tools' 2>/dev/null; then \
	  echo "no python with grpcio-tools found. Run: (cd testservice && poetry install)"; exit 1; \
	fi; \
	tmp=$$(mktemp) && $$py tools/gen-schema.py "$(PROTO)" > $$tmp \
	  && mv $$tmp schema.js && echo "wrote schema.js from $(PROTO) (via $$py)" \
	  || { rm -f $$tmp; echo "schema generation failed; schema.js unchanged"; exit 1; }

vmlinux.h: | toolchain
	sh build/gen-vmlinux.sh $(BPFTOOL) $@

grpcsnoop.bpf.o: grpcsnoop.bpf.c vmlinux.h | toolchain
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f grpcsnoop.bpf.o
