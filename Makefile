CLANG   ?= clang
# `bpftool btf dump` reads /sys/kernel/btf/vmlinux, which is root-only on some
# hardened kernels — default to sudo for portability. Override with BPFTOOL=bpftool.
BPFTOOL ?= sudo bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
# Python used for `make schema`. Defaults to python3, but the target falls back
# to the testservice poetry venv (which has grpcio-tools) if python3 lacks it.
PYTHON  ?= python3

CFLAGS  := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

.PHONY: all clean schema

all: grpcsnoop.bpf.o

# Generate schema.js from a .proto for named-field decoding:
#   make schema PROTO=demo/test.proto
# Writes atomically (a failed run never clobbers schema.js) and falls back to
# the testservice venv if $(PYTHON) doesn't have grpcio-tools.
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

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

grpcsnoop.bpf.o: grpcsnoop.bpf.c vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f grpcsnoop.bpf.o
