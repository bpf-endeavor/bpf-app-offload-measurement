CC = gcc
CFLAGS = -Wall -g -O2
BINARY = original
SOURCE = main.c
BPF_BINARY = ./bpf/bpf.o
BPF_SOURCE = ./bpf/bpf.c

LOADER=../../build/loader
TESTER=./tester

ifndef KASHK_DIR
$(error the KASHK_DIR variable is not set)
endif
# $(info expect ${KASHK_DIR})

CURDIR=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
BPF_GEN_DIR=$(KASHK_DIR)
BPF_GEN=$(BPF_GEN_DIR)/bpf_gen.sh
YAML=$(CURDIR)/build_config.yaml
BPF_COMPILE_SCRIPT=$(BPF_GEN_DIR)/compile_scripts/compile_bpf_source.sh
# $(info ${BPF_GEN})
# $(info ${YAML})

# BPF_CFLAGS =

HOOK=$(shell cat $(YAML) | grep hook | cut -d ' ' -f 2)
ifeq ($(HOOK), xdp)
TARGET_BPF_PROG=--xdp xdp_prog
else
ifeq ($(HOOK), sk_skb)
TARGET_BPF_PROG=--skskb verdict
else
$(error unexpected value for the target hook in the yaml file)
endif
endif
# $(info target hook is ${HOOK} and running $(TARGET_BPF_PROG))

.PHONY: default bpf_gen bpf_comp bpf_load bpf_run bpf_test clean

default: $(BINARY)

# Build the user program
$(BINARY): $(SOURCE)
	$(CC) $(CFLAGS) -o $(BINARY) $(SOURCE)

# Generate BPF program automatically
bpf_gen:
	mkdir -p ./bpf/
	bash $(BPF_GEN) $(YAML)

# Compile the auto-generate BPF program
bpf_comp: $(BPF_SOURCE)
	export CFLAGS="$(BPF_CFLAGS)" && bash $(BPF_COMPILE_SCRIPT) $(BPF_SOURCE) $(BPF_BINARY)

# Test if the auto-generated BPF program can load into the kernel
bpf_load: $(BPF_BINARY)
	bash $(BPF_GEN_DIR)/compile_scripts/load.sh ./bpf/bpf.o

# Run the bpf program
bpf_run: clean bpf_comp $(LOADER)
	if [ -z "${NET_IFACE}" ]; then echo "\"NET_IFACE\" is not set"; exit 1; fi
	sudo $(LOADER) -b $(BPF_BINARY) -i ${NET_IFACE} $(TARGET_BPF_PROG)

bpf_test: clean bpf_comp $(TESTER)
	sudo $(TESTER) -b $(BPF_BINARY)

# Clean the gold sub-dir
clean:
	rm $(BPF_BINARY)

.SILENT:
