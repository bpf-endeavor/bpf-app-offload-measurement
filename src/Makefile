CC = clang
LLC = llc
INCLUDES = -I ./include/ -I ../deps/usr/include/
CFLAGS = -g -O2 -Wall -Wno-unused-but-set-variable -Wno-unused-variable

# Output directory (executables are in this dir)
OUTPUT_DIR = ./build
# BPF programs are in this dir
OUTPUT_DIR_BPF = ./build/bpf/
OUTPUT_DIR_BPF_LL = ./build/bpf/ll

# Loader:
LOADER_FILES = $(wildcard ./userspace/loader/*.c) $(wildcard ./userspace/*.c)

# Local runner
LOCAL_RUNNER_FILES = $(wildcard ./userspace/runner/*.c)
LOCAL_RUNNER_HEADERS = $(wildcard ./userspace/runner/*.h)

# Userspace Server
SERVER_FILES = $(wildcard ./userspace/server/*.c)
SERVER_SHARED_C_FILES = $(wildcard ./userspace/*.c) ../c-hashmap/map.c
USERSPACE_HEADERS =  $(wildcard ./include/userspace/*.h)
# The server binaries that should be built
SERVER_BINS = ${OUTPUT_DIR}/server_inst \
			  ${OUTPUT_DIR}/server_summarize \
			  ${OUTPUT_DIR}/server_lookup \
			  ${OUTPUT_DIR}/server_lookup_ring_buf \
			  ${OUTPUT_DIR}/server_overhead \
			  ${OUTPUT_DIR}/server_bounce \
			  ${OUTPUT_DIR}/server_drop \
			  ${OUTPUT_DIR}/server_hook_timestamp \
			  ${OUTPUT_DIR}/server_comm_map
SERVER_LIBS = -L ../deps -lpthread -lbpf -lelf -lz

# BPF
KERN_OBJECTS := bpf_inst.o \
	bpf_summarize.o \
	bpf_test.o \
	bpf_lookup.o \
	xdp_lookup_multishot.o \
	tc_lookup_multishot.o \
	skskb_lookup_multishot.o \
	tcp_lookup_multishot.o \
	bpf_overhead.o \
	bpf_max_skskb_tp.o \
	bpf_ktime_err.o \
	bpf_drop_perf.o \
	bpf_pass_perf.o \
	bpf_summarize_2.o \
	bpf_summarize_3.o \
	bpf_boundcheck_overhead.o \
	bpf_hook_stamp.o \
	bpf_redirect.o \
	bpf_comm_map.o \
	bpf_empty_hook_test.o \
	bpf_resize_perf.o \
	bpf_jit_vs_native.o \
	bpf_demux.o \
	bpf_skskb_redir.o \
	bpf_jit_vs_native_fib.o \
	bpf_map_access_throughput.o \
	bpf_map_lookup_access_time.o

# bpf_jit_vs_native_prime.o 

_KERN_OBJECTS = $(addprefix $(OUTPUT_DIR_BPF), $(KERN_OBJECTS))
# BPF source code is in this dir
KERN_DIR = ./bpf/
KERN_HEADERS = $(wildcard ./include/bpf/*.h) $(wildcard ./include/*.h)

# All the binary object that should be created
OUTPUTS = ${SERVER_BINS}
OUTPUTS += ${OUTPUT_DIR}/loader
OUTPUTS += ${OUTPUT_DIR}/local_runner
OUTPUTS += ${_KERN_OBJECTS}

VMLINUX = ./include/vmlinux.h


.PHONY: all clean check_output_dir

all: check_output_dir $(VMLINUX) ${OUTPUTS}

clean:
	rm -r build/
	rm -f $(VMLINUX)

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF} ]; then  mkdir -p ${OUTPUT_DIR_BPF} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF_LL} ]; then  mkdir -p ${OUTPUT_DIR_BPF_LL} ; fi


${SERVER_BINS}: ${SERVER_FILES} ${SERVER_SHARED_C_FILES} ${USERSPACE_HEADERS}
	MAIN=$$(basename $@); \
	$(CC) ./userspace/server/$$MAIN.c ${SERVER_SHARED_C_FILES} ${CFLAGS} ${INCLUDES} -o $@ $(SERVER_LIBS);

${OUTPUT_DIR}/loader: ${LOADER_FILES} ${USERSPACE_HEADERS}
	$(CC) ${LOADER_FILES} ${CFLAGS} ${INCLUDES} -o $@ -L ../deps -lbpf -lelf -lz

${OUTPUT_DIR}/local_runner: ${LOCAL_RUNNER_FILES} ${LOCAL_RUNNER_HEADERS}
	$(CC) ${LOCAL_RUNNER_FILES} ${CFLAGS} ${INCLUDES} -o $@ -L ../deps -lbpf -lelf -lz -lrt

$(_KERN_OBJECTS): $(OUTPUT_DIR_BPF)%.o:$(KERN_DIR)%.c $(KERN_HEADERS)
	LL_FILE=${OUTPUT_DIR_BPF_LL}/$(notdir $@); \
	$(CC) ${INCLUDES} \
		-target bpf \
		-S \
		-D BPF_PROG \
		-D__KERNEL__  \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_x86 \
		-Wall \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -g -emit-llvm -c $< -o $$LL_FILE; \
		$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o "$@" $$LL_FILE;

$(VMLINUX): $(KFUNC_MEMCPY_TARGET)
	# Remove the old vmlinux.h
	if [ -f $@ ]; then rm $@; fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

