CC = clang
LLC = llc
INCLUDES = -I ./include/ -I ../deps/usr/include/
CFLAGS = -g -O2 -Wall

# Output directory (executables are in this dir)
OUTPUT_DIR = ./build/
# BPF programs are in this dir
OUTPUT_DIR_BPF = ./build/bpf/
OUTPUT_DIR_BPF_LL = ./build/bpf/ll/

# Loader:
LOADER_FILES = $(wildcard ./userspace/loader/*.c) $(wildcard ./userspace/*.c)

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
			  ${OUTPUT_DIR}/server_drop
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
	bpf_drop_perf.o
_KERN_OBJECTS = $(addprefix $(OUTPUT_DIR_BPF), $(KERN_OBJECTS))
# BPF source code is in this dir
KERN_DIR = ./bpf/
KERN_HEADERS = $(wildcard ./include/bpf/*.h) $(wildcard ./include/*.h)

# All the binary object that should be created
OUTPUTS = ${SERVER_BINS} ${OUTPUT_DIR}/loader ${_KERN_OBJECTS}


.PHONY: all clean check_output_dir

all: check_output_dir ${OUTPUTS}

clean:
	rm -r build/

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF} ]; then  mkdir -p ${OUTPUT_DIR_BPF} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF_LL} ]; then  mkdir -p ${OUTPUT_DIR_BPF_LL} ; fi


${SERVER_BINS}: ${SERVER_FILES} ${SERVER_SHARED_C_FILES} ${USERSPACE_HEADERS}
	MAIN=$$(basename $@); \
	$(CC) ./userspace/server/$$MAIN.c ${SERVER_SHARED_C_FILES} ${CFLAGS} ${INCLUDES} -o $@ $(SERVER_LIBS);

${OUTPUT_DIR}/loader: ${LOADER_FILES} ${USERSPACE_HEADERS}
	$(CC) ${LOADER_FILES} ${CFLAGS} ${INCLUDES} -o $@ -L ../deps -lbpf -lelf -lz

$(_KERN_OBJECTS): $(OUTPUT_DIR_BPF)%.o:$(KERN_DIR)%.c $(KERN_HEADERS)
	LL_FILE=${OUTPUT_DIR_BPF_LL}/$(notdir $@); \
	$(CC) ${INCLUDES} \
		-target bpf \
		-S \
		-D BPF_PROG \
		-D__KERNEL__  \
		-D__BPF_TRACING__ \
		-D__TARGET_ARCH_x86 \
		-Wall -Werror \
		-Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-O2 -g -emit-llvm -c $< -o $$LL_FILE; \
		$(LLC) -mcpu=v3 -march=bpf -filetype=obj -o "$@" $$LL_FILE;
