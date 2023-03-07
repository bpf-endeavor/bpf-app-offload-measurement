CC = clang-12
LLC = llc-12
INCLUDES = -I ./include/ -I ../deps/usr/include/
CFLAGS = -g -O2 -Wall -Werror

# Output directory (executables are in this dir)
OUTPUT_DIR = ./build/
# BPF programs are in this dir
OUTPUT_DIR_BPF = ./build/bpf/
OUTPUT_DIR_BPF_LL = ./build/bpf/ll/

# Loader:
LOADER_FILES = $(wildcard ./userspace/loader/*.c) $(wildcard ./userspace/*.c)

# Userspace Server
SERVER_FILES = $(wildcard ./userspace/server/*.c) $(wildcard ./userspace/*.c)

# BPF
KERN_OBJECTS := bpf_inst.o
_KERN_OBJECTS = $(addprefix $(OUTPUT_DIR_BPF), $(KERN_OBJECTS))
# BPF source code is in this dir
KERN_DIR = ./bpf/
KERN_HEADERS = $(wildcard ./include/bpf/*.h) $(wildcard ./include/*.h)

# $(info ${LOADER_FILES})

OUTPUTS = ${OUTPUT_DIR}/server ${OUTPUT_DIR}/loader ${_KERN_OBJECTS}


.PHONY: all clean check_output_dir

all: check_output_dir ${OUTPUTS}

clean:
	rm -r build/

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF} ]; then  mkdir -p ${OUTPUT_DIR_BPF} ; fi
	@if [ ! -d ${OUTPUT_DIR_BPF_LL} ]; then  mkdir -p ${OUTPUT_DIR_BPF_LL} ; fi


${OUTPUT_DIR}/server: ${SERVER_FILES}
	$(CC) ${SERVER_FILES} ${CFLAGS} ${INCLUDES} -o $@ -lpthread

${OUTPUT_DIR}/loader: ${LOADER_FILES}
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
