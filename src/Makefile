CC = clang-12
LCC = llc-12

# General
OUTPUT_DIR = ./build/
INCLUDES = -I ./include/
CFLAGS = -g -O2 -Wall -Werror

# Loader:
LOADER_FILES = $(wildcard ./userspace/loader/*.c) $(wildcard ./userspace/*.c)
SERVER_FILES = $(wildcard ./userspace/server/*.c) $(wildcard ./userspace/*.c)
# $(info ${LOADER_FILES})

OUTPUTS = ${OUTPUT_DIR}/server ${OUTPUT_DIR}/loader


.PHONY: all clean check_output_dir

all: check_output_dir ${OUTPUTS}

clean:
	rm -r build/

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi

${OUTPUT_DIR}/server: ${SERVER_FILES}
	$(CC) ${SERVER_FILES} ${CFLAGS} ${INCLUDES} -o $@ -lpthread

${OUTPUT_DIR}/loader: ${LOADER_FILES}
	$(CC) ${LOADER_FILES} ${CFLAGS} ${INCLUDES} -o $@
