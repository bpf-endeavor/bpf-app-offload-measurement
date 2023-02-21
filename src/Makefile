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


.PHONY: all clean check_output_dir

all: check_output_dir loader server

clean:
	rm -r build/

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi

server:
	$(CC) ${SERVER_FILES} ${CFLAGS} ${INCLUDES} -o ${OUTPUT_DIR}/server -lpthread

loader:
	$(CC) ${LOADER_FILES} ${CFLAGS} ${INCLUDES} -o ${OUTPUT_DIR}/loader
