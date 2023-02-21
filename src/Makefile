CC = clang-12
LCC = llc-12

# General
OUTPUT_DIR = ./build/
INCLUDES = -I ./include/
CFLAGS = -g -O2 -Wall -Werror

# Loader:
LOADER_FILES = $(wildcard ./userspace/loader/*.c) $(wildcard ./userspace/*.c)
# $(info ${LOADER_FILES})


.PHONY: all clean check_output_dir

all: check_output_dir loader

clean:
	rm -r build/

check_output_dir:
	@if [ ! -d ${OUTPUT_DIR} ]; then  mkdir -p ${OUTPUT_DIR} ; fi

loader:
	$(CC) ${LOADER_FILES} ${CFLAGS} ${INCLUDES} -o ${OUTPUT_DIR}/loader
