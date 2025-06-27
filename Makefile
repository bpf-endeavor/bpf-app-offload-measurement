
CURDIR = ${shell pwd}
DEPS_DIR = ${CURDIR}/deps/
$(info ${DEPS_DIR})

make_project: build_libbpf benchmarks

benchmarks:
	$(MAKE) -C ./src/


build_libbpf: ./libbpf/
	# Update submodules
	git submodule update --init
	# # Create 3rd-party deps directory
	if [ ! -d  ${DEPS_DIR} ]; then mkdir -p ${DEPS_DIR}; fi
	# Build libbpf into deps directory
	CC=clang BUILD_STATIC_ONLY=y DESTDIR=${DEPS_DIR} OBJDIR=${DEPS_DIR} $(MAKE) -C libbpf/src install

	# C-HashMap
	INCDIR=${DEPS_DIR}/usr/include/c-hashmap/; \
	if [ ! -d $$INCDIR ]; then mkdir -p $$INCDIR; fi ; \
	cp ${CURDIR}/c-hashmap/map.h $$INCDIR
