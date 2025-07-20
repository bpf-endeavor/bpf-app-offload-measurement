SRC = $(wildcard *.c)
HEADERS = $(wildcard *.h)

CFLAGS = -O2 -g -Wall 
CFLAGS += -D __LIBXDP
CFLAGS += $(shell pkg-config --cflags libbpf)
CFLAGS += $(shell pkg-config --cflags libxdp)

LDFLAGS = 
LDFLAGS += $(shell pkg-config --libs libbpf)
LDFLAGS += $(shell pkg-config --libs libxdp)

default: build/cache

clean:
	rm -r build/

build/cache: $(SRC) $(HEADERS)
	mkdir -p build/
	gcc $(CFLAGS) -o $@ $(SRC) $(LDFLAGS)
