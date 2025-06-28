src=$(wildcard *.c)
cflags=-O3 -Wall -g
ldflag=-lm

test: $(src) zipf.h
	gcc $(cflags) -o $@ $(src) $(ldflag)
