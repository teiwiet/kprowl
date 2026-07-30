CC = gcc
CLANG = clang
FLAGS = -g -O2
BPFFLAGS = $(FLAGS) -target bpf -c

all: kprowl.bpf.o loader

ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')

kprowl.bpf.o: kprowl.bpf.c kprowl.h
	$(CLANG) $(BPFFLAGS) -D__TARGET_ARCH_$(ARCH) $< -o $@

loader: loader.c
	$(CC) $(FLAGS) $< -o $@ -lbpf

clean:
	rm -f kprowl.bpf.o loader

.PHONY: all clean
