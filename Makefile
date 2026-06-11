CC = gcc 
FLAGS = -g -O2 -target bpf 
CLANG = clang
all: kprowl.bpf.o loader

kprowl.bpf.o: kprowl.bpf.c
	$(CLANG) $(FLAGS) -c $< -o $@
loader: loader.c
	$(CC) $< -o $@ -lbpf
clean:
	rm -f kprowl.bpf.o loader 
