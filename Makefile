all: xdp.o

.PHONY: xdp.o
xdp_drops.o: xdp.c
        clang -Wall -Wextra \
                -O2 -emit-llvm \
                -c xdp.c -S -o - \
        | llc -march=bpf -filetype=obj -o $@
