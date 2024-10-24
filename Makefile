CC=clang
FLAGS=-Wall -g -O2
BPF_FLAGS=-target bpf -O2 -Wall -g
BPFTOOL=bpftool
LIBS=-lbpf

all: test

test: uprobe.skel.h test.c
	$(CC) $(FLAGS) -o test test.c $(LIBS)

uprobe.skel.h: uprobe.bpf.o
	$(BPFTOOL) gen skeleton uprobe.bpf.o > uprobe.skel.h

uprobe.bpf.o: uprobe.bpf.c
	$(CC) $(BPF_FLAGS) -c uprobe.bpf.c


clean:
	rm uprobe.bpf.o uprobe.skel.h test
