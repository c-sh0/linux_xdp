KERNEL_OBJ = simple_pass_kern.o

LLC	?= llc
CLANG	?= clang
CC	:= gcc

BPF_CFLAGS ?= -I../libbpf/bpf/include/

all: $(KERNEL_OBJ)

$(KERNEL_OBJ): %.o: %.c
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	rm -f *.ll *.o
