kern-obj  = process_payload_kern

LLC	?= llc
CLANG	?= clang
CC	:= gcc

KERN_OBJ  = ${kern-obj:=.o}
USER_PROG = ${user-prog}

LIBBPF_DIR	?= ../libbpf/bpf
BPF_CFLAGS	?= -I$(LIBBPF_DIR)/include

all: $(KERN_OBJ)

$(KERN_OBJ): %.o: %.c
	$(CLANG) -S \
		-target bpf \
		-D __BPF_TRACING__ \
		$(BPF_CFLAGS) \
		-Wall \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Werror \
		-D__x86_64__ \
		-D__TARGET_ARCH_ \
                -D__KERNEL__ \
                -D__ASM_SYSREG_H \
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

clean:
	rm -f *.ll *.o $(user-prog)

distclean: clean

install:

