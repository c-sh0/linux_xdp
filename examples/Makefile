kern-obj  = xdp_pass_kern
user-prog = xdp_pass_user

LLC	?= llc
CLANG	?= clang
CC	:= gcc

KERN_OBJ  = ${kern-obj:=.o}
USER_PROG = ${user-prog}

LIBBPF_DIR	?= ../libbpf/bpf
BPF_CFLAGS	?= -I$(LIBBPF_DIR)/include
BPF_LDFLAGS	?= -L$(LIBBPF_DIR)/lib64
BPF_LIBS	?= -l:libbpf.a -lelf -lz

CFLAGS ?= -Wall -Wextra -Wunused -g

all: $(KERN_OBJ) $(USER_PROG)

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
		-O2 -emit-llvm -c -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

$(USER_PROG): %: %.c
	$(CC) $(CFLAGS) $(BPF_CFLAGS) $(BPF_LDFLAGS) -o $@ $< $(BPF_LIBS)

clean:
	rm -f *.ll *.o $(user-prog)

distclean: clean

install:

