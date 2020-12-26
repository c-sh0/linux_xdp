
all:
	gcc -g -Wall -I../libbpf/bpf  -c -o common_params.o common_params.c	
	gcc -Wall -I../libbpf/bpf/include -g -L../libbpf/bpf/lib64 -o xdp-tool common_params.o xdp-tool.c -l:libbpf.a -lelf -lz
clean:
	rm -f *.o xdp-tool
