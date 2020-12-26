LLC	?= llc
CLANG	?= clang
CC	:= gcc

SRC_DIRS   = examples xdp-tool

LIBBPF_DIR   ?= libbpf
LIBBPF_SRC   ?= $(LIBBPF_DIR)/src/
LIBBPF_BUILD ?= $(LIBBPF_DIR)/bpf

all: build_libbpf build_progs 

# libbpf build/install location ./libbpf/bpf
build_libbpf:
	@if [ ! -d $(LIBBPF_SRC) ]; then \
		echo "Error: missing libbpf submodule"; \
		echo "Run: git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_SRC) && PREFIX=/bpf DESTDIR=../ $(MAKE) install; \
	fi

build_progs:
	@for dir in $(SRC_DIRS); do\
		echo Making all in $$dir... ;\
		(cd $$dir ; make) || exit 1;\
	done
	
clean:
	cd $(LIBBPF_SRC) && $(MAKE) clean
	rm -rf $(LIBBPF_BUILD)
	@for dir in $(SRC_DIRS); do\
		(cd $$dir ; make clean) || exit 1;\
	done
	

