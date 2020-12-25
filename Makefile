LLC	?= llc
CLANG	?= clang
CC	:= gcc

LIBBPF_DIR   ?= libbpf
LIBBPF_SRC   ?= $(LIBBPF_DIR)/src/
LIBBPF_BUILD ?= $(LIBBPF_DIR)/bpf

EXAMPLES_DIR ?= examples

all: build_libbpf build_examples

# libbpf build/install location ./libbpf/bpf
build_libbpf:
	@if [ ! -d $(LIBBPF_SRC) ]; then \
		echo "Error: missing libbpf submodule"; \
		echo "Run: git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_SRC) && PREFIX=/bpf DESTDIR=../ $(MAKE) install; \
	fi

build_examples: build_libbpf
	$(MAKE) -C $(EXAMPLES_DIR)

clean:
	$(MAKE) -C $(EXAMPLES_DIR) clean
	cd $(LIBBPF_SRC) && $(MAKE) clean
	rm -rf $(LIBBPF_BUILD)

