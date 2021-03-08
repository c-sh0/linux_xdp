LLC	?= llc
CLANG	?= clang
CC	:= gcc

SRC_DIRS = simple_pass map_pinning

LIBBPF_DIR   ?= libbpf
LIBBPF_SRC   ?= $(LIBBPF_DIR)/src
LIBBPF_BUILD ?= $(LIBBPF_DIR)/bpf

# rpm package info
SPEC_FILE	   = libbpf.spec
PKG_BUILD_DIR	   = rpmbuild
PKG_NAME	   = $$(awk '/^Name:/ {print $$2}' $(SPEC_FILE))
PKG_VERSION	   = $$(awk '/^Version:/ {print $$2}' $(SPEC_FILE))
PKG_BUILD_UID	   = $(shell id -u -n)
PKG_BUILD_GIT_USER = $(shell git config user.email)
PKG_BUILD_HOST	   = $(shell uname -n)
PKG_BUILD_DATE	   = $(shell date +%s)
PKG_BUILD_COMMIT   = $(shell cd $(LIBBPF_DIR) && git --no-pager describe --always --dirty --abbrev=40)
PKG_BUILD_GIT_MSG  = $(shell cd $(LIBBPF_DIR) && git log -n 1 --pretty=format:"%s")
PKG_ARCHIVE	   = $(PKG_NAME)-$(PKG_VERSION).tar.gz

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
		if [ -d $$dir ]; then \
			echo Making all in $$dir... ;\
			(cd $$dir ; make) || exit 1;\
		fi \
	done

clean:
	cd $(LIBBPF_SRC) && $(MAKE) clean
	rm -rf $(LIBBPF_BUILD) $(RPM_BUILD_DIR)
	@for dir in $(SRC_DIRS); do\
		if [ -d $$dir ]; then \
			(cd $$dir ; make clean) || exit 1;\
		fi \
	done

# build libbpf-devel package
package: clean
	$(shell mkdir -p ./$(PKG_BUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS})
	$(shell cp -f $(SPEC_FILE) ./$(PKG_BUILD_DIR)/SPECS/)
	$(shell tar --transform "s/^.\/$(LIBBPF_DIR)/$(PKG_NAME)-$(PKG_VERSION)/" -czf ./$(PKG_BUILD_DIR)/SOURCES/$(PKG_ARCHIVE) ./libbpf)
	sed -i "/^Packager:/c\Packager: $(PKG_BUILD_GIT_USER) uid: $(PKG_BUILD_UID)" ./$(PKG_BUILD_DIR)/SPECS/$(SPEC_FILE)
	sed -i "/^\%description$$/c\\%description\ngit-commit: $(PKG_BUILD_COMMIT)\ngit-msg: $(PKG_BUILD_GIT_MSG)" ./$(PKG_BUILD_DIR)/SPECS/$(SPEC_FILE)
	rpmbuild -bb -D "_topdir $(shell pwd)/$(PKG_BUILD_DIR)" --verbose ./$(PKG_BUILD_DIR)/SPECS/$(SPEC_FILE)
