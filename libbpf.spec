Name:           libbpf-devel
Version:        0.1.0
Release:        1
Source:         %{name}-%{version}.tar.gz
URL:            https://github.com/%{pkgname}/%{pkgname}
Provides:	%{name}
License:        LGPLv2 or BSD
Summary:        Libbpf devlopment libraries
BuildRequires:  gcc llvm elfutils-libelf-devel elfutils-devel kernel-ml-devel kernel-ml-headers

BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Packager:

Requires:	kernel-ml-headers >= 5.9.0-0.rc2.1

# do not generate debugging packages by default - newer versions of rpmbuild
%define debug_package %{nil}
%define _lto_cflags %{nil}

%description

A mirror of bpf-next linux tree bpf-next/tools/lib/bpf directory plus its
supporting headers for developing applications that use libbpf


%global make_flags DESTDIR=%{buildroot} OBJDIR=%{_builddir} CFLAGS="%{build_cflags} -fPIC" LDFLAGS="%{build_ldflags} -Wl,--no-as-needed" LIBDIR=/%{_libdir}/bpf NO_PKG_CONFIG=1

%prep
%setup -n %{name}-%{version}

%build
%make_build -C ./src %{make_flags}

%install
%make_install -C ./src %{make_flags}

%files
%{_libdir}/bpf
%{_includedir}/bpf
%exclude %dir /usr/lib64/bpf

%clean

%post

%changelog
* Fri Sep 13 2019 Jiri Olsa <jolsa@redhat.com> - 0.0.3-1
- Initial release
