Summary: pktstat-bpf forked with Kube integration
Name: pktstat-kube
Version: 1.0.0
Release: 1%{?dist}
Source0: %{name}-%{version}.tar.gz
License: GPLv3+
Group: Development/Tools

Requires(post): info
Requires(preun): info

%description
eBPF packet stat capturer for Replicated CMX environments

%prep
%setup -q

%build
go generate
CGO_ENABLED=0 go build -v -o %{name}

%install
install -Dpm 0755 %{name} %{buildroot}%{_bindir}/%{name}

%files
/usr/bin/pktstat-kube
