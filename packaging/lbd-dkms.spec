Name:           lbd-dkms
Version:        %{version}
Release:        1%{?dist}
Summary:        LBD (Logging Block Device) kernel module - DKMS source
License:        GPLv2
URL:            https://miren.dev/lbd
Source0:        lbd-%{version}.tar.gz
BuildArch:      noarch
Requires:       dkms >= 2.1.0.0
Requires:       kernel-devel

%description
A block device driver backed by a file that logs all write operations
for change tracking, audit, and replay. This package provides the
source for building the module with DKMS.

%prep
%setup -q -n lbd-%{version}

%install
mkdir -p %{buildroot}/usr/src/lbd-%{version}
cp -a . %{buildroot}/usr/src/lbd-%{version}/

%post
dkms add -m lbd -v %{version} --rpm_safe_upgrade 2>/dev/null || true
dkms build -m lbd -v %{version} --rpm_safe_upgrade || true
dkms install -m lbd -v %{version} --rpm_safe_upgrade --force || true
true

%preun
dkms remove -m lbd -v %{version} --rpm_safe_upgrade --all 2>/dev/null || true
true

%files
/usr/src/lbd-%{version}/
