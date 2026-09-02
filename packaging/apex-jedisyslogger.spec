# RPM spec — RHEL, Rocky, Alma, CentOS Stream, Fedora.
#
# Nothing is compiled, so the package is noarch and the build phase is a copy.
# Version must match js/version.js; packaging/version.sh --check enforces it.
%global appname apex-jedisyslogger
%global appdir  %{_datadir}/%{appname}
# Defined by systemd-rpm-macros on a Red Hat host; absent when the spec is built
# with bare rpmbuild elsewhere, which leaves an unexpanded macro in %files and
# fails with "File must begin with /".
%{!?_unitdir: %global _unitdir /usr/lib/systemd/system}

Name:           apex-jedisyslogger
Version:        1.2.1
Release:        1%{?dist}
Summary:        SIEM log-ingestion simulator with a terminal dashboard

# No LICENSE file in the repository yet — set this to the real identifier
# (and restore the %%license line below) before this package is published.
License:        UNSPECIFIED
URL:            https://github.com/alfredonacino/APEX-Jedi-Syslogger
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
Requires:       nodejs >= 18

%description
A synthetic log source and a miniature SIEM in one tool, for detection
engineering practice. Generates RFC 3164/5424 syslog plus 42 appliance formats
(Palo Alto, FortiGate, Cisco, Sysmon, CloudTrail, Microsoft 365, Entra ID,
Defender for Endpoint and more), injects 72 MITRE ATT&CK-tagged attack
scenarios, and runs a stateful detection-rule engine over the result.

Forwards live to a real collector over UDP, TCP or Splunk HEC. The terminal
dashboard needs no browser; the same tree also serves the optional web UI.

%prep
%setup -q

%build
# Deliberately empty: no compiler, no bundler, no dependencies to fetch.

%install
mkdir -p %{buildroot}%{appdir}
cp -r jedi-cli.js desktop.js forward.js updater.js server.js auth.js js css bin samples types \
      index.html login.html account.html about.html ecosystem.config.js \
      %{buildroot}%{appdir}/

install -Dm0755 bin/jedi %{buildroot}%{_bindir}/jedi

install -Dm0644 packaging/%{appname}.desktop %{buildroot}%{_datadir}/applications/%{appname}.desktop
for s in 16 32 48 64 128 256 512; do
  install -Dm0644 packaging/icons/%{appname}-$s.png \
    %{buildroot}%{_datadir}/icons/hicolor/${s}x${s}/apps/%{appname}.png
done
install -Dm0644 packaging/apex-jedisyslogger.service \
  %{buildroot}%{_unitdir}/apex-jedisyslogger.service

mkdir -p %{buildroot}%{_docdir}/%{appname}
install -m0644 README.md DOCUMENTATION.md CONNECTORS.md %{buildroot}%{_docdir}/%{appname}/

%files
%{appdir}
%{_bindir}/jedi
%{_datadir}/applications/%{appname}.desktop
%{_datadir}/icons/hicolor/*/apps/%{appname}.png
%{_unitdir}/apex-jedisyslogger.service
%doc %{_docdir}/%{appname}
# %%license LICENSE   <- uncomment once the repository has one

%changelog
* Wed Sep 02 2026 Alfredo Nacino <alfredo@nacino.net> - 1.0.0-1
- First packaged release: terminal build alongside the web dashboard,
  72 attack scenarios, 42 appliance formats, live UDP/TCP/HEC forwarding.
