# $Id: milter-greylist.spec,v 1.1 2004/12/17 22:37:43 manu Exp $
# Contributed by Ivan F. Martinez
%define ver 1.7.3
%define rel 1
%define user smmsp

Summary: GreyList milter for sendmail
Name: milter-greylist
Version:   %ver
Release:   %rel
Group:		System Environment/Daemons
License: 3-clause BSD license
Source0: ftp://ftp.espci.fr/pub/milter-greylist/%{name}-%{version}.tgz
URL: http://hcpnet.free.fr/milter-greylist/
BuildRoot: %{_tmppath}/%{name}-%{version}

Requires: sendmail >= 8.12
BuildRequires: sendmail-devel >= 8.12
BuildRequires: flex

%description
milter-greylist is a stand-alone milter written in C that implements the
greylist filtering method, as proposed by Evan Harris.

Grey listing works by assuming that unlike legitimate MTA, spam engines will
not retry sending their junk mail on a temporary error. The filter will
always temporarily reject mail on a first attempt, and to accept it after
some time has elapsed.

If spammers ever try to resend rejected messages, we can assume they will
not stay idle between the two sends (if they do, the spam problem would just
be solved). Odds are good that the spammer will send a mail to an honey pot
address and get blacklisted in several real-time distributed black list
before the second attempt.


%prep
%setup -q 


%build
./configure --prefix=%{_prefix} --mandir=%{_mandir} --with-user=%{user}
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}/etc/mail
mkdir -p ${RPM_BUILD_ROOT}/var/milter-greylist
mkdir -p ${RPM_BUILD_ROOT}/usr/share/sendmail-cf/feature

install -m 755 rc-redhat.sh ${RPM_BUILD_ROOT}%{_initrddir}/milter-greylist
install -m 644 milter-greylist.m4 ${RPM_BUILD_ROOT}%{_datadir}/sendmail-cf/feature/milter-greylist.m4
make DESTDIR=${RPM_BUILD_ROOT} install

%pre

%post
/sbin/chkconfig --add milter-greylist

%preun
if [ $1 = 0 ]; then
	/sbin/chkconfig --del milter-greylist
	/bin/grep -q -E '(FEATURE|INPUT_MAIL_FILTER).*milter-greylist' /etc/mail/sendmail.mc
	if [ $? -eq 0 ]
	then
		echo "You you must remove the milter-greylist config"
		echo "from /etc/mail/sendmail.mc file"
	fi
fi

%files
%defattr(-,root,root)
%doc README ChangeLog
%config (noreplace) /etc/mail/greylist.conf
%{_initrddir}/milter-greylist
%{_prefix}/bin/milter-greylist
%{_mandir}/man5/greylist.conf.5.gz
%{_mandir}/man8/milter-greylist.8.gz
%dir %attr(-,%{user},root) /var/milter-greylist

%changelog
* Thu Dec 16 2004 Ivan F. Martinez <ivanfm@users.sourceforge.net> 1.7.3-1
- updated to new version 

* Wed Dec  8 2004 Ivan F. Martinez <ivanfm@users.sourceforge.net> 1.6rc1-1
- initial release

