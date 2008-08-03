# $Id: milter-greylist.spec,v 1.93 2008/08/03 05:00:06 manu Exp $
# Contributed by Ivan F. Martinez

%define ver 4.1.4
%define rel 1

%define user root
%{?build_user:%define user %{build_user}}

%define postfix 0
%{?build_postfix:%define postfix 1}

%define dnsrbl 0
%{?build_dnsrbl:%define dnsrbl 1}

%define libbind 0
%{?build_libbind:%define libbind 1}

%if ! %{postfix}
Summary: GreyList milter for Sendmail
%else
Summary: GreyList milter for Postfix
%endif
Name: milter-greylist
Version:   %ver
Release:   %rel
Group:	   System Environment/Daemons
License: 3-clause BSD license
Source0: ftp://ftp.espci.fr/pub/milter-greylist/%{name}-%{version}.tgz
URL: http://hcpnet.free.fr/milter-greylist/
BuildRoot: %{_tmppath}/%{name}-%{version}-root-%(%{__id_u} -n)

%if ! %{postfix}
Requires: sendmail >= 8.11
Requires: sendmail-cf >= 8.11
%else
Requires: postfix >= 2.3
%endif
BuildRequires: sendmail-devel >= 8.11
BuildRequires: flex
BuildRequires: bison
%if %{libbind}
BuildRequires: bind-libbind-devel
%endif

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
%configure \
	--with-user=%{user} \
%if %{postfix}
	--enable-postfix \
%endif
%if %{dnsrbl}
	--enable-dnsrbl \
%endif
%if %{libbind}
	--with-libbind

%endif

%{__make} %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
mkdir -p ${RPM_BUILD_ROOT}%{_initrddir}
mkdir -p ${RPM_BUILD_ROOT}%{_sysconfdir}/mail
mkdir -p ${RPM_BUILD_ROOT}%{_localstatedir}/milter-greylist
mkdir -p ${RPM_BUILD_ROOT}%{_datadir}/sendmail-cf/feature

install -m 755 rc-redhat.sh ${RPM_BUILD_ROOT}%{_initrddir}/milter-greylist
install -m 644 milter-greylist.m4 ${RPM_BUILD_ROOT}%{_datadir}/sendmail-cf/feature/milter-greylist.m4
touch ${RPM_BUILD_ROOT}%{_localstatedir}/milter-greylist/greylist.db
# use root user, as the %files section define the correct install user
make DESTDIR=${RPM_BUILD_ROOT} USER=root install

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%pre
/usr/bin/id "%{user}" &> /dev/null
if [ $? -ne 0 ]
then 
    /usr/sbin/useradd -r -d /etc/mail -s /sbin/nologin \
        -c "GreyList Milter" %{user} >/dev/null 2>&1 || :
fi


%post
/sbin/chkconfig --add milter-greylist
%if ! %{postfix}
/bin/grep -q -E '(FEATURE|INPUT_MAIL_FILTER).*milter-greylist' /etc/mail/sendmail.mc
if [ $? -ne 0 ]
then
	echo "You can enable milter-greylist in your sendmail, adding the line : "
	echo "FEATURE(\`milter-greylist')dnl"
	echo "to /etc/mail/sendmail.mc file"
fi
%endif


%preun
if [ $1 -eq 0 ]; then
	/sbin/service milter-greylist stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del milter-greylist
%if ! %{postfix}
	/bin/grep -q -E '(FEATURE|INPUT_MAIL_FILTER).*milter-greylist' /etc/mail/sendmail.mc
	if [ $? -eq 0 ]
	then
		echo "You must remove the milter-greylist config"
		echo "from /etc/mail/sendmail.mc file"
	fi
%endif
fi

%postun
if [ $1 -eq 0 ]; then
	rm -rf %{_localstatedir}/milter-greylist/
        grep -q "$%{user}:.*GreyList Milter:"
	if [ $? -eq 0 ]
        then
		/usr/sbin/userdel %{user} >/dev/null 2>&1 || :
		/usr/sbin/groupdel %{user} >/dev/null 2>&1 || :
	fi
else
	/sbin/service milter-greylist condrestart > /dev/null 2>&1 || :
fi

%files
%defattr(-,root,root)
%doc README ChangeLog
%config (noreplace) %{_sysconfdir}/mail/greylist.conf
%{_initrddir}/milter-greylist
%{_bindir}/milter-greylist
%{_mandir}/man5/greylist.conf.5.gz
%{_mandir}/man8/milter-greylist.8.gz
%{_datadir}/sendmail-cf/feature/milter-greylist.m4
%dir %attr(-,%{user},root) %{_localstatedir}/milter-greylist
%attr(0600,%{user},root) %ghost %{_localstatedir}/milter-greylist/greylist.db

%changelog
* Thu Jan  4 2007 Nerijus Baliunas <nerijus|users.sourceforge.net> 3.1.4-1
- added build_user, build_postfix, build_dnsrbl, build_libbind definitions

* Sun Mar 13 2005 Petr Kristof <Petr|Kristof_CZ> 1.7.4-3
- support for running as specific user

* Tue Jan 25 2005 Petr Kristof <Petr|Kristof_CZ> 1.7.4-3
- Use more %macros
- Add conditional restart during upgrade
- Fixed %postun cleanup
- Add %ghost for greylist.db

* Mon Jan 17 2005 Ivan F. Martinez <ivanfm@users.sourceforge.net> 1.7.4-2
- added check for milter-greylist in sendmail.mc on post

* Wed Jan  5 2005 Horst H. von Brand <vonbrand@inf.utfsm.cl> 1.7.4-1
- Updated version
- Added missing installed milter-greylist.m4 file
- Need sendmail-cf if installing above
- Requires bison for building

* Thu Dec 16 2004 Ivan F. Martinez <ivanfm@users.sourceforge.net> 1.7.3-1
- updated to new version 

* Wed Dec  8 2004 Ivan F. Martinez <ivanfm@users.sourceforge.net> 1.6rc1-1
- initial release

