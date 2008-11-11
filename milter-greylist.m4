dnl $Id: milter-greylist.m4,v 1.2 2008/11/11 02:01:03 manu Exp $
dnl Contributed by Ivan F. Martinez
dnl
dnl This file configure sendmail to use milter-greylist
dnl you can put the file in sendmail-cf/hack directory
dnl and put in your sendmail.mc file
dnl
dnl     HACK(`milter-greylist')
dnl
dnl  or put the file in sendmail-cf/feature directory
dnl and put in your sendmail.mc file
dnl
dnl     FEATURE(`milter-greylist')
dnl
dnl
dnl You can define milter parameters
dnl
dnl    confGREYLIST_SOCKET
dnl        socket to communicate with milter
dnl        default value :
dnl           local:/var/milter-greylist/milter-greylist.sock
dnl
dnl    confGREYLIST_OPTIONS
dnl       extra parameters to be used in INPUT_MAIL_FILTER
dnl
dnl
dnl
divert(-1)
dnl
dnl To get more information about milter parameters:
dnl     http://www.sendmail.org/m4/adding_mailfilters.html
dnl     http://www.milter.org/milter_api/installation.html
dnl
ifdef(`confGREYLIST_SOCKET',`dnl',`dnl
define(`confGREYLIST_SOCKET',`local:/var/milter-greylist/milter-greylist.sock')dnl
dnl')dnl
ifdef(`confGREYLIST_OPTIONS',`dnl',`define(`confGREYLIST_OPTIONS',`')dnl')dnl
INPUT_MAIL_FILTER(`greylist', `S=confGREYLIST_SOCKET confGREYLIST_OPTIONS')dnl
dnl debugmode(`V')dnl
define(`xxquote',```$1''')dnl
define(`xxconcat',`define(`$1', xxquote($1`$2')))')dnl
dnl
dnl add variables used by milter-greylist
dnl
ifelse(regexp(confMILTER_MACROS_CONNECT,`\<j\>'),`-1',`xxconcat(`confMILTER_MACROS_CONNECT',`, j')',`')dnl
ifelse(index(confMILTER_MACROS_CONNECT,`{if_addr}'),`-1',`xxconcat(`confMILTER_MACROS_CONNECT',`, {if_addr}')',`')dnl
ifelse(index(confMILTER_MACROS_CONNECT,`{daemon_port}'),`-1',`xxconcat(`confMILTER_MACROS_CONNECT',`, {daemon_port}')',`')dnl
dnl
ifelse(index(confMILTER_MACROS_HELO,`{verify}'),`-1',`xxconcat(`confMILTER_MACROS_HELO',`, {verify}')',`')dnl
ifelse(index(confMILTER_MACROS_HELO,`{cert_subject}'),`-1',`xxconcat(`confMILTER_MACROS_HELO',`, {cert_subject}')',`')dnl
dnl
ifelse(regexp(confMILTER_MACROS_ENVFROM,`\<i\>'),`-1',`xxconcat(`confMILTER_MACROS_ENVFROM',`, i')',`')dnl
ifelse(index(confMILTER_MACROS_ENVFROM,`{auth_authen}'),`-1',`xxconcat(`confMILTER_MACROS_ENVFROM',`, {auth_authen}')',`')dnl
dnl
ifelse(index(confMILTER_MACROS_ENVRCPT,`{greylist}'),`-1',`xxconcat(`confMILTER_MACROS_ENVRCPT',`, {greylist}')',`')dnl
dnl
undefine(`xxquote')dnl
undefine(`xxconcat')dnl
dnl debugmode(`-V')dnl
dnl
