%option nodefault
%option nomain
%option noyywrap
%option prefix="conf_"

number		[0-9]+
ipaddr		[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}
ip6addr		([0-9a-fA-F]*:){2,}[0-9a-fA-F]*(%[0-9a-zA-Z]+)?
cidr		"/"[0-9]{1,3}
atext		[A-Za-z0-9!#$%&'*+/=?$^_`}{|~.-]{1,}
qtext		"\""[!-~]{1,}"\""
mailbox		{atext}|{qtext}
domainname	[A-Za-z0-9._-]+
email		{mailbox}"\@"{domainname}
comment		#.*$
blank		[ \t]+
addr		[Aa][Dd][Dd][Rr]:?
helo		[Hh][Ee][Ll][Oo]
from		[Ff][Rr][Oo][Mm]:?
rcpt		[Rr][Cc][Pp][Tt]:?
peer		[Pp][Ee][Ee][Rr]:?
verbose		[Vv][Ee][Rr][Bb][Oo][Ss][Ee]
quiet		[Qq][Uu][Ii][Ee][Tt]
noauth		[Nn][Oo][Aa][Uu][Tt][Hh]
auth		[Aa][Uu][Tt][Hh]
tls		[Tt][Ll][Ss]
msgsize		[Mm][Ss][Gg][Ss][Ii][Zz][Ee]
rcptcount	[Rr][Cc][Pp][Tt][Cc][Oo][Uu][Nn][Tt]
noaccessdb	[Nn][Oo][Aa][Cc][Cc][Ee][Ss][Ss][Dd][Bb]
extendedregex	[Ee][Xx][Tt][Ee][Nn][Dd][Ee][Dd][Rr][Ee][Gg][Ee][Xx]
nospf		[Nn][Oo][Ss][Pp][Ff]
spf		[Ss][Pp][Ff]
dkimcheck	[Dd][Kk][Ii][Mm]
pass		[Pp][Aa][Ss][Ss]
fail		[Ff][Aa][Ii][Ll]
softfail	[Ss][Oo][Ff][Tt][Ff][Aa][Ii][Ll]
neutral		[Nn][Ee][Uu][Tt][Rr][Aa][Ll]
unknown		[Uu][Nn][Kk][Nn][Oo][Ww][Nn]
error		[Ee][Rr][Rr][Oo][Rr]
self		[Ss][Ee][Ll][Ff]
delayedreject	[Dd][Ee][Ll][Aa][Yy][Ee][Dd][Rr][Ee][Jj][Ee][Cc][Tt]
testmode	[Tt][Ee][Ss][Tt][Mm][Oo][Dd][Ee]
greylist	[Gg][Rr][Ee][Yy][Ll][Ii][Ss][Tt]:?		
autowhite	[Aa][Uu][Tt][Oo][Ww][Hh][Ii][Tt][Ee]:?
pidfile		[Pp][Ii][Dd][Ff][Ii][Ll][Ee]:?
dumpfile	[Dd][Uu][Mm][Pp][Ff][Ii][Ll][Ee]:?
subnetmatch	[Ss][Uu][Bb][Nn][Ee][Tt][Mm][Aa][Tt][Cc][Hh]:?
subnetmatch6	[Ss][Uu][Bb][Nn][Ee][Tt][Mm][Aa][Tt][Cc][Hh]6:?
socket		[Ss][Oo][Cc][Kk][Ee][Tt]:?
user		[Uu][Ss][Ee][Rr]:?
nodetach	[Nn][Oo][Dd][Ee][Tt][Aa][Cc][Hh]
report		[Rr][Ee][Pp][Oo][Rr][Tt]:?
stat		[Ss][Tt][Aa][Tt]
none		[Nn][Oo][Nn][Ee]
delays		[Dd][Ee][Ll][Aa][Yy][Ss]
nodelays	[Nn][Oo][Dd][Ee][Ll][Aa][Yy][Ss]
gldelay		[Dd][Ee][Ll][Aa][Yy]
tarpit		[Tt][Aa][Rr][Pp][Ii][Tt]:?
tarpitmode	[Tt][Aa][Rr][Pp][Ii][Tt][Mm][Oo][Dd][Ee]
persession	[Pp][Ee][Rr][Ss][Ee][Ss][Ss][Ii][Oo][Nn]
perresponse	[Pp][Ee][Rr][Rr][Ee][Ss][Pp][Oo][Nn][Ss][Ee]
lazyaw		[Ll][Aa][Zz][Yy][Aa][Ww]
all		[Aa][Ll][Ll]
delay		-?[0-9]+[smhdw]?
qstring		"\""([^"\n]|\\\")+"\""
regex		"/"([^/\n]|\\"/")+"/"
dumpfreq	[Dd][Uu][Mm][Pp][Ff][Rr][Ee][Qq]:?
binddn		[Bb][Ii][Nn][Dd][Dd][Nn]
bindpw		[Bb][Ii][Nn][Dd][Pp][Ww]
timeout		[Tt][Ii][Mm][Ee][Oo][Uu][Tt]:?
time		[Tt][Ii][Mm][Ee]
domain		[Dd][Oo][Mm][Aa][Ii][Nn]:?
syncaddr	[Ss][Yy][Nn][Cc][Aa][Dd][Dd][Rr]:?
syncsrcaddr	[Ss][Yy][Nn][Cc][Ss][Rr][Cc][Aa][Dd][Dd][Rr]:?
syncmaxqlen	[Ss][Yy][Nn][Cc][Mm][Aa][Xx][Qq][Ll][Ee][Nn]:?
port		[Pp][Oo][Rr][Tt]
acl		[Aa][Cc][Ll]
racl		[Rr][Aa][Cc][Ll]
dacl		[Dd][Aa][Cc][Ll]
whitelist	[Ww][Hh][Ii][Tt][Ee][Ll][Ii][Ss][Tt]:?
blacklist	[Bb][Ll][Aa][Cc][Kk][Ll][Ii][Ss][Tt]:?
default		[Dd][Ee][Ff][Aa][Uu][Ll][Tt]
drac		[Dd][Rr][Aa][Cc]
db		[Dd][Bb]
nodrac		[Nn][Oo][Dd][Rr][Aa][Cc]
dump_no_time_translation [Dd][Uu][Mm][Pp]_[Nn][Oo]_[Tt][Ii][Mm][Ee]_[Tt][Rr][Aa][Nn][Ss][Ll][Aa][Tt][Ii][Oo][Nn]
logexpired    [Ll][Oo][Gg][Ee][Xx][Pp][Ii][Rr][Ee][Dd]
dnsrbl		[Dd][Nn][Ss][Rr][Bb][Ll]
sm_macro	[Ss][Mm]_[Mm][Aa][Cc][Rr][Oo]
urlcheck	[Uu][Rr][Ll][Cc][Hh][Ee][Cc][Kk]
postmsg		[Pp][Oo][Ss][Tt][Mm][Ss][Gg]
getprop		[Gg][Ee][Tt][Pp][Rr][Oo][Pp]
fork		[Ff][Oo][Rr][Kk]
clear		[Cc][Ll][Ee][Aa][Rr]
unset		[Uu][Nn][Ss][Ee][Tt]
list		[Ll][Ii][Ss][Tt]
flushaddr	[Ff][Ll][Uu][Ss][Hh][Aa][Dd][Dd][Rr]
nolog		[Nn][Oo][Ll][Oo][Gg]
code		[Cc][Oo][Dd][Ee]
ecode		[Ee][Cc][Oo][Dd][Ee]
msg		[Mm][Ss][Gg]
header		[Hh][Ee][Aa][Dd][Ee][Rr]
addheader	[Aa][Dd][Dd][Hh][Ee][Aa][Dd][Ee][Rr]
body		[Bb][Oo][Dd][Yy]
maxpeek		[Mm][Aa][Xx][Pp][Ee][Ee][Kk]
geoipdb		[Gg][Ee][Oo][Ii][Pp][Dd][Bb]
geoip		[Gg][Ee][Oo][Ii][Pp]
ldapconf	[Ll][Dd][Aa][Pp][Cc][Oo][Nn][Ff]
ldapcheck	[Ll][Dd][Aa][Pp][Cc][Hh][Ee][Cc][Kk]
logfac		[Ll][Oo][Gg][Ff][Aa][Cc]
log_kern	[Kk][Ee][Rr][Nn]
log_user	[Uu][Ss][Ee][Rr]
log_mail	[Mm][Aa][Ii][Ll]
log_daemon	[Dd][Aa][Ee][Mm][Oo][Nn]
log_auth	[Aa][Uu][Tt][Hh]
log_syslog	[Ss][Yy][Ss][Ll][Oo][Gg]
log_lpr		[Ll][Pp][Rr]
log_news	[Nn][Ee][Ww][Ss]
log_uucp	[Uu][Uu][Cc][Pp]
log_cron	[Cc][Rr][Oo][Nn]
log_authpriv	[Aa][Uu][Tt][Hh][Pp][Rr][Ii][Vv]
log_ftp		[Ff][Tt][Pp]
log_local0	[Ll][Oo][Cc][Aa][Ll]0
log_local1	[Ll][Oo][Cc][Aa][Ll]1
log_local2	[Ll][Oo][Cc][Aa][Ll]2
log_local3	[Ll][Oo][Cc][Aa][Ll]3
log_local4	[Ll][Oo][Cc][Aa][Ll]4
log_local5	[Ll][Oo][Cc][Aa][Ll]5
log_local6	[Ll][Oo][Cc][Aa][Ll]6
log_local7	[Ll][Oo][Cc][Aa][Ll]7

p0fsock		[Pp]0[Ff][Ss][Oo][Cc][Kk]
p0f		[Pp]0[Ff]
spamdsock	[Ss][Pp][Aa][Mm][Dd][Ss][Oo][Cc][Kk]
spamdsockt	[Ii][Nn][Ee][Tt]|[Uu][Nn][Ii][Xx]
spamd		[Ss][Pp][Aa][Mm][Dd]
openlist	"{"
closelist	"}"
nextln		"\\".*"\n"
star		"*"
slash		"/"
minus		"-"
comma		","
eq		"=="
ne		"!="
ge		">="
le		"<="
gt		">"
lt		"<"
no		[Nn][Oo]
not		[Nn][Oo][Tt]
neg		"!"
prop		"$"[-_A-Za-z0-9]+
domainexact	[Dd][Oo][Mm][Aa][Ii][Nn][Ee][Xx][Aa][Cc][Tt]

%s S_REGEX 
%s S_SPF
%s S_DKIM
%x S_LOGFAC
%x S_CLOCKSPEC1 S_CLOCKSPEC2


%{
	#include "config.h"

	#ifdef HAVE_SYS_CDEFS_H
	#ifndef HAVE_BROKEN_RCSID
	#include <sys/cdefs.h>
	#ifdef __RCSID
	__RCSID("$Id: conf_lex.l,v 1.90 2009/06/08 23:40:06 manu Exp $");
	#endif
	#endif
	#endif

	#include <string.h>
	#include <errno.h>
	#include <sysexits.h>
	#ifdef USE_DMALLOC
	#include <dmalloc.h> 
	#endif

	#define YY_NO_UNPUT

	int conf_line;
	int conf_acl_end;
	int conf_racl_end;
	int conf_dacl_end;
%}

%%
<*>{blank}
{comment}
{eq}		{	yylval.op = OP_EQ; return OP; }
{ne}		{	yylval.op = OP_NE; return OP; }
{lt}		{	yylval.op = OP_LT; return OP; }
{gt}		{	yylval.op = OP_GT; return OP; }
{le}		{	yylval.op = OP_LE; return OP; }
{ge}		{	yylval.op = OP_GE; return OP; }
<INITIAL>{no}	{ return NO; }
<INITIAL>{not}	{ return NO; }
<INITIAL>{neg}	{ return NO; }
{prop}		{ 
			BEGIN(S_REGEX);
			strncpy(yylval.prop, yytext, QSTRLEN);
			yylval.qstring[QSTRLEN] = '\0';
			return PROP;
		}
{addr}		{ return ADDR; }
{helo}		{ BEGIN(S_REGEX); return HELO; }
{from}		{ BEGIN(S_REGEX); return FROM; }
{rcpt}		{ BEGIN(S_REGEX); return RCPT; }
{peer}		{ return PEER; }
{autowhite}	{ return AUTOWHITE; }
{lazyaw}	{ return LAZYAW; }
{greylist}	{ return GREYLIST; }
{noauth}	{ return NOAUTH; }
{auth}		{ BEGIN(S_REGEX); return AUTH; }
{tls}		{ BEGIN(S_REGEX); return TLS; }
{msgsize}	{ return MSGSIZE; }
{rcptcount}	{ return RCPTCOUNT; }
{noaccessdb}	{ return NOACCESSDB; }
{extendedregex}	{ return EXTENDEDREGEX; }
{delayedreject}	{ return DELAYEDREJECT; }
{nospf}		{ return NOSPF; }
{spf}		{ BEGIN(S_SPF); return SPF; }
{dkimcheck}	{ BEGIN(S_DKIM); return DKIMCHECK; }
{pass}		{ BEGIN(0); 
		  yylval.spf_status = MGSPF_PASS; return SPF_STATUS; }
{fail}		{ BEGIN(0); 
		  yylval.spf_status = MGSPF_FAIL; return SPF_STATUS; }
{softfail}	{ BEGIN(0); 
		  yylval.spf_status = MGSPF_SOFTFAIL; return SPF_STATUS; }
{neutral}	{ BEGIN(0); 
		  yylval.spf_status = MGSPF_NEUTRAL; return SPF_STATUS; }
{unknown}	{ BEGIN(0); 
		  yylval.spf_status = MGSPF_UNKNOWN; return SPF_STATUS; }
{error}		{ BEGIN(0); 
		  yylval.spf_status = MGSPF_ERROR; return SPF_STATUS; }
<S_SPF>{self}	{ BEGIN(0); 
		  yylval.spf_status = MGSPF_SELF; return SPF_STATUS; }
<S_SPF>{none}	{ BEGIN(0); 
		  yylval.spf_status = MGSPF_NONE; return SPF_STATUS; }
{quiet}		{ return QUIET; }
{testmode}	{ return TESTMODE; }
{verbose}	{ return VERBOSE; }
{dump_no_time_translation}	{ return DUMP_NO_TIME_TRANSLATION; }
{logexpired}  { return LOGEXPIRED; }
{dnsrbl}  	{ return DNSRBL; }
{sm_macro}  	{ BEGIN(S_REGEX); return SM_MACRO; }
{urlcheck}  	{ return URLCHECK; }
{postmsg}	{ return POSTMSG; }
{getprop}	{ return GETPROP; }
{clear}		{ return CLEAR; }
{fork}		{ return FORK; }
{unset}  	{ return UNSET; }
{list}  	{ return LIST; }
{flushaddr}  	{ return FLUSHADDR; }
{nolog}  	{ return NOLOG; }
{code}  	{ return CODE; }
{ecode}  	{ return ECODE; }
{msg}	  	{ return MSG; }
{header}	{ BEGIN(S_REGEX); return GLHEADER; }
{addheader}	{ return ADDHEADER; }
{body}		{ BEGIN(S_REGEX); return BODY; }
{maxpeek}	{ return MAXPEEK; }
{geoipdb}	{ return GEOIPDB; }
{geoip}		{ return GEOIP; }
{ldapconf}	{ return LDAPCONF; }
{ldapcheck}	{ return LDAPCHECK; }
{p0fsock}	{ return P0FSOCK; }
{p0f}		{ BEGIN(S_REGEX); return P0F; }
{spamdsock}	{ return SPAMDSOCK; }
{spamdsockt}	{ 
			strncpy(yylval.spamdsockt, yytext, QSTRLEN);
			yylval.spamdsockt[QSTRLEN] = '\0';
			return SPAMDSOCKT;
		}
{spamd}		{ return SPAMD; }
{pidfile}	{ return PIDFILE; }
{dumpfile}	{ return GLDUMPFILE; }
{subnetmatch}	{ return SUBNETMATCH; }
{subnetmatch6}	{ return SUBNETMATCH6; }
{socket}	{ return SOCKET; }
{user}		{ return USER; }
{nodetach}	{ return NODETACH; }
{logfac}	{ BEGIN(S_LOGFAC); return LOGFAC; }
<S_LOGFAC>{log_kern}	{ BEGIN(0); return LOGFAC_KERN; }
<S_LOGFAC>{log_user}	{ BEGIN(0); return LOGFAC_USER; }
<S_LOGFAC>{log_mail}	{ BEGIN(0); return LOGFAC_MAIL; }
<S_LOGFAC>{log_daemon}	{ BEGIN(0); return LOGFAC_DAEMON; }
<S_LOGFAC>{log_auth}	{ BEGIN(0); return LOGFAC_AUTH; }
<S_LOGFAC>{log_syslog}	{ BEGIN(0); return LOGFAC_SYSLOG; }
<S_LOGFAC>{log_lpr}	{ BEGIN(0); return LOGFAC_LPR; }
<S_LOGFAC>{log_news}	{ BEGIN(0); return LOGFAC_NEWS; }
<S_LOGFAC>{log_uucp}	{ BEGIN(0); return LOGFAC_UUCP; }
<S_LOGFAC>{log_cron}	{ BEGIN(0); return LOGFAC_CRON; }
<S_LOGFAC>{log_authpriv}	{ BEGIN(0); return LOGFAC_AUTHPRIV; }
<S_LOGFAC>{log_ftp}	{ BEGIN(0); return LOGFAC_FTP; }
<S_LOGFAC>{log_local0}	{ BEGIN(0); return LOGFAC_LOCAL0; }
<S_LOGFAC>{log_local1}	{ BEGIN(0); return LOGFAC_LOCAL1; }
<S_LOGFAC>{log_local2}	{ BEGIN(0); return LOGFAC_LOCAL2; }
<S_LOGFAC>{log_local3}	{ BEGIN(0); return LOGFAC_LOCAL3; }
<S_LOGFAC>{log_local4}	{ BEGIN(0); return LOGFAC_LOCAL4; }
<S_LOGFAC>{log_local5}	{ BEGIN(0); return LOGFAC_LOCAL5; }
<S_LOGFAC>{log_local6}	{ BEGIN(0); return LOGFAC_LOCAL6; }
<S_LOGFAC>{log_local7}	{ BEGIN(0); return LOGFAC_LOCAL7; }
<S_LOGFAC>{none}	{ BEGIN(0); return NONE; }
{report}	{ return REPORT; }
<INITIAL>{none}	{ return NONE; }
{stat}		{ return STAT; }
{delays}	{ return DELAYS; }
{nodelays}	{ return NODELAYS; }
{gldelay}	{ return GLXDELAY; }
{tarpit}	{ return TARPIT; }
{tarpitmode}	{ return TARPITMODE; }
{persession}	{ return PERSESSION; }
{perresponse}	{ return PERRESPONSE; }
{all}		{ return ALL; }
{dumpfreq}	{ return GLDUMPFREQ; }
{timeout}	{ return GLTIMEOUT; }
{binddn}	{ return LDAPBINDDN; }
{bindpw}	{ return LDAPBINDPW; }
{time}		{ BEGIN(S_CLOCKSPEC1); return TIME; }
{domain}	{ BEGIN(S_REGEX); return DOMAIN; }
{syncaddr}	{ return SYNCADDR; }
{syncsrcaddr}	{ return SYNCSRCADDR; }
{syncmaxqlen}	{ return SYNCMAXQLEN; }
{port}		{ return PORT; }
{acl}		{ return ACL; }
{racl}		{ return RACL; }
{dacl}		{ return DACL; }
{whitelist}	{ return WHITELIST; }
{blacklist}	{ return BLACKLIST; }
{default}	{ return DEFAULT; }
{domainexact}	{ return DOMAINEXACT; }
<INITIAL>{star}		{ return STAR; }
<S_CLOCKSPEC2>{star}	{ return STAR; }
<S_CLOCKSPEC2>{slash}	{ return SLASH; }
<S_CLOCKSPEC2>{minus}	{ return MINUS; }
<S_CLOCKSPEC2>{comma}	{ return COMMA; }
{drac}		{ return DRAC; }
{nodrac}	{ return NODRAC; }
{db}		{ return DB; }
<INITIAL,S_REGEX>{qstring}	{
			strncpy(yylval.qstring, yytext, QSTRLEN);
			yylval.qstring[QSTRLEN] = '\0';
			return QSTRING;
		}
<S_CLOCKSPEC1>"\""	{ BEGIN(S_CLOCKSPEC2); }
<S_CLOCKSPEC2>"\""	{ BEGIN(0); }
<*>{number}	{
			strncpy(yylval.delay, yytext, NUMLEN);
			yylval.delay[NUMLEN] = '\0';
			return TNUMBER;
		}
{delay}		{
			strncpy(yylval.delay, yytext, NUMLEN);
			yylval.delay[NUMLEN] = '\0';
			return TDELAY;
		}
{email}		{
			strncpy(yylval.email, yytext, ADDRLEN);
			yylval.email[ADDRLEN] = '\0';
			return EMAIL;
		}
{ipaddr}	{ 
			socklen_t salen = sizeof(yylval.ipaddr);

			if (ipfromstring(yytext, SA(&yylval.ipaddr), &salen,
			     AF_INET) != 1)
				REJECT;
			return IPADDR; 
		}
{ip6addr}	{
#ifdef AF_INET6
			socklen_t salen = sizeof(yylval.ip6addr);

			if (ipfromstring(yytext, SA(&yylval.ip6addr), &salen,
			    AF_INET6) != 1) 
				REJECT;
#endif
			return IP6ADDR;
		}
{domainname}	{ 
			strncpy(yylval.domainname, yytext, ADDRLEN);
			yylval.domainname[ADDRLEN] = '\0';
			return DOMAINNAME; 
		}
<S_REGEX>{regex} {
			strncpy(yylval.regex, yytext, REGEXLEN);
			yylval.regex[REGEXLEN] = '\0';
			return REGEX;
		}
{cidr}		{ 
			yylval.cidr = atoi(yytext + 1);
			return CIDR; 
		}
{openlist}	{	return OPENLIST; }
{closelist}	{	return CLOSELIST; }
<*>\n		{ 
			BEGIN(0);
			conf_line++; 
			return yytext[0]; 
		}
{nextln}	{	conf_line++; }
<*>.|\n		{ 
			mg_log(LOG_ERR, "unknown token \"%s\" line %d", 
			    yytext, conf_line); 
			exit(EX_DATAERR);
		}
%%

void
yyerror(err)
	char *err;
{
	mg_log(LOG_ERR, "config error at line %d: %s", conf_line, err);
	exit(EX_DATAERR);
	return;
}

void
conf_dispose_input_file(void) {
	conf__flush_buffer(YY_CURRENT_BUFFER);
}
