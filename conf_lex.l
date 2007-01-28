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
lazyaw		[Ll][Aa][Zz][Yy][Aa][Ww]
all		[Aa][Ll][Ll]
delay		-?[0-9]+[smhdw]?
qstring		"\""[^"\n]+"\""
regex		"/"[^/\n]+"/"
dumpfreq	[Dd][Uu][Mm][Pp][Ff][Rr][Ee][Qq]:?
timeout		[Tt][Ii][Mm][Ee][Oo][Uu][Tt]:?
domain		[Dd][Oo][Mm][Aa][Ii][Nn]:?
syncaddr	[Ss][Yy][Nn][Cc][Aa][Dd][Dd][Rr]:?
syncsrcaddr	[Ss][Yy][Nn][Cc][Ss][Rr][Cc][Aa][Dd][Dd][Rr]:?
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
unset		[Uu][Nn][Ss][Ee][Tt]
list		[Ll][Ii][Ss][Tt]
flushaddr	[Ff][Ll][Uu][Ss][Hh][Aa][Dd][Dd][Rr]
code		[Cc][Oo][Dd][Ee]
ecode		[Ee][Cc][Oo][Dd][Ee]
msg		[Mm][Ss][Gg]
header		[Hh][Ee][Aa][Dd][Ee][Rr]
body		[Bb][Oo][Dd][Yy]
maxpeek		[Mm][Aa][Xx][Pp][Ee][Ee][Kk]
openlist	"{"
closelist	"}"
nextln		"\\".*"\n"
star		"*"
eq		"=="
ne		"!="
ge		">="
le		"<="
gt		">"
lt		"<"
no		[Nn][Oo]
not		[Nn][Oo][Tt]
neg		"!"

%s S_REGEX


%{
	#include "config.h"

	#ifdef HAVE_SYS_CDEFS_H
	#ifndef HAVE_BROKEN_RCSID
	#include <sys/cdefs.h>
	#ifdef __RCSID
	__RCSID("$Id: conf_lex.l,v 1.64 2007/01/28 02:16:33 manu Exp $");
	#endif
	#endif
	#endif

	#include <string.h>
	#include <errno.h>
	#include <sysexits.h>

	#define YY_NO_UNPUT

	int conf_line;
	int conf_acl_end;
	int conf_racl_end;
	int conf_dacl_end;
%}

%%
{blank}
{comment}
{eq}		{	yylval.op = OP_EQ; return OP; }
{ne}		{	yylval.op = OP_NE; return OP; }
{lt}		{	yylval.op = OP_LT; return OP; }
{gt}		{	yylval.op = OP_GT; return OP; }
{le}		{	yylval.op = OP_LE; return OP; }
{ge}		{	yylval.op = OP_GE; return OP; }
{no}		{ return NO; }
{not}		{ return NO; }
{neg}		{ return NO; }
{addr}		{ return ADDR; }
{from}		{ BEGIN(S_REGEX); return FROM; }
{rcpt}		{ BEGIN(S_REGEX); return RCPT; }
{peer}		{ return PEER; }
{autowhite}	{ return AUTOWHITE; }
{lazyaw}	{ return LAZYAW; }
{greylist}	{ return GREYLIST; }
{noauth}	{ return NOAUTH; }
{auth}		{ return AUTH; }
{tls}		{ return TLS; }
{msgsize}	{ return MSGSIZE; }
{rcptcount}	{ return RCPTCOUNT; }
{noaccessdb}	{ return NOACCESSDB; }
{extendedregex}	{ return EXTENDEDREGEX; }
{delayedreject}	{ return DELAYEDREJECT; }
{nospf}		{ return NOSPF; }
{spf}		{ return SPF; }
{quiet}		{ return QUIET; }
{testmode}	{ return TESTMODE; }
{verbose}	{ return VERBOSE; }
{dump_no_time_translation}	{ return DUMP_NO_TIME_TRANSLATION; }
{logexpired}  { return LOGEXPIRED; }
{dnsrbl}  	{ return DNSRBL; }
{sm_macro}  	{ BEGIN(S_REGEX); return SM_MACRO; }
{urlcheck}  	{ return URLCHECK; }
{postmsg}	{ return POSTMSG; }
{unset}  	{ return UNSET; }
{list}  	{ return LIST; }
{flushaddr}  	{ return FLUSHADDR; }
{code}  	{ return CODE; }
{ecode}  	{ return ECODE; }
{msg}	  	{ return MSG; }
{header}	{ BEGIN(S_REGEX); return HEADER; }
{body}		{ BEGIN(S_REGEX); return BODY; }
{maxpeek}	{ return MAXPEEK; }
{pidfile}	{ return PIDFILE; }
{dumpfile}	{ return GLDUMPFILE; }
{subnetmatch}	{ return SUBNETMATCH; }
{subnetmatch6}	{ return SUBNETMATCH6; }
{socket}	{ return SOCKET; }
{user}		{ return USER; }
{nodetach}	{ return NODETACH; }
{report}	{ return REPORT; }
{stat}		{ return STAT; }
{none}		{ return NONE; }
{delays}	{ return DELAYS; }
{nodelays}	{ return NODELAYS; }
{gldelay}	{ return GLXDELAY; }
{all}		{ return ALL; }
{dumpfreq}	{ return GLDUMPFREQ; }
{timeout}	{ return GLTIMEOUT; }
{domain}	{ BEGIN(S_REGEX); return DOMAIN; }
{syncaddr}	{ return SYNCADDR; }
{syncsrcaddr}	{ return SYNCSRCADDR; }
{port}		{ return PORT; }
{acl}		{ return ACL; }
{racl}		{ return RACL; }
{dacl}		{ return DACL; }
{whitelist}	{ return WHITELIST; }
{blacklist}	{ return BLACKLIST; }
{default}	{ return DEFAULT; }
{star}		{ return STAR; }
{drac}		{ return DRAC; }
{nodrac}	{ return NODRAC; }
{db}		{ return DB; }
{qstring}	{
			strncpy(yylval.qstring, yytext, QSTRLEN);
			yylval.qstring[QSTRLEN] = '\0';
			return QSTRING;
		}
{number}	{
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
\n		{ 
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
	YY_FLUSH_BUFFER;
}
