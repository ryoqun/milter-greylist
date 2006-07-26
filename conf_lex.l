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
noaccessdb	[Nn][Oo][Aa][Cc][Cc][Ee][Ss][Ss][Dd][Bb]
extendedregex	[Ee][Xx][Tt][Ee][Nn][Dd][Ee][Dd][Rr][Ee][Gg][Ee][Xx]
nospf		[Nn][Oo][Ss][Pp][Ff]
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
whitelist	[Ww][Hh][Ii][Tt][Ee][Ll][Ii][Ss][Tt]:?
default		[Dd][Ee][Ff][Aa][Uu][Ll][Tt]
drac		[Dd][Rr][Aa][Cc]
db		[Dd][Bb]
nodrac		[Nn][Oo][Dd][Rr][Aa][Cc]
dump_no_time_translation [Dd][Uu][Mm][Pp]_[Nn][Oo]_[Tt][Ii][Mm][Ee]_[Tt][Rr][Aa][Nn][Ss][Ll][Aa][Tt][Ii][Oo][Nn]
logexpired    [Ll][Oo][Gg][Ee][Xx][Pp][Ii][Rr][Ee][Dd]
dnsrbl		[Dd][Nn][Ss][Rr][Bb][Ll]
star		"*"

%s S_REGEX


%{
	#include "config.h"

	#ifdef HAVE_SYS_CDEFS_H
	#ifndef HAVE_BROKEN_RCSID
	#include <sys/cdefs.h>
	#ifdef __RCSID
	__RCSID("$Id: conf_lex.l,v 1.44 2006/07/26 13:03:11 manu Exp $");
	#endif
	#endif
	#endif

	#include <string.h>
	#include <errno.h>
	#include <sysexits.h>

	#define YY_NO_UNPUT

	int conf_line = 1;
%}

%%
{blank}
{comment}
{addr}		{ return ADDR; }
{from}		{ BEGIN(S_REGEX); return FROM; }
{rcpt}		{ BEGIN(S_REGEX); return RCPT; }
{peer}		{ return PEER; }
{autowhite}	{ return AUTOWHITE; }
{lazyaw}	{ return LAZYAW; }
{greylist}	{ return GREYLIST; }
{noauth}	{ return NOAUTH; }
{noaccessdb}	{ return NOACCESSDB; }
{extendedregex}	{ return EXTENDEDREGEX; }
{delayedreject}	{ return DELAYEDREJECT; }
{nospf}		{ return NOSPF; }
{quiet}		{ return QUIET; }
{testmode}	{ return TESTMODE; }
{verbose}	{ return VERBOSE; }
{dump_no_time_translation}	{ return DUMP_NO_TIME_TRANSLATION; }
{logexpired}  { return LOGEXPIRED; }
{dnsrbl}  	{ return DNSRBL; }
{pidfile}	{ return PIDFILE; }
{dumpfile}	{ return GLDUMPFILE; }
{subnetmatch}	{ return SUBNETMATCH; }
{subnetmatch6}	{ return SUBNETMATCH6; }
{socket}	{ return SOCKET; }
{user}		{ return USER; }
{nodetach}	{ return NODETACH; }
{report}	{ return REPORT; }
{none}		{ return NONE; }
{delays}	{ return DELAYS; }
{nodelays}	{ return NODELAYS; }
{gldelay}	{ return GLDELAY; }
{all}		{ return ALL; }
{dumpfreq}	{ return GLDUMPFREQ; }
{timeout}	{ return GLTIMEOUT; }
{domain}	{ BEGIN(S_REGEX); return DOMAIN; }
{syncaddr}	{ return SYNCADDR; }
{syncsrcaddr}	{ return SYNCSRCADDR; }
{port}		{ return PORT; }
{acl}		{ return ACL; }
{whitelist}	{ return WHITELIST; }
{default}	{ return DEFAULT; }
{star}		{ return STAR; }
{drac}		{ return DRAC; }
{nodrac}	{ return NODRAC; }
{db}		{ return DB; }
{qstring}	{
			strncpy(yylval.qstring, yytext, PATHLEN);
			yylval.qstring[PATHLEN] = '\0';
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
			yylval.regex[PATHLEN] = '\0';
			return REGEX;
		}
{cidr}		{ 
			yylval.cidr = atoi(yytext + 1);
			return CIDR; 
		}
\n		{ 
			BEGIN(0);
			conf_line++; 
			return yytext[0]; 
		}
<*>.|\n		{ 
			printf("unknown token \"%s\" line %d\n", 
			    yytext, conf_line); 
			exit(EX_DATAERR);
		}
%%

void
yyerror(err)
	char *err;
{
	fprintf(stderr, "config error at line %d: %s\n", conf_line, err);
	return;
}
