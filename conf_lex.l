%option nodefault
%option nomain
%option noyywrap
%option prefix="conf_"

byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
cidr		"/"{byte}
atext		[A-Za-z0-9!#$%&'*+/=?$^_`}{|~.-]{1,}
qtext		"\""[!-~]{1,}"\""
mailbox		{atext}|{qtext}
domainname	[A-Za-z0-9._-]{1,}
email		{mailbox}"\@"{domainname}
comment		#.*$
blank		[ \t]{1,}
addr		[Aa][Dd][Dd][Rr]:?
from		[Ff][Rr][Oo][Mm]:?
rcpt		[Rr][Cc][Pp][Tt]:?
peer		[Pp][Ee][Ee][Rr]:?
verbose		[Vv][Ee][Rr][Bb][Oo][Ss][Ee]
quiet		[Qq][Uu][Ii][Ee][Tt]
noauth		[Nn][Oo][Aa][Uu][Tt][Hh]
nospf		[Nn][Oo][Ss][Pp][Ff]
testmode	[Tt][Ee][Ss][Tt][Mm][Oo][Dd][Ee]
greylist	[Gg][Rr][Ee][Yy][Ll][Ii][Ss][Tt]:?		
autowhite	[Aa][Uu][Tt][Oo][Ww][Hh][Ii][Tt][Ee]:?
pidfile		[Pp][Ii][Dd][Ff][Ii][Ll][Ee]:?
dumpfile	[Dd][Uu][Mm][Pp][Ff][Ii][Ll][Ee]:?
subnetmatch	[Ss][Uu][Bb][Nn][Ee][Tt][Mm][Aa][Tt][Cc][Hh]:?
socket		[Ss][Oo][Cc][Kk][Ee][Tt]:?
user		[Uu][Ss][Ee][Rr]:?
nodetach	[Nn][Oo][Dd][Ee][Tt][Aa][Cc][Hh]
report		[Rr][Ee][Pp][Oo][Rr][Tt]:?
none		[Nn][Oo][Nn][Ee]
delays		[Dd][Ee][Ll][Aa][Yy][Ss]
nodelays	[Nn][Oo][Dd][Ee][Ll][Aa][Yy][Ss]
lazyaw		[Ll][Aa][Zz][Yy][Aa][Ww]
all		[Aa][Ll][Ll]
delay		-?[0-9]{1,}[smhdw]?
path		"\""[^"\n]{1,}"\""
regex		"/"[^/\n]{1,}"/"
dumpfreq	[Dd][Uu][Mm][Pp][Ff][Rr][Ee][Qq]:?
timeout		[Tt][Ii][Mm][Ee][Oo][Uu][Tt]:?
domain		[Dd][Oo][Mm][Aa][Ii][Nn]:?

%{
	#include "config.h"

	#ifdef HAVE_SYS_CDEFS_H
	#ifndef HAVE_BROKEN_RCSID
	#include <sys/cdefs.h>
	#ifdef __RCSID
	__RCSID("$Id: conf_lex.l,v 1.24 2004/05/28 23:35:14 manu Exp $");
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
{from}		{ return FROM; }
{rcpt}		{ return RCPT; }
{peer}		{ return PEER; }
{autowhite}	{ return AUTOWHITE; }
{lazyaw}	{ return LAZYAW; }
{greylist}	{ return GREYLIST; }
{noauth}	{ return NOAUTH; }
{nospf}		{ return NOSPF; }
{quiet}		{ return QUIET; }
{testmode}	{ return TESTMODE; }
{verbose}	{ return VERBOSE; }
{pidfile}	{ return PIDFILE; }
{dumpfile}	{ return GLDUMPFILE; }
{subnetmatch}	{ return SUBNETMATCH; }
{socket}	{ return SOCKET; }
{user}		{ return USER; }
{nodetach}	{ return NODETACH; }
{report}	{ return REPORT; }
{none}		{ return NONE; }
{delays}	{ return DELAYS; }
{nodelays}	{ return NODELAYS; }
{all}		{ return ALL; }
{dumpfreq}	{ return DUMPFREQ; }
{timeout}	{ return TIMEOUT; }
{domain}	{ return DOMAIN; }
{path}		{
			strncpy(yylval.path, yytext, PATHLEN);
			yylval.path[PATHLEN] = '\0';
			return PATH;
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
			if (inet_pton(AF_INET, yytext, &yylval.ipaddr) != 1) {
				printf("invalid IP address line %d\n", 
				    conf_line);
				exit(EX_DATAERR);
			}
			return IPADDR; 
		}
{domainname}	{ 
			strncpy(yylval.domainname, yytext, ADDRLEN);
			yylval.domainname[ADDRLEN] = '\0';
			return DOMAINNAME; 
		}
{regex}		{
			strncpy(yylval.regex, yytext, REGEXLEN);
			yylval.regex[PATHLEN] = '\0';
			return REGEX;
		}
{cidr}		{ 
			yylval.cidr = atoi(yytext + 1);
			return CIDR; 
		}
\n		{ 
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
	fprintf(stderr, "error at line %d: %s\n", conf_line, err);
	return;
}
