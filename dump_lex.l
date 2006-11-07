%option nodefault
%option nomain
%option noyywrap
%option prefix="dump_"

num		[0-9]{1,}
byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
ip6addr		([0-9a-fA-F]*:){2,}[0-9a-fA-F]*(%[0-9a-zA-Z]+)?
atext		[A-Za-z0-9!#$%&'*+/=?$^_`}{|~.-]{1,}
qtext		"\""[!-~]{1,}"\""
mailbox		{atext}|{qtext}
domain		[A-Za-z0-9._-]{1,}
email		"<"?{mailbox}"\@"?{domain}?">"?
void_email	"<>"
comment		#.*$
blank		[ \t]{1,}
auto		[Aa][Uu][Tt][Oo]

%{
	#include "config.h"

	#ifdef HAVE_SYS_CDEFS_H
	#ifndef HAVE_BROKEN_RCSID
	#include <sys/cdefs.h>
	#ifdef __RCSID  
	__RCSID("$Id: dump_lex.l,v 1.17.2.2 2006/11/07 05:12:11 manu Exp $");
	#endif
	#endif
	#endif

	#include <string.h>
	#include <errno.h>
	#include <syslog.h>
	#include <sysexits.h>

	#define YY_NO_UNPUT

	int dump_line = 1;
%}

%%
{auto}		{ return AUTO; }
{blank}
{comment}
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
{num}		{ 
			yylval.time = atoi(yytext);
			return TIME; 
		}
{email}|{void_email} {
			strncpy(yylval.email, yytext, ADDRLEN);
			yylval.email[ADDRLEN] = '\0';
			return EMAIL;
		}
\n		{ 
			dump_line++; 
			return yytext[0]; 
		}
<*>.|\n		{ 
			mg_log(LOG_DEBUG, 
			    "unknown token \"%s\" line %d, skipping\n", 
			    yytext, dump_line); 
			return GARBAGE;
		}
%%

void
yyerror(err)
	char *err;
{
	mg_log(LOG_DEBUG, "dump error at line %d: %s\n", dump_line, err);
	return;
}
