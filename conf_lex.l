%option nodefault
%option nomain
%option noyywrap
%option prefix="conf_"

byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
cidr		{byte}
email		[A-Za-z0-9\.\-_+]+"\@"[A-Za-z0-9\.\-_+]+
comment		#.*$
blank		[ \t]{1,}
addr		[Aa][Dd][Dd][Rr]:?
from		[Ff][Rr][Oo][Mm]:?
rcpt		[Rr][Cc][Pp][Tt]:?
peer		[Pp][Ee][Ee][Rr]:?

%{
	#include <sys/cdefs.h>
	#ifdef __RCSID
	__RCSID("$Id: conf_lex.l,v 1.2 2004/03/11 14:12:48 manu Exp $");
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
"/"		{ return yytext[0]; }
{addr}		{ return ADDR; }
{from}		{ return FROM; }
{rcpt}		{ return RCPT; }
{peer}		{ return PEER; }
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
{cidr}		{ 
			yylval.cidr = atoi(yytext);
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