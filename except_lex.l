%option nodefault
%option nomain
%option noyywrap
%option prefix="except_"

byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
cidr		{byte}
email		[A-Za-z0-9\.\-_+]+"\@"[A-Za-z0-9\.\-_+]+
comment		#.*$
blank		[ \t]{1,}
addr		[Aa][Dd][Dd][Rr]:?
from		[Ff][Rr][Oo][Mm]:?
rcpt		[Tt][Oo]:?

%{
	#include <string.h>
	#include <sysexits.h>

	int except_line = 1;
	char ipaddr[IPADDRLEN + 1];
	char cidr[IPADDRLEN + 1];
	char email[ADDRLEN + 1];
%}

%%
{blank}
{comment}
"/"		{ return yytext[0]; }
{addr}		{ return ADDR; }
{from}		{ return FROM; }
{rcpt}		{ return RCPT; }
{email}		{
			strncpy(email, yytext, ADDRLEN);
			yylval.email = email;
			return EMAIL;
		}
{ipaddr}	{ 
			strncpy(ipaddr, yytext, IPADDRLEN); 
			if (inet_aton(ipaddr, &yylval.ipaddr) != 1) {
				printf("invalid IP address line %d\n", 
				    except_line);
				exit(EX_DATAERR);
			}
			return IPADDR; 
		}
{cidr}		{ 
			strncpy(cidr, yytext, IPADDRLEN); 
			yylval.cidr = atoi(cidr);
			return CIDR; 
		}
\n		{ 
			except_line++; 
			return yytext[0]; 
		}
<*>.|\n		{ 
			printf("unknown token \"%s\" line %d\n", 
			    yytext, except_line); 
			exit(EX_DATAERR);
		}
%%

void
yyerror(err)
	char *err;
{
	fprintf(stderr, "error at line %d: %s\n", except_line, err);
	return;
}
