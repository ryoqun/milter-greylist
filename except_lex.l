%option nodefault
%option nomain
%option noyywrap
%option prefix="except_"

byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
cidr		{byte}
comment		#.*$
blank		[ \t]{1,}

%{
	#include <string.h>
	#include <sysexits.h>

	int except_line = 1;
	char ipaddr[15 + 1];
	char cidr[2 + 1];
%}

%%
{blank}
{comment}
{ipaddr}	{ 
			strncpy(ipaddr, yytext, yyleng); 
			if (inet_aton(ipaddr, &yylval.ipaddr) != 1) {
				printf("invalid IP address line %d\n", 
				    except_line);
				exit(EX_DATAERR);
			}
			return IPADDR; 
		}
{cidr}		{ 
			strncpy(cidr, yytext, yyleng); 
			yylval.cidr = atoi(cidr);
			return CIDR; 
		}
"/"		{ return yytext[0]; }
\n		{ except_line++; return yytext[0]; }
<*>.|\n
%%

void
yyerror(err)
	char *err;
{
	fprintf(stderr, "error at line %d: %s\n", except_line, err);
	return;
}
