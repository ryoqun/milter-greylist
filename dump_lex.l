%option nodefault
%option nomain
%option noyywrap
%option prefix="dump_"

num		[0-9]{1,}
byte		[0-9]{1,3}
ipaddr		{byte}"."{byte}"."{byte}"."{byte}
email		<?[A-Za-z0-9\.\-_+]+"\@"[A-Za-z0-9\.\-_+]+>?
void_email	<>
comment		#.*$
blank		[ \t]{1,}

%{
	#include <string.h>
	#include <errno.h>
	#include <sysexits.h>

	int dump_line = 1;
%}

%%
{blank}
{comment}
{email}|{void_email} {
			yylval.email = yytext;
			return EMAIL;
		}
{ipaddr}	{ 
			if (inet_pton(AF_INET, yytext, &yylval.ipaddr) != 1) {
				printf("invalid IP address line %d\n", 
				    dump_line);
				exit(EX_DATAERR);
			}
			return IPADDR; 
		}
{num}		{ 
			yylval.time = atoi(yytext);
			return TIME; 
		}
\n		{ 
			dump_line++; 
			return yytext[0]; 
		}
<*>.|\n		{ 
			printf("unknown token \"%s\" line %d, skiping\n", 
			    yytext, dump_line); 
		}
%%

void
yyerror(err)
	char *err;
{
	fprintf(stderr, "error at line %d: %s\n", dump_line, err);
	return;
}
