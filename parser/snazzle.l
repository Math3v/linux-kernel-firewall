%{
#define YY_DECL extern "C" int yylex()

#include <stdio.h>
#include <string.h>

#include "snazzle.tab.h"
int line_num = 1;
%}
%%
[ \t]          ;
\n 			   { ++line_num; return ENDL; }
[0-9]+\ (allow|deny)\ (tcp|udp|icmp|ip)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)\ to\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)(\n|[[:space:]])?(src-port\ [0-9]+[[:space:]]?)*(\n)?(dst-port\ [0-9]+)*(\n)? {
	yylval.sval = strdup(yytext);
	return STRING;
}
.                ;
%%