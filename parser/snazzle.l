%{
#define YY_DECL extern "C" int yylex()

#include <stdio.h>
#include <string.h>

#include "snazzle.tab.h"

const char delim[2] = " ";
char *token;

%}
%%
[ \t\n]          ;
[0-9]+\ (allow|deny)\ (tcp|udp|icmp|ip)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)\ to\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)(\n|[[:space:]])?(src-port\ [0-9]+[[:space:]]?)*(\n)?(dst-port\ [0-9]+)*(\n)? {
	printf("flex found: %s", yytext);
	yylval.sval = strdup("OK");
	token = strtok(yytext, delim);
	while(token != NULL){
		//printf("token '%s'\n", token);
		token = strtok(NULL, delim);
	}
	//printf("\n");
	return STRING;
}
.                ;
%%