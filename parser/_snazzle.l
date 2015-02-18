%{
#include <iostream>
using namespace std;
#define YY_DECL extern "C" int yylex()

#include "snazzle.tab.h"
#include <string.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/socket.h>

const char delim[2] = " ";
char *token;
struct sockaddr_in sa;
%}
%%
[ \t\n]          ;
[0-9]+\.[0-9]+   { yylval.fval = atof(yytext); return FLOAT; }
[0-9]+           { yylval.ival = atoi(yytext); return INT; }
[a-zA-Z0-9]+     { yylval.sval = strdup(yytext); return STRING; }
ipaddr\ [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ { 
token = strtok(yytext, delim); token = strtok(NULL, delim); /* ... TODO ... */
inet_pton(AF_INET, token, &(sa.sin_addr)); cout << "flex addr: " << std::hex << sa.sin_addr.s_addr << endl; }
port\ [0-9]+	 { 
token = strtok(yytext, delim); token = strtok(NULL, delim); yylval.portval = atoi(token); return PORT; }
[0-9]+\ (allow|deny)\ (tcp|udp|icmp|ip)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)\ to\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)[[:space:]]?(src-port\ [0-9]+[[:space:]]?)*(dst-port\ [0-9]+)* {
	cout << "flex found: " << yytext << endl;
}
.                ;
%%
/*main() {
	
	// open a file handle to a particular file:
	FILE *myfile = fopen("a.snazzle.file", "r");
	// make sure it's valid:
	if (!myfile) {
		cout << "I can't open a.snazzle.file!" << endl;
		return -1;
	}
	// set lex to read from it instead of defaulting to STDIN:
	yyin = myfile;
	
	// lex through the input:
	yylex();
}*/
