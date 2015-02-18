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
[0-9]+\ (allow|deny)\ (tcp|udp|icmp|ip)\ from\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)\ to\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)[[:space:]]?(src-port\ [0-9]+[[:space:]]?)*(dst-port\ [0-9]+)* {
	cout << "flex found: " << yytext << endl;
	token = strtok(yytext, delim);
	while(token != NULL){
		cout << "token '" << token << "' ";
		token = strtok(NULL, delim);
	}
}
.                ;
%%