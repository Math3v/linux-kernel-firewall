%option interactive
%{
#define YY_DECL extern "C" int yylex()

#include <stdio.h>
#include <string.h>

#include "snazzle.tab.h"
int line_num = 1;
%}
%%
[ \t]									;
[0-9]+									{ yylval.ival = atoi(yytext);   return INT;		}
([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|any)	{ yylval.sval = strdup(yytext); return SRCIP;	}
(allow|deny)							{ yylval.sval = strdup(yytext); return ACTION;	}
(tcp|udp|icmp|ip)						{ yylval.sval = strdup(yytext); return PROTO;	}
from									{ return FROM;									}
to										{ return DEST;									}	
src-port								{ return SRCPORT;								}
dst-port								{ return DSTPORT;								}
\n										{ ++line_num; return ENDL; 						}
.										;
%%