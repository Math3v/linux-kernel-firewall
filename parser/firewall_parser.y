%{
#include <iostream>
#include <list>
using namespace std;

#include <string.h>
#include "firewall.h"

extern "C" int yylex();
extern "C" FILE *yyin;
extern int line_num;

struct rules_t;
rule_t rule;
std::list<rule_t> rulesList;
 
void yyerror(const char *s);
%}

%union {
	int ival;
	char *sval;
};

%token <ival> INT
%token <sval> STRING
%token <line_num> ENDL
%token <sval> ACTION
%token <sval> PROTO
%token <sval> IP

%token SRCPORT
%token DSTPORT
%token FROM
%token DEST

%start all

%%

all:
	all line
	| line
	;

line:
	base endl
	| base srcport endl
	| base dstport endl
	| base srcport dstport endl
	;
base:
	INT ACTION PROTO FROM IP DEST IP {
	 rule.id = $1;
	 rule.action = strdup($2);
	 rule.proto = strdup($3);
	 rule.src_ip = strdup($5);
	 rule.dst_ip = strdup($7);
	 }
	;
srcport:
	SRCPORT INT { 
		rule.src_port = $2;
	}
	;
dstport:
	DSTPORT INT { 
		rule.dst_port = $2;
	}
	;
endl:
	ENDL { 
		rulesList.push_back(rule);

		/* Clean up rule */
		rule.id = 0;
		rule.action = strdup("");
		rule.proto = strdup("");
		rule.src_ip = strdup("");
		rule.dst_ip = strdup("");
		rule.src_port = 0;
		rule.dst_port = 0;
	}
	;
%%
