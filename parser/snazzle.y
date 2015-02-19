%{
#include <cstdio>
#include <iostream>
#include <list>
using namespace std;

#include <string.h>

// stuff from flex that bison needs to know about:
extern "C" int yylex();
extern "C" int yyparse();
extern "C" FILE *yyin;
extern int line_num;

struct rules_t {
	int id;
	char *action;
	char *proto;
	char *src_ip;
	char *dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

std::list<rules_t> rulesList;
rules_t rule;
 
void yyerror(const char *s);
%}

// Bison fundamentally works by asking flex to get the next token, which it
// returns as an object of type "yystype".  But tokens could be of any
// arbitrary data type!  So we deal with that in Bison by defining a C union
// holding each of the types of tokens that Flex could return, and have Bison
// use that union instead of "int" for the definition of "yystype":
%union {
	int ival;
	float fval;
	char *sval;
	unsigned int ipval;
	unsigned short portval;
};

// define the "terminal symbol" token types I'm going to use (in CAPS
// by convention), and associate each with a field of the union:
%token <ival> INT
%token <fval> FLOAT
%token <sval> STRING
%token <ipval> IPADDR
%token <portval> PORT
%token <rules> RULES
%token <line_num> ENDL
%token <sval> ACTION
%token <sval> PROTO
%token <sval> SRCIP

%token SRCPORT
%token DSTPORT
%token FROM
%token DEST

%start all

%%
// this is the actual grammar that bison will parse, but for right now it's just
// something silly to echo to the screen what bison gets from flex.  We'll
// make a real one shortly:
all:
	all line
	| line
	;

line:
	snazzle endl
	| snazzle srcport endl
	| snazzle dstport endl
	| snazzle srcport dstport endl
	;
snazzle:
	INT ACTION PROTO FROM SRCIP DEST SRCIP {
	 //cout << "all matched: " << endl; 
	 rule.id = $1;
	 rule.action = strdup($2);
	 rule.proto = strdup($3);
	 rule.src_ip = strdup($5);
	 rule.dst_ip = strdup($7);
	 }
	;
srcport:
	SRCPORT INT { 
		//cout << "srcport: " << $2 << endl; 
		rule.src_port = $2;
	}
	;
dstport:
	DSTPORT INT { 
		//cout << "dstport: " << $2 << endl; 
		rule.dst_port = $2;
	}
	;
endl:
	ENDL { 
		cout << "RID: " << rule.id << " ";
		cout << "ACTION: " << rule.action << " ";
		cout << "PROTO: " << rule.proto << " "; 
		cout << "SRCIP: " << rule.src_ip << " ";
		cout << "DSTIP: " << rule.dst_ip << " ";

		if(rule.src_port != 0){
			cout << "SCRPORT: " << rule.src_port << " ";
		}
		if(rule.dst_port != 0){
			cout << "DSTPORT: " << rule.dst_port << " ";
		}

		cout << endl;

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
main() {
       // open a file handle to a particular file:
       FILE *myfile = fopen("a.snazzle.file", "r");
       // make sure it is valid:
       if (!myfile) {
               cout << "I can't open a.snazzle.file!" << endl;
               return -1;
       }
       // set flex to read from it instead of defaultingTDIN:
       yyin = myfile;
       
       // parse through the input until there is no more:
       do {
               yyparse();
       } while (!feof(yyin));
       
}

void yyerror(const char *s) {
       cout << "EEK, parse error!  Message: " << s << " on line: " << line_num;
       // might as well halt now:
       exit(-1);
}