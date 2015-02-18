%{
#include <cstdio>
#include <iostream>
using namespace std;

// stuff from flex that bison needs to know about:
extern "C" int yylex();
extern "C" int yyparse();
extern "C" FILE *yyin;
extern int line_num;
 
void yyerror(const char *s);
%}

// Bison fundamentally works by asking flex to get the next token, which it
// returns as an object of type "yystype".  But tokens could be of any
// arbitrary data type!  So we deal with that in Bison by defining a C union
// holding each of the types of tokens that Flex could return, and have Bison
// use that union instead of "int" for the definition of "yystype":
%code requires{
		struct rules_t {
		int id;
		char *action;
		char *proto;
		unsigned int src_ip;
		unsigned int dst_ip;
		unsigned short src_port;
		unsigned short dst_port;
	};
}
%union {
	int ival;
	float fval;
	char *sval;
	unsigned int ipval;
	int portval;
	rules_t rules;
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
	;
snazzle:
	INT ACTION PROTO FROM SRCIP DEST SRCIP { cout << "all matched: " << endl; }
	;
srcport:
	SRCPORT INT { cout << "srcport: " << $2 << endl; }
	;
dstport:
	DSTPORT INT { cout << "dstport: " << $2 << endl; }
	;
endl:
	ENDL { ; }
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
	// set flex to read from it instead of defaulting to STDIN:
	yyin = myfile;
	
	// parse through the input until there is no more:
	do {
		yyparse();
	} while (!feof(yyin));
	
}

void yyerror(const char *s) {
	cout << "EEK, parse error!  Message: " << s << " on line: " << line_num << endl;
	// might as well halt now:
	exit(-1);
}

