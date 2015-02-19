#include <iostream>
#include <list>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

#include "snazzle.tab.h"
#include "test.h"

//extern "C" int yylex();
//extern "C" int yyparse();
extern "C" FILE *yyin;
extern int line_num;

//struct rules_t;

extern void yyerror(const char *s);

int main(){
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

	for(std::list<rules_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i){
		cout << i->id << endl;
	}

	return 0;
}

void yyerror(const char *s) {
       cout << "EEK, parse error!  Message: " << s << " on line: " << line_num;
       // might as well halt now:
       exit(-1);
}