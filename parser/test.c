#include <iostream>
#include <list>
#include <stdio.h>
#include <stdlib.h>

using namespace std;

#include "snazzle.tab.h"
#include "test.h"

extern "C" FILE *yyin;
extern int line_num;
extern void yyerror(const char *s);

void yyerror(const char *s) {
       cout << "EEK, parse error!  Message: " << s << " on line: " << line_num;
       exit(-1);
}

void parseRules(){
	FILE *myfile = fopen("../a.snazzle.file", "r");
	if (!myfile) {
		cout << "I can't open a.snazzle.file!" << endl;
		exit(-1);
	}
	// set flex to read from it instead of defaulting to STDIN:
	yyin = myfile;
	
	// parse through the input until there is no more:
	do {
		yyparse();
	} while (!feof(yyin));

	for(std::list<rule_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i){
		cout << i->id << " ";
		cout << i->action << " ";
		cout << i->proto << " ";
		cout << i->src_ip << " ";
		cout << i->dst_ip << " ";
		cout << i->src_port << " ";
		cout << i->dst_port << " ";
		cout << endl;
	}
}

int main(){

	parseRules();

	return 0;
}