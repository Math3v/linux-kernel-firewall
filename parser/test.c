#include <iostream>
#include <list>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
}

void printRules(){
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

int main(int argc, char *argv[]){

	parseRules();

	int opt;
	while((opt = getopt(argc, argv, "pa:d:f:")) != -1) {
		switch(opt) {
			case 'p': /* print rules */
				printRules();
				break;
			case 'a': /* add rule */
				break;
			case 'd': /* delete rule rule-id */
				break;
			case 'f': /* read rules from file */
				break;
			default: /* unmatched argument */
				fprintf(stderr, "Usage: %s <-a rule | -p | -d rule-id | -f file>\n", 
					argv[0]);
		}
	}

	return 0;
}