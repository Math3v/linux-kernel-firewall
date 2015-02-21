#include <iostream>
#include <list>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

using namespace std;

#include "firewall_parser.tab.h"
#include "firewall.h"

extern "C" FILE *yyin;
extern int line_num;
extern void yyerror(const char *s);

#define PROCFILE "/proc/linux-kernel-firewall"

void send_to_proc(char *str) {
	FILE *fw;
	fw = fopen(PROCFILE, "w");
	if(fw == NULL) {
		fprintf(stderr, "Cannot open %s\n", PROCFILE);
		exit(-1);
	}

	fprintf(fw, "%s", str);
	fclose(fw);
}

void send_rule_to_proc(struct rule_t rule) {
	char srule[200];
	sprintf(srule, "%d %s %s %s %s %d %d\n",
		rule.id, rule.action, rule.proto,
		rule.src_ip, rule.dst_ip,
		rule.src_port, rule.dst_port);

	fprintf(stdout, "Sending %s", srule);
	send_to_proc(srule);
}

void yyerror(const char *s) {
       cout << "EEK, parse error!  Message: " << s << " on line: " << line_num;
       exit(-1);
}

void parse_rules(){
	FILE *myfile = fopen("rules.in", "r");
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

void send_rules() {
	for(std::list<rule_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i) {
		send_rule_to_proc(*i);
	}
}

void print_rules(){
	for(std::list<rule_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i) {
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

	parse_rules();
	send_rules();

	int opt;
	while((opt = getopt(argc, argv, "pa:d:f:")) != -1) {
		switch(opt) {
			case 'p': /* print rules */
				print_rules();
				break;
			case 'a': /* add rule */
				break;
			case 'd': /* delete rule rule-id */
				break;
			case 'f': /* read rules from file */
				break;
			default: /* unmatched argument */
				fprintf(stderr, "Usage: %s -a rule | -p | -d rule-id | -f file>\n", 
					argv[0]);
		}
	}

	return 0;
}
