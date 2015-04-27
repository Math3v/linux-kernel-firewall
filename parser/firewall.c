#include <iostream>
#include <list>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

using namespace std;

#include "firewall_parser.tab.h"
#include "firewall.h"

extern "C" FILE *yyin;
extern int line_num;
extern void yyerror( const char *s );

#define PROCFILE "/proc/linux-kernel-firewall"
#define TEMPFILE "tmp"
#define DEBUG
#define MAXLEN 1024

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

int is_duplicate(int id) {
	/* TODO */
	return 0; /* false */
}

void send_rule_to_proc(struct rule_t rule) {
	char *srule;

	if(is_duplicate(rule.id) == 1) {
		fprintf(stderr, "Cannot add rule with id %d, because it is a duplicate id\n", rule.id);
		return;
	}

	srule = (char *) calloc(MAXLEN, sizeof(char));
	if(srule == NULL) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(EXIT_FAILURE);
	}

	sprintf(srule, "a %d %s %s %s %s %d %d\n",
		rule.id, rule.action, rule.proto,
		rule.src_ip, rule.dst_ip,
		rule.src_port, rule.dst_port);

	#ifdef DEBUG
	printf("Sending '%s'\n", srule);
	#endif

	send_to_proc(srule);
	free(srule);
}

void yyerror(const char *s) {
       cout << "ERROR: " << s << " on line: " << line_num << endl;
       exit(-1);
}

void parse_rules(const char *filename){
	FILE *myfile = fopen(filename, "r");
	if (!myfile) {
		fprintf(stderr, "Cannot open file '%s'\n", filename);
		exit(-1);
	}
	// set flex to read from it instead of defaulting to STDIN:
	yyin = myfile;
	
	// parse through the input until there is no more:
	do {
		yyparse();
	} while (!feof(yyin));	
	fclose(myfile);
}

void send_rules() {
	for(std::list<rule_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i) {
		send_rule_to_proc(*i);
	}
}

void print_rules(){
	FILE *fr;
	char *line;

	line = (char *) calloc(MAXLEN, sizeof(char));
	if(line == NULL) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(EXIT_FAILURE);
	}

	fr = fopen(PROCFILE, "r");
	if(fr == NULL) {
		fprintf(stderr, "Cannot open file %s\n", PROCFILE);
		exit(EXIT_FAILURE);
	}
	
  	while(fgets(line, MAXLEN, fr) != NULL) {
  		printf("%s", line);
  	}

	fclose(fr);
	free(line);
}

void concat_rule(char **rule, int argc, char **argv) {
	int i;
	char *tmp = NULL;

	tmp = (char *) calloc(MAXLEN, sizeof(char));
	if(tmp == NULL) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(EXIT_FAILURE);
	}

	for(i = 2; i < argc; i++) {
		strcat(tmp, argv[i]);
		if(i != (argc - 1))
			strcat(tmp, " ");
	}

	*rule = (char *) calloc(strlen(tmp), sizeof(char));
	strcpy(*rule, tmp);

	free(tmp);
}

void add_rule(int argc, char **argv) {
	char *line;
	FILE *tmp;

	tmp = fopen(TEMPFILE, "w");
	if(tmp == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", TEMPFILE);
		exit(EXIT_FAILURE);
	}

	concat_rule(&line, argc, argv);
	fprintf(tmp, "%s\n", line);
	fclose(tmp);

	parse_rules(TEMPFILE);
	send_rules();

	#ifdef DEBUG
	for(std::list<rule_t>::iterator i = rulesList.begin(); i != rulesList.end(); ++i) {
		printf("In list: %d\n", (*i).id);
	}
	#endif

	free(line);
	remove(TEMPFILE);
}

void del_rule(char *id) {
	char *sproc;

	sproc = (char *) calloc(MAXLEN, sizeof(char));
	if(sproc == NULL) {
		fprintf(stderr, "Cannot allocate memory\n");
		exit(EXIT_FAILURE);
	}

	#ifdef DEBUG
	printf("Deleting rule-id '%s'\n", id);
	#endif

	sprintf(sproc, "d %s\n", id);
	send_to_proc(sproc);

	free(sproc);
}

int main(int argc, char *argv[]){

	int opt;
	while((opt = getopt(argc, argv, "pa:d:f:")) != -1) {
		switch(opt) {
			case 'p': /* print rules */
				print_rules();
				break;
			case 'a': /* add rule */
				add_rule(argc, argv);
				break;
			case 'd': /* delete rule rule-id */
				del_rule(optarg);
				break;
			case 'f': /* read rules from file */
				parse_rules(optarg);
				send_rules();
				break;
			default: /* unmatched argument */
				fprintf(stderr, "Usage: %s -a rule | -p | -d rule-id | -f file>\n", 
					argv[0]);
		}
	}

	return 0;
}
