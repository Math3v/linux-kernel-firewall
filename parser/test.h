#ifndef _TEST_H_
#define _TEST_H_

struct rule_t {
	int id;
	char *action;
	char *proto;
	char *src_ip;
	char *dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

extern std::list<rule_t> rulesList;

#endif