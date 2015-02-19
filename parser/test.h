#ifndef _TEST_H_
#define _TEST_H_

struct rules_t {
	int id;
	char *action;
	char *proto;
	char *src_ip;
	char *dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};
//rules_t rule;
extern std::list<rules_t> rulesList;

#endif