#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10");

DEFINE_HASHTABLE(hashmap, 4);

struct user_hash {
	struct hlist_node hash;
	unsigned int id;
	unsigned char action; /* d-deny a-allow */
	unsigned char proto; /* t-tcp u-udp m-icmp i-ip */
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

int init_module(){
	struct user_hash *node;
	struct user_hash *rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	unsigned int bkt = 0;
	unsigned int cnt = 0;
	struct hlist_node empty = {.next = NULL, .pprev = NULL};

	printk("firewall init\n");

	rule->id = 10;
	rule->action = 'a';
	rule->proto = 't';
	rule->src_ip = 240;
	rule->dst_ip = 250;
	rule->hash = empty;
	hash_add_rcu(hashmap, &rule->hash, rule->proto);

	rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	rule->id = 20;
	rule->action = 'd';
	rule->proto = 'u';
	rule->src_ip = 270;
	rule->dst_ip = 280;
	rule->hash = empty;
	hash_add_rcu(hashmap, &rule->hash, rule->proto);

	rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	rule->id = 30;
	rule->action = 'd';
	rule->proto = 'u';
	rule->src_ip = 280;
	rule->dst_ip = 290;
	rule->hash = empty;
	hash_add_rcu(hashmap, &rule->hash, rule->proto);

	rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	rule->id = 40;
	rule->action = 'd';
	rule->proto = 'm';
	rule->src_ip = 300;
	rule->dst_ip = 310;
	rule->hash = empty;
	hash_add_rcu(hashmap, &rule->hash, rule->proto);

	rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	rule->id = 50;
	rule->action = 'd';
	rule->proto = 'u';
	rule->src_ip = 220;
	rule->dst_ip = 210;
	rule->hash = empty;
	hash_add_rcu(hashmap, &rule->hash, rule->proto);


	printk("start\n");
	hash_for_each_rcu(hashmap, bkt, node, hash){
		printk("node %d proto %c in bucket %d\n", node->id, node->proto, bkt);
		++cnt;
	}
	printk("end with %d\n", cnt);

	printk("hash for each possible\n");
	hash_for_each_possible_rcu(hashmap, node, hash, 'u') {
		printk("node %d proto %c\n", node->id, node->proto);
	}
	printk("end for each possible\n");

	return 0;
}


void cleanup_module(){
	printk("firewall cleanup\n");
}