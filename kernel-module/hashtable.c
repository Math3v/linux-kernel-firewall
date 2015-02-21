#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>	/* for copy_from_user */

#define PROCF_MAX_SIZE 1024
#define PROCF_NAME "linux-kernel-firewall"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10");

DEFINE_HASHTABLE(hashmap, 4);

static struct proc_dir_entry *mf_proc_file;
unsigned long procf_buffer_pos;
char *procf_buffer;

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

int procf_write(struct file *file, const char *buffer, 
	unsigned long count, void *data)
{
   int i, j;
   struct mf_rule_desp *rule_desp;
   char c;
 
   printk(KERN_INFO "procf_write is called.\n");
 
   /*read the write content into the storage buffer*/
 
   procf_buffer_pos = 0;
   printk(KERN_INFO "pos: %ld; count: %ld\n", procf_buffer_pos, count);
   if (procf_buffer_pos + count > PROCF_MAX_SIZE) {
 
       count = PROCF_MAX_SIZE-procf_buffer_pos;
 
   } 
   if (copy_from_user(procf_buffer+procf_buffer_pos, buffer, count)) {
 
       return -EFAULT;
 
   }

   printk("Received: ");
   while((c = procf_buffer[procf_buffer_pos]) != '\n') {
   		printk("%c", c);
   }
}

int init_module(){
	struct user_hash *node;
	struct user_hash *rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	unsigned int bkt = 0;
	unsigned int cnt = 0;
	struct hlist_node empty = {.next = NULL, .pprev = NULL};

	procf_buffer = (char *) vmalloc(PROCF_MAX_SIZE);
	mf_proc_file = create_proc_entry(PROCF_NAME, 0644, NULL);
	if(mf_proc_file == NULL) {
		printk("Could not initialize /proc/%s\n", PROCF_NAME);
		return -ENOMEM;
	}

	//mf_proc_file->read_proc = procf_read;
 
    mf_proc_file->write_proc = procf_write;
 
    printk(KERN_INFO "/proc/%s is created\n", PROCF_NAME);

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