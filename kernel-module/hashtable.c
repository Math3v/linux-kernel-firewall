#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>	/* for copy_from_user */

#include <linux/fs.h>		// for basic filesystem
#include <linux/proc_fs.h>	// for the proc filesystem
#include <linux/seq_file.h>	// for sequence files
#include <linux/jiffies.h>	// for jiffies

#include <linux/string.h>

#define str(x) #x

#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "linux-kernel-firewall"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10");

DEFINE_HASHTABLE(hashmap, 4);

static struct proc_dir_entry *procfs;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;

/*enum proto_t{
	tcp, udp, icmp, ip
};*/

struct user_hash {
	struct hlist_node hash;
	unsigned int id;
	unsigned char action; /* d-deny a-allow */
	unsigned int proto; /* 1000-tcp 2500-udp 3800-icmp 4200-ip */
	//enum proto_t proto;
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

int procfile_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	unsigned int cnt = 0, token_cnt = 0;
	//char line[50];
	char *token, *running, *line = kmalloc(50, GFP_KERNEL);
	const char delim[2] = " ";
	struct user_hash *node;
	/* get buffer size */
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
		return -EFAULT;
	}

	printk("Received: ");
	for(; cnt < procfs_buffer_size; ++cnt) {
		printk("%c", buffer[cnt]);
		line[cnt] = buffer[cnt];
		if(buffer[cnt] == '\n') {
			token_cnt = 0;
			line[cnt] = '\0';
			node = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
			running = kmalloc(strlen(line), GFP_KERNEL);
			memcpy(running, line, strlen(line));
			token = strsep(&running, delim);
			while(token != NULL) {
				if(token_cnt == 0) {
					kstrtouint(token, 10, &node->id);
				}
				else if(token_cnt == 1) {
					if(strcmp(token, "allow") == 0)
						node->action = 'a';
					else if(strcmp(token, "deny") == 0)
						node->action = 'd';
					else {
						printk(KERN_ERR "Parsing failed on action %s\n", token);
						return -1;
					}
				}
				else if(token_cnt == 2) {
					if(strcmp(token, "tcp") == 0)
						node->proto = 1000;
					else if(strcmp(token, "udp") == 0){
						node->proto = 2500;
					}
					else if(strcmp(token, "icmp") == 0){
						node->proto = 3800;
					}
					else if(strcmp(token, "ip") == 0){
						node->proto = 4200;
					}
					else {
						printk(KERN_ERR "Parsing failed on proto %s\n", token);
						return -1;
					}
				}

				token = strsep(&running, delim);
				++token_cnt;
			}
			printk("Adding node %c %d\n", node->action, node->proto);
			hash_add_rcu(hashmap, &node->hash, node->proto);
		}
	}
	
	return procfs_buffer_size;
}

int init_module(){
	struct user_hash *node;
	struct user_hash *rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	unsigned int bkt = 0, cnt = 0;
	struct hlist_node empty = {.next = NULL, .pprev = NULL };
	static const struct file_operations proc_file_fops = {
		.owner = THIS_MODULE,
	 	.write = procfile_write,
	};

	procfs = proc_create(PROCFS_NAME, 0, NULL, &proc_file_fops);
	if (procfs == NULL) {
		remove_proc_entry(PROCFS_NAME, NULL);
		printk("Error: Could not initialize /proc/%s\n",
			PROCFS_NAME);
		return -ENOMEM;
	}

	printk("firewall init\n");
	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

	/*rule->id = 10;
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
	printk("end for each possible\n");*/

	return 0;
}


void cleanup_module(){
	struct user_hash *node; 
	unsigned int bkt = 0;
	hash_for_each_rcu(hashmap, bkt, node, hash){
		printk("node %d proto %d in bucket %d\n", node->id, node->proto, bkt);
	}
	printk("possible i\n");
	hash_for_each_possible_rcu(hashmap, node, hash, 3800){
		printk("node %d proto %d in bucket %d\n", node->id, node->proto, bkt);
	}
	printk("possible m\n");
	hash_for_each_possible_rcu(hashmap, node, hash, 4200){
		printk("node %d proto %d in bucket %d\n", node->id, node->proto, bkt);
	}
	remove_proc_entry(PROCFS_NAME, NULL);
	printk("firewall cleanup\n");

}