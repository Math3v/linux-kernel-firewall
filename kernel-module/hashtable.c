#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h> /* copy_from_user */
#include <linux/inet.h>  /* inet_hton ... */
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/string.h>

#define LINE_MAX_SIZE 50
#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "linux-kernel-firewall"
#define DBG

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-kernel-firewall");
MODULE_AUTHOR("Matej Minarik");

DEFINE_HASHTABLE(hashmap, 4);

static struct proc_dir_entry *procfs;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;

struct user_hash {
	struct hlist_node hash;
	unsigned int id;
	unsigned char action; /* d-deny a-allow */
	unsigned int proto; /* 1000-tcp 2500-udp 3800-icmp 4200-ip */
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

static ssize_t procfs_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	const char delim[2] = " ";
	unsigned int cnt = 0, token_cnt = 0;
	char *token, *running, *line;
	struct user_hash *node;

	line = kmalloc(LINE_MAX_SIZE, GFP_KERNEL);

	/* get buffer size */
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) ) {
		return -EFAULT;
	}

#ifdef DBG
	printk("Received: ");
#endif
	for(; cnt < procfs_buffer_size; ++cnt) {
	#ifdef DBG
		printk("%c", buffer[cnt]);
	#endif
		line[cnt] = buffer[cnt];

		/* if line is received, we will start with parsing */
		if(buffer[cnt] == '\n') {
			token_cnt = 0;
			line[cnt] = '\0';
			node = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
			running = kmalloc(strlen(line), GFP_KERNEL);
			memcpy(running, line, strlen(line));
			token = strsep(&running, delim);

			while(token != NULL) {

				/* parse rule-id */
				if(token_cnt == 0) {
					kstrtouint(token, 10, &node->id);
				}
				/* parse action */
				else if(token_cnt == 1) {
					if(strcmp("allow", token) == 0)
						node->action = 'a';
					else if(strcmp("deny", token) == 0)
						node->action = 'd';
					else {
						printk(KERN_ERR "Parsing failed on action %s\n", token);
						return -1;
					}
				}
				/* parse proto */
				else if(token_cnt == 2) {
					if(strcmp("tcp", token) == 0)
						node->proto = 1000;
					else if(strcmp("udp", token) == 0){
						node->proto = 2500;
					}
					else if(strcmp("icmp", token) == 0){
						node->proto = 3800;
					}
					else if(strcmp("ip", token) == 0){
						node->proto = 4200;
					}
					else {
						printk(KERN_ERR "Parsing failed on proto %s\n", token);
						return -1;
					}
				}
				/* parse src_ip */
				else if(token_cnt == 3) {
					if(strcmp("any", token) == 0) {
						node->src_ip = 0;
						#ifdef DBG
						printk("src_ip: %u\n", node->src_ip);
						#endif
					} 
					else {
						node->src_ip = htonl( in_aton(token) );
						#ifdef DBG
						printk("src_ip: %pI4h\n", &(node->src_ip));
						#endif
					}
				}

				token = strsep(&running, delim);
				++token_cnt;
			}
			#ifdef DBG
				printk("Adding node %c %d\n", node->action, node->proto);
			#endif
			hash_add_rcu(hashmap, &node->hash, node->proto);
		}
	}
	
	return procfs_buffer_size;
}

int init_module(){
	static const struct file_operations proc_file_fops = {
		.owner = THIS_MODULE,
	 	.write = procfs_write,
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

	return 0;
}


void cleanup_module(){
	struct user_hash *node, *existing;
	struct hlist_node *prev; 

#ifdef DBG
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
#endif
	printk("procfs cleanup\n");
	remove_proc_entry(PROCFS_NAME, NULL);
	
	printk("hashmap cleanup\n");
	node = NULL;
	prev = NULL;
	hash_for_each_rcu(hashmap, bkt, existing, hash) {
		if(prev != NULL) 
			hash_del(prev);
		kfree(node);
		prev = &existing->hash;
		node = existing;
	}
	hash_del(prev);
	kfree(node);
	printk("all good, module is removed\n");
}