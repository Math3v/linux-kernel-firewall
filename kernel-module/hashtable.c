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

#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "linux-kernel-firewall"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10");

DEFINE_HASHTABLE(hashmap, 4);

static struct proc_dir_entry *procfs;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;

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

int procfile_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	unsigned int cnt = 0;
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
	}
	
	return procfs_buffer_size;
}

int init_module(){
	struct user_hash *node;
	struct user_hash *rule = kmalloc(sizeof(struct user_hash), GFP_KERNEL);
	unsigned int bkt = 0, cnt = 0;
	struct hlist_node empty = {.next = NULL, .pprev = NULL };

	printk("firewall init\n");

	static const struct file_operations proc_file_fops = {
	 .owner	= THIS_MODULE,
	 //.open	= procfs_open,
	 //.read	= seq_read,
	 //.llseek	= seq_lseek,
	 //.release	= single_release,
	 	.write = procfile_write
	};

	procfs = proc_create(PROCFS_NAME, 0, NULL, &proc_file_fops);
	if (procfs == NULL) {
		//remove_proc_entry(PROCFS_NAME, &proc_root);
		printk("Error: Could not initialize /proc/%s\n",
			PROCFS_NAME);
		return -ENOMEM;
	}

	//Our_Proc_File->read_proc  = procfile_read;
	/*procfs->write_proc = procfile_write;
	procfs->owner 	  = THIS_MODULE;
	procfs->mode 	  = S_IFREG | S_IRUGO;
	procfs->uid 	  = 0;
	procfs->gid 	  = 0;
	procfs->size 	  = 37;*/

	printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);

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
	remove_proc_entry(PROCFS_NAME, NULL);
	printk("firewall cleanup\n");

}