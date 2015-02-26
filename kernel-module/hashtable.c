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
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>

#define INT_MAX_LEN 20
#define LINE_MAX_SIZE 100
#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "linux-kernel-firewall"
#define DBG

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-kernel-firewall");
MODULE_AUTHOR("Matej Minarik");

DEFINE_HASHTABLE(hashmap, 4);

//the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

//variables for procfs
static struct proc_dir_entry *procfs;
static char procfs_buffer[PROCFS_MAX_SIZE];
static unsigned long procfs_buffer_size = 0;

typedef enum action_t {
	allow,
	deny
};

typedef enum proto_t {
	tcp 	= 1000,
	udp 	= 2500,
	icmp 	= 3800,
	ip		= 4200
};

struct user_hash {
	struct hlist_node hash;
	unsigned int id;
	enum action_t action;
	enum proto_t proto;
	unsigned int src_ip;
	unsigned int dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

void remove_null(char **p, unsigned int *pos) {
	unsigned int i;
	for(i = *pos; i < INT_MAX_LEN; ++i) {
		(*p)[i] = ' ';
	}
}

unsigned int iptostr(unsigned int *ip, char **str, unsigned int maxlen) {
	unsigned char f = ((*ip) & (0xFF000000)) >> 24;
	unsigned char s = ((*ip) & (0x00FF0000)) >> 16;
	unsigned char t = ((*ip) & (0x0000FF00)) >> 8;
	unsigned char h = (*ip) & (0x000000FF);
	unsigned int ret = snprintf(*str, maxlen, "%u.%u.%u.%u", f, s, t, h);

	remove_null(str, &ret);
	return ret;
}

void get_action(enum action_t *action, char **p) {
	switch(*action){
    		case allow:
    			strcpy(*p, "allow");
    			break;
    		case deny:
    			strcpy(*p, "deny");
    			break;
    	}
}

void get_proto(enum proto_t *proto, char **p) {
	switch(*proto) {
		case icmp:
			strcpy(*p, "icmp");
			break;
		case ip:
			strcpy(*p, "ip");
			break;
		case tcp:
			strcpy(*p, "tcp");
			break;
		case udp:
			strcpy(*p, "udp");
			break;
	}
}

static ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t * data){
	ssize_t off = 0;
	struct user_hash *node;
	unsigned int bkt = 0, ret;
	char *buff = vmalloc(LINE_MAX_SIZE);
	char *delim = "\n", *space = " ";
	char *c = vmalloc(INT_MAX_LEN);
	unsigned int zero = 0, ip_len = 0;

	printk("Count %d\n", count);

    if((int)*data>0){
        return 0;
    }

    //char * ret_str = "This is actually me!!!\n";
    hash_for_each_rcu(hashmap, bkt, node, hash) {
    	ret = snprintf(c, INT_MAX_LEN, "%u", node->id);
    	remove_null(&c, &ret);

    	/* add id */
    	memcpy(buff + off, c, sizeof(unsigned int));
    	off += sizeof(unsigned int);

    	/* add action */
    	get_action(&node->action, &c);
    	memcpy(buff + off, c, strlen(c));
    	off += strlen(c);

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add proto */
    	get_proto(&node->proto, &c);
    	memcpy(buff + off, c, strlen(c));
    	off += strlen(c);

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);
    	
    	/* add src_ip */
    	remove_null(&c, &zero);
    	ip_len = iptostr(&node->src_ip, &c, strlen(c));
    	memcpy(buff + off, c, ip_len);
    	off += ip_len;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add dst_ip */
    	remove_null(&c, &zero);
    	ip_len = iptostr(&node->dst_ip, &c, strlen(c));
    	memcpy(buff + off, c, ip_len);
    	off += ip_len;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add src_port */
    	remove_null(&c, &zero);
    	ret = snprintf(c, INT_MAX_LEN, "%u", node->src_port);
    	remove_null(&c, &ret);
    	memcpy(buff + off, c, ret);
    	off += ret;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add dst_port */
    	remove_null(&c, &zero);
    	ret = snprintf(c, INT_MAX_LEN, "%u", node->dst_port);
    	remove_null(&c, &ret);
    	memcpy(buff + off, c, ret);
    	off += ret;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add end of line */
    	memcpy(buff + off, delim, strlen(delim));
    	off += strlen(delim);
    }
    buff[off] = '\0';

    *data += off;
    memcpy(buffer, buff, strlen(buff));

    vfree(buff);
    vfree(c);
    return off;
}

int procfs_read__dummy(char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
    int ret, procfs_buffer_pos;
    struct user_hash *node;
    char token[200];
    unsigned int bkt = 0;
    unsigned int id, src_ip, dst_ip, src_port, dst_port;
    char action[10] = "";
    char proto[5] = "";
 
    printk(KERN_INFO "procf_read (/proc/%s) called \n", PROCFS_NAME);
    if (offset > 0) {
        printk(KERN_INFO "eof is 1, nothing to read\n");
        //*eof = 1;
        return 0;
    } else {
        procfs_buffer_pos = 0;
        ret = 0;
        hash_for_each_rcu(hashmap, bkt, node, hash) {
 
            id = node->id;
            switch(node->action) {
            	case allow: 
            		strcpy(action, "allow");
            		break;
            	case deny:
            		strcpy(action, "deny");
            		break;
            };

            switch(node->proto) {
            	case tcp:
            		strcpy(proto, "tcp");
            		break;
            	case udp:
            		strcpy(proto, "udp");
            		break;
            	case icmp:
            		strcpy(proto, "icmp");
            		break;
            	case ip:
            		strcpy(proto, "ip");
            		break;
            };

            src_ip = node->src_ip;
            dst_ip = node->dst_ip;
            src_port = node->src_port;
            dst_port = node->dst_port;
 
 			/*snprintf(token, "%u %s %s %u %u %u %u\n", 
 				id, &action, &proto, src_ip, dst_ip, src_port, dst_port);*/
            snprintf(token, 200, "%d\n", id);
            printk(KERN_INFO "token: %s\n", token);
 
            memcpy(procfs_buffer + procfs_buffer_pos, token, strlen(token));
 
            procfs_buffer_pos += strlen(token);
            memcpy(buffer, procfs_buffer, procfs_buffer_pos);
            ret = procfs_buffer_pos;

            src_port = dst_port = 0;
            strcpy(action, "");
            strcpy(proto, "");
        }
    }

        return ret;
}

static ssize_t procfs_write(struct file *file, const char *buffer, unsigned long count,
		   void *data)
{
	const char delim[2] = " ";
	unsigned int cnt = 0, token_cnt = 0, ui_tmp = 0;
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
						node->action = allow;
					else if(strcmp("deny", token) == 0)
						node->action = deny;
					else {
						printk(KERN_ERR "Parsing failed on action %s\n", token);
						return -1;
					}
				}
				/* parse proto */
				else if(token_cnt == 2) {
					if(strcmp("tcp", token) == 0)
						node->proto = tcp;
					else if(strcmp("udp", token) == 0){
						node->proto = udp;
					}
					else if(strcmp("icmp", token) == 0){
						node->proto = icmp;
					}
					else if(strcmp("ip", token) == 0){
						node->proto = ip;
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
				/* parse dst_ip */
				else if(token_cnt == 4) {
					if(strcmp("any", token) == 0) {
						node->dst_ip = 0;
						#ifdef DBG
						printk("dst_ip: %u\n", node->dst_ip);
						#endif
					} 
					else {
						node->dst_ip = htonl( in_aton(token) );
						#ifdef DBG
						printk("dst_ip: %pI4h\n", &(node->dst_ip));
						#endif
					}
				}
				/* parse src_port */
				else if(token_cnt == 5) {
					kstrtouint(token, 10, &ui_tmp);
					node->src_port = (unsigned short) ui_tmp;
					#ifdef DBG
					printk("src_port: %u\n", node->src_port);
					#endif
				}
				/* parse dst_port */
				else if(token_cnt == 6) {
					kstrtouint(token, 10, &ui_tmp);
					node->dst_port = (unsigned short) ui_tmp;
					#ifdef DBG
					printk("dst_port: %u\n", node->dst_port);
					#endif
				}

				token = strsep(&running, delim);
				++token_cnt;
			}
			#ifdef DBG
				printk("Adding node %d %d\n", node->action, node->proto);
			#endif
			hash_add_rcu(hashmap, &node->hash, node->proto);
		}
	}
	
	return procfs_buffer_size;
}

unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
 	unsigned int proto_key = 0;
 	struct user_hash *node;

   /*get src address, src netmask, src port, dest ip, dest netmask, dest port, protocol*/
   struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
   struct udphdr *udp_header;
   struct tcphdr *tcp_header;
 
   /**get src and dest ip addresses**/
   unsigned int src_ip = (unsigned int)ip_header->saddr; 
   unsigned int dest_ip = (unsigned int)ip_header->daddr; 
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
 
   /***get src and dest port number***/
   if (ip_header->protocol == 17) { /* UDP */
       udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
       proto_key = udp;
   } else if (ip_header->protocol == 6) { /* TCP */
       tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
       proto_key = tcp;
   } else if (ip_header->protocol == 1 ) { /* ICMP */
       proto_key = icmp;
   }

   /* TODO: IP protocol filtering */
   /* TODO: Descending rules inside one bucket need to be ascending */
   hash_for_each_possible_rcu(hashmap, node, hash, proto_key) {
   		printk("Possible rule-id %u\n", node->id);
   		printk("node->src_ip src_ip %pI4h %pI4h\n", &(node->src_ip), &src_ip);
   		if(node->src_ip == 0 || node->src_ip == src_ip) {
   			if(node->dst_ip == 0 || node->dst_ip == dest_ip) {
   				if(node->src_port == 0 || node->src_port == src_port) {
   					if(node->dst_port == 0 || node->dst_port == dest_port) {
   						if(node->action == deny) {
   							#ifdef DBG
   							printk("packet drop\n");
   							#endif
   							return NF_DROP;
   						}
   						else if(node->action == allow) {
   							#ifdef DBG
   							printk("packet access\n");
   							#endif
   							return NF_ACCEPT;
   						}
   					}
   				}	
   			}
   		}
   }
 
 #ifdef DBG
   printk("IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", 
    src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
 #endif

   return NF_ACCEPT;                
 
}

int init_module(){
	static const struct file_operations proc_file_fops = {
		.owner = THIS_MODULE,
	 	.write = procfs_write,
	 	.read = proc_read,
	};

	procfs = proc_create(PROCFS_NAME, 0, NULL, &proc_file_fops);
	if (procfs == NULL) {
		remove_proc_entry(PROCFS_NAME, NULL);
		printk("Error: Could not initialize /proc/%s\n",
			PROCFS_NAME);
		return -ENOMEM;
	}

	/* Fill in the hook structure for incoming packet hook*/
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
 
    nf_register_hook(&nfho);         // Register the hook

	printk("firewall init\n");
	printk("/proc/%s created\n", PROCFS_NAME);
	printk("hook_func_in registered\n");

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

	printk("hook_func_in unregister\n");
	nf_unregister_hook(&nfho);
	
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