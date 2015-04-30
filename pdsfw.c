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
#include <linux/if_ether.h>

#define INT_MAX_LEN 20
#define LINE_MAX_SIZE 512
#define PROCFS_MAX_SIZE 1024
#define PROCFS_NAME "linux-kernel-firewall"
#define DBG

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-kernel-firewall");
MODULE_AUTHOR("Matej Minarik");

/* Hashtable for rules */
DEFINE_HASHTABLE(hashmap, 16);

/* Structure used to register the function */
static struct nf_hook_ops nfho;

enum action_t {
	allow,
	deny
};

enum proto_t {
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
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
};

void remove_null(char **p, unsigned int *pos) {
	unsigned int i;
	for(i = *pos; i < INT_MAX_LEN; ++i) {
		(*p)[i] = ' ';
	}
}

unsigned int iptostr(uint32_t *ip, char **str, unsigned int maxlen) {
	unsigned char f = ((*ip) & (0xFF000000)) >> 24;
	unsigned char s = ((*ip) & (0x00FF0000)) >> 16;
	unsigned char t = ((*ip) & (0x0000FF00)) >> 8;
	unsigned char h = (*ip) & (0x000000FF);
	unsigned int ret = snprintf(*str, maxlen, "%u.%u.%u.%u", f, s, t, h);

	if(*ip == 0) {
		strcpy(*str, "*");
		return 1;
	}

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

void delete_rule(const char *aid) {
	unsigned int id, bkt;
	struct user_hash *node;
	struct hlist_node *tmp;

	if(aid == NULL) {
		printk(KERN_ERR "Id came null to delete_rule\n");
		return;
	}

	#ifdef DBG
	printk("Kstrtouint '%s'\n", aid);
	#endif
	if(kstrtouint(aid, 10, &id) != 0) {
		printk(KERN_ERR "ERROR: kstrtouint failed\n");
		return;
	}

	#ifdef DBG
	printk("Attempting to delete node '%s'\n", aid);
	#endif
	hash_for_each_safe(hashmap, bkt, tmp, node, hash){
		if(id == node->id){
			#ifdef DBG
			printk("Deleting node %d proto %d in bucket %d\n", node->id, node->proto, bkt);
			#endif
			hash_del(&node->hash);
			break;
		}
	}
}

ssize_t proc_read(struct file *file, char __user *buffer, size_t count, loff_t *data){
	ssize_t off = 0;
	struct user_hash *node;
	unsigned int bkt = 0, ret;
	char *buff = vmalloc(LINE_MAX_SIZE);
	const char *delim = "\n", *space = "\t";
	char *c = vmalloc(INT_MAX_LEN);
	unsigned int zero = 0, ip_len = 0;

    if((int)*data>0){
        return 0;
    }

    hash_for_each_rcu(hashmap, bkt, node, hash) {
    	#ifdef DBG
    	printk("Sending rule-id '%d'\n", node->id);
    	#endif

    	ret = snprintf(c, INT_MAX_LEN, "%u\t", node->id);
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
    	
    	/* add src_ip */
    	remove_null(&c, &zero);
    	ip_len = iptostr(&node->src_ip, &c, strlen(c));
    	memcpy(buff + off, c, ip_len);
    	off += ip_len;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add src_port */
    	remove_null(&c, &zero);
    	if(node->src_port == 0) {
    		strcpy(c, "*");
    		ret = 1;
    	}
    	else {
    		ret = snprintf(c, INT_MAX_LEN, "%u", node->src_port);
    	}
    	remove_null(&c, &ret);
    	memcpy(buff + off, c, ret);
    	off += ret;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add dst_ip */
    	remove_null(&c, &zero);
    	ip_len = iptostr(&node->dst_ip, &c, strlen(c));
    	memcpy(buff + off, c, ip_len);
    	off += ip_len;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add dst_port */
    	remove_null(&c, &zero);
    	if(node->dst_port == 0) {
    		strcpy(c, "*");
    		ret = 1;
    	}
    	else {
    		ret = snprintf(c, INT_MAX_LEN, "%u", node->dst_port);
    	}
    	remove_null(&c, &ret);
    	memcpy(buff + off, c, ret);
    	off += ret;

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add proto */
    	get_proto(&node->proto, &c);
    	memcpy(buff + off, c, strlen(c));
    	off += strlen(c);

    	memcpy(buff + off, space, strlen(space));
    	off += strlen(space);

    	/* add end of line */
    	memcpy(buff + off, delim, strlen(delim));
    	off += strlen(delim);

    	#ifdef DEBUG
    	printk("Buff is '%s'\n", buff);
    	#endif
    }
    buff[off] = '\0';

    *data += off;
    memcpy(buffer, buff, strlen(buff));

    vfree(buff);
    vfree(c);
    return off;
}

ssize_t procfs_write(struct file *file, const char __user *buffer, size_t count, loff_t *date) {
	static char procfs_buffer[PROCFS_MAX_SIZE];
	static unsigned long procfs_buffer_size = 0;
	const char delim[2] = " ";
	unsigned int cnt = 0, token_cnt = 0, ui_tmp = 0, del = 0;
	char *token, *running, *line;
	struct user_hash *node;

	line = vmalloc(LINE_MAX_SIZE);

	/* get buffer size */
	procfs_buffer_size = count;
	if (procfs_buffer_size > PROCFS_MAX_SIZE ) {
		procfs_buffer_size = PROCFS_MAX_SIZE;
	}
	
	/* write data to the buffer */
	if ( copy_from_user(procfs_buffer, buffer, procfs_buffer_size) != 0) {
		printk(KERN_ERR "ERROR: copy_from_user failed\n");
		printk(KERN_ERR "Dump: [%lu] '%s'\n", procfs_buffer_size, procfs_buffer);
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
			running = vmalloc(strlen(line));
			memcpy(running, line, strlen(line));
			token = strsep(&running, delim);

			while(token != NULL) {

				#ifdef DBG
				printk("Token '%s'\n", token);
				#endif

				/* parse add/delete */
				if(token_cnt == 0) {
					if(strcmp("a", token) == 0) {
						/* This is actually nop, just "eat" the token */
						del = 0;
					}
					else if(strcmp("d", token) == 0) {
						#ifdef DBG
						printk("Before strsep, running is '%s' token is '%s'\n", running, token);
						#endif
						token = strsep(&running, delim);
						#ifdef DBG
						printk("Running is '%s' token is '%s'\n", running, token);
						#endif
						delete_rule(token);
						del = 1;
					}
					else {
						printk(KERN_ERR "Add / delete is unknown value %s\n", token);
						return -1;
					}
				}
				/* parse rule-id */
				else if(token_cnt == 1) {
					kstrtouint(token, 10, &node->id);
				}
				/* parse action */
				else if(token_cnt == 2) {
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
				else if(token_cnt == 3) {
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
				else if(token_cnt == 4) {
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
				else if(token_cnt == 5) {
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
				else if(token_cnt == 6) {
					kstrtouint(token, 10, &ui_tmp);
					node->src_port = (unsigned short) ui_tmp;
					#ifdef DBG
					printk("src_port: %u\n", node->src_port);
					#endif
				}
				/* parse dst_port */
				else if(token_cnt == 7) {
					kstrtouint(token, 10, &ui_tmp);
					node->dst_port = (unsigned short) ui_tmp;
					#ifdef DBG
					printk("dst_port: %u\n", node->dst_port);
					#endif
				}

				token = strsep(&running, delim);
				++token_cnt;
			}

			if(del == 0) {
				#ifdef DBG
				printk("Adding node %d %d\n", node->action, node->proto);
				#endif
				hash_add_rcu(hashmap, &node->hash, node->proto);
			}

			vfree(running);
		}
	}

	
	vfree(line);
	
	return procfs_buffer_size;
}

unsigned int hook_func_in(const struct nf_hook_ops *ops,
							struct sk_buff *skb, 
        					const struct net_device *in,
        					const struct net_device *out,
        					int (*okfn)(struct sk_buff *)) {
 	unsigned int proto_key;
 	uint32_t src_ip, dst_ip;
 	uint16_t src_port, dst_port;
 	struct user_hash *node;
 	struct ethhdr *eth_header;
 	struct iphdr *ip_header;
 	struct udphdr *udp_header;
 	struct tcphdr *tcp_header;

 	eth_header = eth_hdr(skb);
 	/* Netfilter works with IP traffic only */
 	if(eth_header->h_proto != htons(ETH_P_IP)) {
 		return NF_ACCEPT;
 	}

   /* Get IP header from skb */
   ip_header = (struct iphdr *)skb_network_header(skb);
 
   /* Get IP addresses */
   src_ip = (uint32_t) ntohl(ip_header->saddr); 
   dst_ip = (uint32_t) ntohl(ip_header->daddr); 
   src_port = 0;
   dst_port = 0;

   /* IP protocol filtering */
   proto_key = ip;
   hash_for_each_possible_rcu(hashmap, node, hash, proto_key) {
   		#ifdef DBG
   		printk("Possible rule-id %u\n", node->id);
   		printk("node->src_ip %pI4h src_ip %pI4h\n", &(node->src_ip), &src_ip);
   		#endif
   		if(node->src_ip == 0 || node->src_ip == src_ip) {
   			if(node->dst_ip == 0 || node->dst_ip == dst_ip) {
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
 
   /* Determine protocol and get ports */
   if (ip_header->protocol == 17) { /* UDP */
       udp_header = (struct udphdr *)(skb_network_header(skb)+20);
       src_port = (uint16_t) ntohs(udp_header->source);
       dst_port = (uint16_t) ntohs(udp_header->dest);
       proto_key = udp;
   } else if (ip_header->protocol == 6) { /* TCP */
       tcp_header = (struct  tcphdr *)(skb_network_header(skb)+20);
       src_port = (uint16_t) ntohs(tcp_header->source);
       dst_port = (uint16_t) ntohs(tcp_header->dest);
       proto_key = tcp;
   } else if (ip_header->protocol == 1 ) { /* ICMP */
       proto_key = icmp;
   } else {
   		return NF_ACCEPT;
   }

   /* Other protocols filtering */
   hash_for_each_possible_rcu(hashmap, node, hash, proto_key) {
   		#ifdef DBG
   		printk("Possible rule-id %u\n", node->id);
   		printk("node->src_ip %pI4h src_ip %pI4h\n", &(node->src_ip), &src_ip);
   		printk("node->src_port %d src_port %d\n", node->src_port, src_port);
   		#endif
   		if(node->src_ip == 0 || node->src_ip == src_ip) {
   			if(node->dst_ip == 0 || node->dst_ip == dst_ip) {
   				if(node->src_port == 0 || node->src_port == src_port) {
   					if(node->dst_port == 0 || node->dst_port == dst_port) {
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
   printk("IN packet info: src ip: %pI4h, src port: %u; dest ip: %pI4h, dest port: %u proto: %u\n", 
    &src_ip, src_port, &dst_ip, dst_port, ip_header->protocol); 
 #endif

   return NF_ACCEPT;                
 
}

int init_module(){
	static struct proc_dir_entry *procfs;
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
	unsigned int bkt = 0;

	#ifdef DBG
	hash_for_each_rcu(hashmap, bkt, node, hash){
		printk("node %d proto %d in bucket %d\n", node->id, node->proto, bkt);
	}
	printk("possible ip\n");
	hash_for_each_possible_rcu(hashmap, node, hash, 3800){
		printk("node %d proto %d\n", node->id, node->proto);
	}
	printk("possible icmp\n");
	hash_for_each_possible_rcu(hashmap, node, hash, 4200){
		printk("node %d proto %d\n", node->id, node->proto);
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
		if(&existing->hash != NULL)
			prev = &existing->hash;
		if(existing != NULL)
			node = existing;
	}
	if(prev != NULL)
		hash_del(prev);
	kfree(node);
	printk("all good, module is removed\n");
}