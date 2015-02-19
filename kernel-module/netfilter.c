#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/plist.h>
 
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("linux-simple-firewall");
MODULE_AUTHOR("Liu Feipeng/roman10");
 
//the structure used to register the function
static struct nf_hook_ops nfho;
static struct nf_hook_ops nfho_out;

struct rule_t {
  int prio;
  int number;
  struct plist_head *plist;
}

static LIST_HEAD(plist);
 
unsigned int port_str_to_int(char *port_str) {
    unsigned int port = 0;    
    int i = 0;
    if (port_str==NULL) {
        return 0;
    } 
    while (port_str[i]!='\0') {
        port = port*10 + (port_str[i]-'0');
        ++i;
    }
    return port;
}
 
unsigned int ip_str_to_hl(char *ip_str) {
    /*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
    unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0; 
    }
    memset(ip_array, 0, 4);
    while (ip_str[i]!='.') {
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='\0') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    //printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
    return ip;
}
 
/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
 
    unsigned int tmp = ntohl(ip);    //network to host long
 
    int cmp_len = 32;
 
    int i = 0, j = 0;
 
    printk("compare ip: %u <=> %u\n", tmp, ip_rule);
 
    if (mask != 0) {
 
       //printk(KERN_INFO "deal with mask\n");
 
       //printk(KERN_INFO "mask: %d.%d.%d.%d\n", mask[0], mask[1], mask[2], mask[3]);
 
       cmp_len = 0;
 
       for (i = 0; i < 32; ++i) {
 
      if (mask & (1 << (32-1-i)))
 
         cmp_len++;
 
      else
 
         break;
 
       }
 
    }
    /*compare the two IP addresses for the first cmp_len bits*/
 
    for (i = 31, j = 0; j < cmp_len; --i, ++j) {
 
        if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
 
            printk("ip compare: %d bit doesn't match\n", (32-i));
 
            return false;
 
        }
 
    }
 
    return true;
 
}
 
//the hook function itself: regsitered for filtering outgoing packets
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb,  
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
 
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
   if (ip_header->protocol==17) {
       udp_header = (struct udphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
 
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)skb_transport_header(skb);
       src_port = (unsigned int)ntohs(tcp_header->source); 
       dest_port = (unsigned int)ntohs(tcp_header->dest);
 
   }
 
   printk("OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", 
    src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
 
   return NF_ACCEPT;            
 
}
 
 
 
 
 
//the hook function itself: registered for filtering incoming packets
 
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, 
        const struct net_device *in, const struct net_device *out,
        int (*okfn)(struct sk_buff *)) {
 
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
   if (ip_header->protocol==17) {
       udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(udp_header->source);
       dest_port = (unsigned int)ntohs(udp_header->dest);
   } else if (ip_header->protocol == 6) {
       tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
       src_port = (unsigned int)ntohs(tcp_header->source);
       dest_port = (unsigned int)ntohs(tcp_header->dest);
   }
 
   printk("IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", 
    src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
  
   return NF_ACCEPT;                
 
}

void plist_test(){
    struct rule_t rule;
    rule.prio = 100;
    rule.number = 24;

    struct rule_t *r;

    INIT_LIST_HEAD(rule.plist);
    list_add(rule.plist, plist);

    plist_for_each(r, plist){
      printk("hello from list %d\n", r->number);
    }
}
 
/* Initialization routine */
int init_module() {
    printk("initialize kernel module\n");
 
    //INIT_LIST_HEAD(&(policy_list.list));
 
    /* Fill in the hook structure for incoming packet hook*/
    nfho.hook = hook_func_in;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
 
    //nf_register_hook(&nfho);         // Register the hook
 
    /* Fill in the hook structure for outgoing packet hook*/
    nfho_out.hook = hook_func_out;
    nfho_out.hooknum = NF_INET_LOCAL_OUT; 
    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_FIRST;
 
    //nf_register_hook(&nfho_out);    // Register the hook
 
    plist_test();

    return 0;
 
}
 
 
 
/* Cleanup routine */
void cleanup_module() {
    nf_unregister_hook(&nfho);
    nf_unregister_hook(&nfho_out);
 
    printk("kernel module unloaded.\n");
 
}