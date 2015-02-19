#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("helloworld");
MODULE_AUTHOR("matej minarik");

int init_module() {
	printk("initialize kernel module\n");

	return 0;
}

void cleanup_module(){
	printk("kernel module unloaded\n");
}
