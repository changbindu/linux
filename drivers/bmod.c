#include <linux/device.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/module.h>

extern int amod_value;

static int __init bmod_init(void)
{
	printk(KERN_ERR "init module B, amod_value=%d *******************\n", amod_value);
	return 0;
}

static void __exit bmod_exit(void)
{
}

module_init(bmod_init);
module_exit(bmod_exit);

MODULE_LICENSE("GPL");
