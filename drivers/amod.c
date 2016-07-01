#include <linux/device.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/module.h>

int amod_value;
EXPORT_SYMBOL(amod_value);

static int __init amod_init(void)
{
	printk(KERN_ERR "init module A *******************\n");
	amod_value = 111111;
	return 0;
}

static void __exit amod_exit(void)
{
}

module_init(amod_init);
module_exit(amod_exit);

MODULE_LICENSE("GPL");
