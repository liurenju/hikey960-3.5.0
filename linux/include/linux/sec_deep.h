#ifndef _SEC_DEEP_ENABLED
#define _SEC_DEEP_ENABLED
#endif

// #include <linux/printk.h>
#define PAGE_TABLE_READ_ONLY
#define RENJU_DEBUG(...)	printk(KERN_ERR __VA_ARGS__)
