#include <linux/module.h>
#include <linux/security.h>

int pid = 513;

static int __init krum_client_init(void) {
  printk(KERN_INFO "init kern_client with pid %d\n", pid);
  krum_pid_of_interest = pid;
  return 0;
}

void cleanup_module() {
  krum_pid_of_interest = 9999999;
}

MODULE_LICENSE("GPL");

security_initcall(krum_client_init);
