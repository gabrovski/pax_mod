#include <linux/security.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/traps.h>



static struct security_operations pax_mod_sec_ops = {
  .name = "pax_mod",
};

dotraplinkage void pax_mod_do_page_fault(struct pt_regs *regs, long error_code) {
  printk(KERN_INFO "my fault\n");
  do_page_fault(regs, error_code);
}

int init_module() { 
  printk(KERN_INFO "init module pax_mod\n");
  return 0; 
}

void cleanup_module() { 
  return; 
}

