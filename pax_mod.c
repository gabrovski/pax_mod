
/*
 * Using the root plug example from Linux journal as a starting point for pax_mod
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/usb.h>

/* flag to keep track of how we were registered */
static int secondary;

static int pax_mod_ptrace (struct task_struct *parent,
			    struct task_struct *child)
{
	return 0;
}

static int pax_mod_capget (struct task_struct *target,
			    kernel_cap_t *effective,
			    kernel_cap_t *inheritable,
			    kernel_cap_t *permitted)
{
	return 0;
}

static int pax_mod_capset_check (struct task_struct *target,
				  kernel_cap_t *effective,
				  kernel_cap_t *inheritable,
				  kernel_cap_t *permitted)
{
	return 0;
}

static void pax_mod_capset_set (struct task_struct *target,
				 kernel_cap_t *effective,
				 kernel_cap_t *inheritable,
				 kernel_cap_t *permitted)
{
	return;
}

static int pax_mod_acct (struct file *file)
{
	return 0;
}

static int pax_mod_capable (struct task_struct *tsk, int cap)
{
	if (cap_is_fs_cap (cap) ? tsk->fsuid == 0 : tsk->euid == 0)
		/* capability granted */
		return 0;

	/* capability denied */
	return -EPERM;
}

static int pax_mod_sys_security (unsigned int id, unsigned int call,
				  unsigned long *args)
{
	return -ENOSYS;
}

static int pax_mod_quotactl (int cmds, int type, int id,
			      struct super_block *sb)
{
	return 0;
}

static int pax_mod_quota_on (struct file *f)
{
	return 0;
}

static int pax_mod_bprm_alloc_security (struct linux_binprm *bprm)
{
	return 0;
}

static void pax_mod_bprm_free_security (struct linux_binprm *bprm)
{
	return;
}

static void pax_mod_bprm_compute_creds (struct linux_binprm *bprm)
{
	return;
}

static int pax_mod_bprm_set_security (struct linux_binprm *bprm)
{
	return 0;
}

static int pax_mod_sb_alloc_security (struct super_block *sb)
{
	return 0;
}

static void pax_mod_sb_free_security (struct super_block *sb)
{
	return;
}

static int pax_mod_sb_statfs (struct super_block *sb)
{
	return 0;
}

static int pax_mod_mount (char *dev_name, struct nameidata *nd, char *type,
			   unsigned long flags, void *data)
{
	return 0;
}

static int pax_mod_check_sb (struct vfsmount *mnt, struct nameidata *nd)
{
	return 0;
}

static int pax_mod_umount (struct vfsmount *mnt, int flags)
{
	return 0;
}

static void pax_mod_umount_close (struct vfsmount *mnt)
{
	return;
}

static void pax_mod_umount_busy (struct vfsmount *mnt)
{
	return;
}

static void pax_mod_post_remount (struct vfsmount *mnt, unsigned long flags,
				   void *data)
{
	return;
}


static void pax_mod_post_mountroot (void)
{
	return;
}

static void pax_mod_post_addmount (struct vfsmount *mnt,
				    struct nameidata *nd)
{
	return;
}

static int pax_mod_pivotroot (struct nameidata *old_nd,
			       struct nameidata *new_nd)
{
	return 0;
}

static void pax_mod_post_pivotroot (struct nameidata *old_nd,
				     struct nameidata *new_nd)
{
	return;
}

static int pax_mod_inode_alloc_security (struct inode *inode)
{
	return 0;
}

static void pax_mod_inode_free_security (struct inode *inode)
{
	return;
}

static int pax_mod_inode_create (struct inode *inode,
				  struct dentry *dentry,
				  int mask)
{
	return 0;
}

static void pax_mod_inode_post_create (struct inode *inode,
					struct dentry *dentry,
					int mask)
{
	return;
}

static int pax_mod_inode_link (struct dentry *old_dentry,
				struct inode *inode,
				struct dentry *new_dentry)
{
	return 0;
}

static void pax_mod_inode_post_link (struct dentry *old_dentry,
				      struct inode *inode,
				      struct dentry *new_dentry)
{
	return;
}

static int pax_mod_inode_unlink (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int pax_mod_inode_symlink (struct inode *inode, struct dentry *dentry,
				   const char *name)
{
	return 0;
}

static void pax_mod_inode_post_symlink (struct inode *inode,
					 struct dentry *dentry,
					 const char *name)
{
	return;
}

static int pax_mod_inode_mkdir (struct inode *inode,
				 struct dentry *dentry,
				 int mask)
{
	return 0;
}

static void pax_mod_inode_post_mkdir (struct inode *inode,
				       struct dentry *dentry,
				       int mask)
{
	return;
}

static int pax_mod_inode_rmdir (struct inode *inode, struct dentry *dentry)
{
	return 0;
}

static int pax_mod_inode_mknod (struct inode *inode, struct dentry *dentry,
				 int major, dev_t minor)
{
	return 0;
}

static void pax_mod_inode_post_mknod (struct inode *inode,
				       struct dentry *dentry,
				       int major, dev_t minor)
{
	return;
}

static int pax_mod_inode_rename (struct inode *old_inode,
				  struct dentry *old_dentry,
				  struct inode *new_inode,
				  struct dentry *new_dentry)
{
	return 0;
}

static void pax_mod_inode_post_rename (struct inode *old_inode,
					struct dentry *old_dentry,
					struct inode *new_inode,
					struct dentry *new_dentry)
{
	return;
}

static int pax_mod_inode_readlink (struct dentry *dentry)
{
	return 0;
}

static int pax_mod_inode_follow_link (struct dentry *dentry,
				       struct nameidata *nameidata)
{
	return 0;
}

static int pax_mod_inode_permission (struct inode *inode, int mask)
{
	return 0;
}

static int pax_mod_inode_permission_lite (struct inode *inode, int mask)
{
	return 0;
}

static int pax_mod_inode_setattr (struct dentry *dentry, struct iattr *iattr)
{
	return 0;
}

static int pax_mod_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
	return 0;
}

static void pax_mod_post_lookup (struct inode *ino, struct dentry *d)
{
	return;
}

static void pax_mod_delete (struct inode *ino)
{
	return;
}

static int pax_mod_inode_setxattr (struct dentry *dentry, char *name,
				    void *value, size_t size, int flags)
{
	return 0;
}

static int pax_mod_inode_getxattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int pax_mod_inode_listxattr (struct dentry *dentry)
{
	return 0;
}

static int pax_mod_inode_removexattr (struct dentry *dentry, char *name)
{
	return 0;
}

static int pax_mod_file_permission (struct file *file, int mask)
{
	return 0;
}

static int pax_mod_file_alloc_security (struct file *file)
{
	return 0;
}

static void pax_mod_file_free_security (struct file *file)
{
	return;
}

static int pax_mod_file_llseek (struct file *file)
{
	return 0;
}

static int pax_mod_file_ioctl (struct file *file, unsigned int command,
				unsigned long arg)
{
	return 0;
}

static int pax_mod_file_mmap (struct file *file, unsigned long prot,
			       unsigned long flags)
{
	return 0;
}

static int pax_mod_file_mprotect (struct vm_area_struct *vma,
				   unsigned long prot)
{
	return 0;
}

static int pax_mod_file_lock (struct file *file, unsigned int cmd)
{
	return 0;
}

static int pax_mod_file_fcntl (struct file *file, unsigned int cmd,
				unsigned long arg)
{
	return 0;
}

static int pax_mod_file_set_fowner (struct file *file)
{
	return 0;
}

static int pax_mod_file_send_sigiotask (struct task_struct *tsk,
					 struct fown_struct *fown,
					 int fd, int reason)
{
	return 0;
}

static int pax_mod_file_receive (struct file *file)
{
	return 0;
}

static int pax_mod_task_create (unsigned long clone_flags)
{
	return 0;
}

static int pax_mod_task_alloc_security (struct task_struct *p)
{
	return 0;
}

static void pax_mod_task_free_security (struct task_struct *p)
{
	return;
}

static int pax_mod_task_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int pax_mod_task_post_setuid (uid_t id0, uid_t id1, uid_t id2, int flags)
{
	return 0;
}

static int pax_mod_task_setgid (gid_t id0, gid_t id1, gid_t id2, int flags)
{
	return 0;
}

static int pax_mod_task_setpgid (struct task_struct *p, pid_t pgid)
{
	return 0;
}

static int pax_mod_task_getpgid (struct task_struct *p)
{
	return 0;
}

static int pax_mod_task_getsid (struct task_struct *p)
{
	return 0;
}

static int pax_mod_task_setgroups (int gidsetsize, gid_t * grouplist)
{
	return 0;
}

static int pax_mod_task_setnice (struct task_struct *p, int nice)
{
	return 0;
}

static int pax_mod_task_setrlimit (unsigned int resource, struct rlimit *new_rlim)
{
	return 0;
}

static int pax_mod_task_setscheduler (struct task_struct *p, int policy,
				       struct sched_param *lp)
{
	return 0;
}

static int pax_mod_task_getscheduler (struct task_struct *p)
{
	return 0;
}

static int pax_mod_task_wait (struct task_struct *p)
{
	return 0;
}

static int pax_mod_task_kill (struct task_struct *p,
			       struct siginfo *info,
			       int sig)
{
	return 0;
}

static int pax_mod_task_prctl (int option,
				unsigned long arg2,
				unsigned long arg3,
				unsigned long arg4,
				unsigned long arg5)
{
	return 0;
}

static void pax_mod_task_kmod_set_label (void)
{
	return;
}

static void pax_mod_task_reparent_to_init (struct task_struct *p)
{
	p->euid = p->fsuid = 0;
	return;
}

static int pax_mod_register (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}

static int pax_mod_unregister (const char *name, struct security_operations *ops)
{
	return -EINVAL;
}


/* the interesting stuff... */

/* default is a generic type of usb to serial converter */
static int vendor_id = 0x0557;
static int product_id = 0x2008;

MODULE_PARM(vendor_id, "h");
MODULE_PARM_DESC(vendor_id, "USB Vendor ID of device to look for");

MODULE_PARM(product_id, "h");
MODULE_PARM_DESC(product_id, "USB Product ID of device to look for");


/* should we print out debug messages */
static int debug = 0;

MODULE_PARM(debug, "i");
MODULE_PARM_DESC(debug, "Debug enabled or not");

#if defined(CONFIG_SECURITY_PAX_MOD_MODULE)
#define MY_NAME THIS_MODULE->name
#else
#define MY_NAME "root_plug"
#endif

#define dbg(fmt, arg...)					\
	do {							\
		if (debug)					\
			printk(KERN_DEBUG "%s: %s: " fmt ,	\
				MY_NAME , __FUNCTION__ , 	\
				## arg);			\
	} while (0)

extern struct list_head usb_bus_list;
extern struct semaphore usb_bus_list_lock;

static int match_device (struct usb_device *dev)
{
	int retval = -ENODEV;
	int child;

	dbg ("looking at vendor %d, product %d\n",
	     dev->descriptor.idVendor,
	     dev->descriptor.idProduct);

	/* see if this device matches */
	if ((dev->descriptor.idVendor == vendor_id) &&
	    (dev->descriptor.idProduct == product_id)) {
		dbg ("found the device!\n");
		retval = 0;
		goto exit;
	}

	/* look through all of the children of this device */
	for (child = 0; child < dev->maxchild; child) {
		if (dev->children[child]) {
			retval = match_device (dev->children[child]);
			if (retval == 0)
				goto exit;
		}
	}
exit:
	return retval;
}

static int find_usb_device (void)
{
	struct list_head *buslist;
	struct usb_bus *bus;
	int retval = -ENODEV;
	
	down (&usb_bus_list_lock);
	for (buslist = usb_bus_list.next;
	     buslist != &usb_bus_list; 
	     buslist = buslist->next) {
		bus = container_of (buslist, struct usb_bus, bus_list);
		retval = match_device(bus->root_hub);
		if (retval == 0)
			goto exit;
	}
exit:
	up (&usb_bus_list_lock);
	return retval;
}
	

static int pax_mod_bprm_check_security (struct linux_binprm *bprm)
{
	dbg ("file %s, e_uid = %d, e_gid = %d\n",
	     bprm->filename, bprm->e_uid, bprm->e_gid);

	if (bprm->e_gid == 0) {
		if (find_usb_device() != 0) {
			dbg ("e_gid = 0, and device not found, "
				"task not allowed to run...\n");
			return -EPERM;
		}
	}

	return 0;
}

static struct security_operations pax_mod_security_ops = {
	.ptrace =			pax_mod_ptrace,
	.capget =			pax_mod_capget,
	.capset_check =			pax_mod_capset_check,
	.capset_set =			pax_mod_capset_set,
	.acct =				pax_mod_acct,
	.capable =			pax_mod_capable,
	.sys_security =			pax_mod_sys_security,
	.quotactl =			pax_mod_quotactl,
	.quota_on =			pax_mod_quota_on,

	.bprm_alloc_security =		pax_mod_bprm_alloc_security,
	.bprm_free_security =		pax_mod_bprm_free_security,
	.bprm_compute_creds =		pax_mod_bprm_compute_creds,
	.bprm_set_security =		pax_mod_bprm_set_security,
	.bprm_check_security =		pax_mod_bprm_check_security,

	.sb_alloc_security =		pax_mod_sb_alloc_security,
	.sb_free_security =		pax_mod_sb_free_security,
	.sb_statfs =			pax_mod_sb_statfs,
	.sb_mount =			pax_mod_mount,
	.sb_check_sb =			pax_mod_check_sb,
	.sb_umount =			pax_mod_umount,
	.sb_umount_close =		pax_mod_umount_close,
	.sb_umount_busy =		pax_mod_umount_busy,
	.sb_post_remount =		pax_mod_post_remount,
	.sb_post_mountroot =		pax_mod_post_mountroot,
	.sb_post_addmount =		pax_mod_post_addmount,
	.sb_pivotroot =			pax_mod_pivotroot,
	.sb_post_pivotroot =		pax_mod_post_pivotroot,
	
	.inode_alloc_security =		pax_mod_inode_alloc_security,
	.inode_free_security =		pax_mod_inode_free_security,
	.inode_create =			pax_mod_inode_create,
	.inode_post_create =		pax_mod_inode_post_create,
	.inode_link =			pax_mod_inode_link,
	.inode_post_link =		pax_mod_inode_post_link,
	.inode_unlink =			pax_mod_inode_unlink,
	.inode_symlink =		pax_mod_inode_symlink,
	.inode_post_symlink =		pax_mod_inode_post_symlink,
	.inode_mkdir =			pax_mod_inode_mkdir,
	.inode_post_mkdir =		pax_mod_inode_post_mkdir,
	.inode_rmdir =			pax_mod_inode_rmdir,
	.inode_mknod =			pax_mod_inode_mknod,
	.inode_post_mknod =		pax_mod_inode_post_mknod,
	.inode_rename =			pax_mod_inode_rename,
	.inode_post_rename =		pax_mod_inode_post_rename,
	.inode_readlink =		pax_mod_inode_readlink,
	.inode_follow_link =		pax_mod_inode_follow_link,
	.inode_permission =		pax_mod_inode_permission,
	.inode_permission_lite =	pax_mod_inode_permission_lite,
	.inode_setattr =		pax_mod_inode_setattr,
	.inode_getattr =		pax_mod_inode_getattr,
	.inode_post_lookup =		pax_mod_post_lookup,
	.inode_delete =			pax_mod_delete,
	.inode_setxattr =		pax_mod_inode_setxattr,
	.inode_getxattr =		pax_mod_inode_getxattr,
	.inode_listxattr =		pax_mod_inode_listxattr,
	.inode_removexattr =		pax_mod_inode_removexattr,

	.file_permission =		pax_mod_file_permission,
	.file_alloc_security =		pax_mod_file_alloc_security,
	.file_free_security =		pax_mod_file_free_security,
	.file_llseek =			pax_mod_file_llseek,
	.file_ioctl =			pax_mod_file_ioctl,
	.file_mmap =			pax_mod_file_mmap,
	.file_mprotect =		pax_mod_file_mprotect,
	.file_lock =			pax_mod_file_lock,
	.file_fcntl =			pax_mod_file_fcntl,
	.file_set_fowner =		pax_mod_file_set_fowner,
	.file_send_sigiotask =		pax_mod_file_send_sigiotask,
	.file_receive =			pax_mod_file_receive,

	.task_create =			pax_mod_task_create,
	.task_alloc_security =		pax_mod_task_alloc_security,
	.task_free_security =		pax_mod_task_free_security,
	.task_setuid =			pax_mod_task_setuid,
	.task_post_setuid =		pax_mod_task_post_setuid,
	.task_setgid =			pax_mod_task_setgid,
	.task_setpgid =			pax_mod_task_setpgid,
	.task_getpgid =			pax_mod_task_getpgid,
	.task_getsid =			pax_mod_task_getsid,
	.task_setgroups =		pax_mod_task_setgroups,
	.task_setnice =			pax_mod_task_setnice,
	.task_setrlimit =		pax_mod_task_setrlimit,
	.task_setscheduler =		pax_mod_task_setscheduler,
	.task_getscheduler =		pax_mod_task_getscheduler,
	.task_wait =			pax_mod_task_wait,
	.task_kill =			pax_mod_task_kill,
	.task_prctl =			pax_mod_task_prctl,
	.task_kmod_set_label =		pax_mod_task_kmod_set_label,
	.task_reparent_to_init =	pax_mod_task_reparent_to_init,

	.register_security =		pax_mod_register,
	.unregister_security =		pax_mod_unregister,
};

static int __init pax_mod_init (void)
{
	/* register ourselves with the security framework */
	if (register_security (&pax_mod_security_ops)) {
		printk (KERN_INFO 
			"Failure registering Root Plug module with the kernel\n");
		/* try registering with primary module */
		if (mod_reg_security (MY_NAME, &pax_mod_security_ops)) {
			printk (KERN_INFO "Failure registering Root Plug "
				" module with primary security module.\n");
			return -EINVAL;
		}
		secondary = 1;
	}
	printk (KERN_INFO "Root Plug module initialized, "
		"vendor_id = %4.4x, product id = %4.4x\n", vendor_id, product_id);
	return 0;
}

static void __exit pax_mod_exit (void)
{
	/* remove ourselves from the security framework */
	if (secondary) {
		if (mod_unreg_security (MY_NAME, &pax_mod_security_ops))
			printk (KERN_INFO "Failure unregistering Root Plug "
				" module with primary module.\n");
	} else { 
		if (unregister_security (&pax_mod_security_ops)) {
			printk (KERN_INFO "Failure unregistering Root Plug "
				"module with the kernel\n");
		}
	}
	printk (KERN_INFO "Root Plug module removed\n");
}

module_init (pax_mod_init);
module_exit (pax_mod_exit);

MODULE_DESCRIPTION("Root Plug sample LSM module, written for Linux Journal article");
MODULE_LICENSE("GPL");

