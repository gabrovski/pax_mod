#include <linux/security.h>
#include <linux/module.h>
#include <linux/kernel.h>


static int pax_mod_ptrace_access_check (struct task_struct *child, unsigned int mode)
{
  return 0;
}

static int pax_mod_ptrace_traceme (struct task_struct *parent)
{
  return 0;
}

static int pax_mod_quotactl (int cmds, int type, int id, struct super_block *sb)
{
  return 0;
}

static int pax_mod_quota_on (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_syslog (int type)
{
  return 0;
}

static int pax_mod_settime (const struct timespec *ts, const struct timezone *tz)
{
  return 0;
}

static int pax_mod_vm_enough_memory (struct mm_struct *mm, long pages)
{
  return 0;
}

static int pax_mod_bprm_set_creds (struct linux_binprm *bprm)
{
  return 0;
}

static int pax_mod_bprm_check_security (struct linux_binprm *bprm)
{
  return 0;
}

static int pax_mod_bprm_secureexec (struct linux_binprm *bprm)
{
  return 0;
}

static void pax_mod_bprm_committing_creds (struct linux_binprm *bprm)
{
  return;
}

static void pax_mod_bprm_committed_creds (struct linux_binprm *bprm)
{
  return;
}

static int pax_mod_sb_alloc_security (struct super_block *sb)
{
  return 0;
}

static void pax_mod_sb_free_security (struct super_block *sb)
{
  return;
}

static int pax_mod_sb_copy_data (char *orig, char *copy)
{
  return 0;
}

static int pax_mod_sb_remount (struct super_block *sb, void *data)
{
  return 0;
}

static int pax_mod_sb_kern_mount (struct super_block *sb, int flags, void *data)
{
  return 0;
}

static int pax_mod_sb_show_options (struct seq_file *m, struct super_block *sb)
{
  return 0;
}

static int pax_mod_sb_statfs (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_sb_umount (struct vfsmount *mnt, int flags)
{
  return 0;
}

static int pax_mod_sb_parse_opts_str (char *options, struct security_mnt_opts *opts)
{
  return 0;
}

static int pax_mod_path_unlink (struct path *dir, struct dentry *dentry)
{
  return 0;
}

static int pax_mod_path_mkdir (struct path *dir, struct dentry *dentry, int mode)
{
  return 0;
}

static int pax_mod_path_rmdir (struct path *dir, struct dentry *dentry)
{
  return 0;
}

static int pax_mod_path_truncate (struct path *path)
{
  return 0;
}

static int pax_mod_path_chown (struct path *path, uid_t uid, gid_t gid)
{
  return 0;
}

static int pax_mod_path_chroot (struct path *path)
{
  return 0;
}

static int pax_mod_inode_alloc_security (struct inode *inode)
{
  return 0;
}

static void pax_mod_inode_free_security (struct inode *inode)
{
  return;
}

static int pax_mod_inode_unlink (struct inode *dir, struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_mkdir (struct inode *dir, struct dentry *dentry, int mode)
{
  return 0;
}

static int pax_mod_inode_rmdir (struct inode *dir, struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_readlink (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_follow_link (struct dentry *dentry, struct nameidata *nd)
{
  return 0;
}

static int pax_mod_inode_permission (struct inode *inode, int mask)
{
  return 0;
}

static int pax_mod_inode_getattr (struct vfsmount *mnt, struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_getxattr (struct dentry *dentry, const char *name)
{
  return 0;
}

static int pax_mod_inode_listxattr (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_removexattr (struct dentry *dentry, const char *name)
{
  return 0;
}

static int pax_mod_inode_need_killpriv (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_killpriv (struct dentry *dentry)
{
  return 0;
}

static int pax_mod_inode_getsecurity (const struct inode *inode, const char *name, void **buffer, bool alloc)
{
  return 0;
}

static int pax_mod_inode_setsecurity (struct inode *inode, const char *name, const void *value, size_t size, int flags)
{
  return 0;
}

static int pax_mod_inode_listsecurity (struct inode *inode, char *buffer, size_t buffer_size)
{
  return 0;
}

static void pax_mod_inode_getsecid (const struct inode *inode, u32 *secid)
{
  return;
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

static int pax_mod_file_lock (struct file *file, unsigned int cmd)
{
  return 0;
}

static int pax_mod_file_set_fowner (struct file *file)
{
  return 0;
}

static int pax_mod_file_receive (struct file *file)
{
  return 0;
}

static int pax_mod_dentry_open (struct file *file, const struct cred *cred)
{
  return 0;
}

static int pax_mod_task_create (unsigned long clone_flags)
{
  return 0;
}

static int pax_mod_cred_alloc_blank (struct cred *cred, gfp_t gfp)
{
  return 0;
}

static void pax_mod_cred_free (struct cred *cred)
{
  return;
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

static void pax_mod_task_getsecid (struct task_struct *p, u32 *secid)
{
  return;
}

static int pax_mod_task_setnice (struct task_struct *p, int nice)
{
  return 0;
}

static int pax_mod_task_setioprio (struct task_struct *p, int ioprio)
{
  return 0;
}

static int pax_mod_task_getioprio (struct task_struct *p)
{
  return 0;
}

static int pax_mod_task_setscheduler (struct task_struct *p)
{
  return 0;
}

static int pax_mod_task_getscheduler (struct task_struct *p)
{
  return 0;
}

static int pax_mod_task_movememory (struct task_struct *p)
{
  return 0;
}

static int pax_mod_task_wait (struct task_struct *p)
{
  return 0;
}

static void pax_mod_task_to_inode (struct task_struct *p, struct inode *inode)
{
  return;
}

static int pax_mod_ipc_permission (struct kern_ipc_perm *ipcp, short flag)
{
  return 0;
}

static void pax_mod_ipc_getsecid (struct kern_ipc_perm *ipcp, u32 *secid)
{
  return;
}

static int pax_mod_msg_msg_alloc_security (struct msg_msg *msg)
{
  return 0;
}

static void pax_mod_msg_msg_free_security (struct msg_msg *msg)
{
  return;
}

static int pax_mod_msg_queue_alloc_security (struct msg_queue *msq)
{
  return 0;
}

static void pax_mod_msg_queue_free_security (struct msg_queue *msq)
{
  return;
}

static int pax_mod_msg_queue_associate (struct msg_queue *msq, int msqflg)
{
  return 0;
}

static int pax_mod_msg_queue_msgctl (struct msg_queue *msq, int cmd)
{
  return 0;
}

static int pax_mod_shm_alloc_security (struct shmid_kernel *shp)
{
  return 0;
}

static void pax_mod_shm_free_security (struct shmid_kernel *shp)
{
  return;
}

static int pax_mod_shm_associate (struct shmid_kernel *shp, int shmflg)
{
  return 0;
}

static int pax_mod_shm_shmctl (struct shmid_kernel *shp, int cmd)
{
  return 0;
}

static int pax_mod_sem_alloc_security (struct sem_array *sma)
{
  return 0;
}

static void pax_mod_sem_free_security (struct sem_array *sma)
{
  return;
}

static int pax_mod_sem_associate (struct sem_array *sma, int semflg)
{
  return 0;
}

static int pax_mod_sem_semctl (struct sem_array *sma, int cmd)
{
  return 0;
}

static int pax_mod_netlink_send (struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

static int pax_mod_netlink_recv (struct sk_buff *skb, int cap)
{
  return 0;
}

static void pax_mod_d_instantiate (struct dentry *dentry, struct inode *inode)
{
  return;
}

static int pax_mod_getprocattr (struct task_struct *p, char *name, char **value)
{
  return 0;
}

static int pax_mod_setprocattr (struct task_struct *p, char *name, void *value, size_t size)
{
  return 0;
}

static int pax_mod_secid_to_secctx (u32 secid, char **secdata, u32 *seclen)
{
  return 0;
}

static int pax_mod_secctx_to_secid (const char *secdata, u32 seclen, u32 *secid)
{
  return 0;
}

static void pax_mod_release_secctx (char *secdata, u32 seclen)
{
  return;
}

static int pax_mod_unix_stream_connect (struct sock *sock, struct sock *other, struct sock *newsk)
{
  return 0;
}

static int pax_mod_unix_may_send (struct socket *sock, struct socket *other)
{
  return 0;
}

static int pax_mod_socket_create (int family, int type, int protocol, int kern)
{
  return 0;
}

static int pax_mod_socket_listen (struct socket *sock, int backlog)
{
  return 0;
}

static int pax_mod_socket_accept (struct socket *sock, struct socket *newsock)
{
  return 0;
}

static int pax_mod_socket_getsockname (struct socket *sock)
{
  return 0;
}

static int pax_mod_socket_getpeername (struct socket *sock)
{
  return 0;
}

static int pax_mod_socket_getsockopt (struct socket *sock, int level, int optname)
{
  return 0;
}

static int pax_mod_socket_setsockopt (struct socket *sock, int level, int optname)
{
  return 0;
}

static int pax_mod_socket_shutdown (struct socket *sock, int how)
{
  return 0;
}

static int pax_mod_socket_sock_rcv_skb (struct sock *sk, struct sk_buff *skb)
{
  return 0;
}

static int pax_mod_socket_getpeersec_stream (struct socket *sock, char __user *optval, int __user *optlen, unsigned len)
{
  return 0;
}

static int pax_mod_socket_getpeersec_dgram (struct socket *sock, struct sk_buff *skb, u32 *secid)
{
  return 0;
}

static int pax_mod_sk_alloc_security (struct sock *sk, int family, gfp_t priority)
{
  return 0;
}

static void pax_mod_sk_free_security (struct sock *sk)
{
  return;
}

static void pax_mod_sk_clone_security (const struct sock *sk, struct sock *newsk)
{
  return;
}

static void pax_mod_sk_getsecid (struct sock *sk, u32 *secid)
{
  return;
}

static void pax_mod_sock_graft (struct sock *sk, struct socket *parent)
{
  return;
}

static void pax_mod_inet_csk_clone (struct sock *newsk, const struct request_sock *req)
{
  return;
}

static void pax_mod_inet_conn_established (struct sock *sk, struct sk_buff *skb)
{
  return;
}

static int pax_mod_secmark_relabel_packet (u32 secid)
{
  return 0;
}

static void pax_mod_secmark_refcount_inc (void)
{
  return;
}

static void pax_mod_secmark_refcount_dec (void)
{
  return;
}

static void pax_mod_req_classify_flow (const struct request_sock *req, struct flowi *fl)
{
  return;
}

static int pax_mod_xfrm_policy_clone_security (struct xfrm_sec_ctx *old_ctx, struct xfrm_sec_ctx **new_ctx)
{
  return 0;
}

static void pax_mod_xfrm_policy_free_security (struct xfrm_sec_ctx *ctx)
{
  return;
}

static int pax_mod_xfrm_policy_delete_security (struct xfrm_sec_ctx *ctx)
{
  return 0;
}

static void pax_mod_xfrm_state_free_security (struct xfrm_state *x)
{
  return;
}

static int pax_mod_xfrm_state_delete_security (struct xfrm_state *x)
{
  return 0;
}

static int pax_mod_xfrm_policy_lookup (struct xfrm_sec_ctx *ctx, u32 fl_secid, u8 dir)
{
  return 0;
}

static int pax_mod_xfrm_decode_session (struct sk_buff *skb, u32 *secid, int ckall)
{
  return 0;
}

static int pax_mod_key_alloc (struct key *key, const struct cred *cred, unsigned long flags)
{
  return 0;
}

static void pax_mod_key_free (struct key *key)
{
  return;
}

static int pax_mod_audit_rule_init (u32 field, u32 op, char *rulestr, void **lsmrule)
{
  return 0;
}

static int pax_mod_audit_rule_known (struct audit_krule *krule)
{
  return 0;
}

static void pax_mod_audit_rule_free (void *lsmrule)
{
  return;
}

static struct security_operations pax_mod_sec_ops = {
  .name = "pax_mod",

  .ptrace_access_check  =  pax_mod_ptrace_access_check,
  .ptrace_traceme  =  pax_mod_ptrace_traceme,
  .quotactl  =  pax_mod_quotactl,
  .quota_on  =  pax_mod_quota_on,
  .syslog  =  pax_mod_syslog,
  .settime  =  pax_mod_settime,
  .vm_enough_memory  =  pax_mod_vm_enough_memory,
  .bprm_set_creds  =  pax_mod_bprm_set_creds,
  .bprm_check_security  =  pax_mod_bprm_check_security,
  .bprm_secureexec  =  pax_mod_bprm_secureexec,
  .bprm_committing_creds  =  pax_mod_bprm_committing_creds,
  .bprm_committed_creds  =  pax_mod_bprm_committed_creds,
  .sb_alloc_security  =  pax_mod_sb_alloc_security,
  .sb_free_security  =  pax_mod_sb_free_security,
  .sb_copy_data  =  pax_mod_sb_copy_data,
  .sb_remount  =  pax_mod_sb_remount,
  .sb_kern_mount  =  pax_mod_sb_kern_mount,
  .sb_show_options  =  pax_mod_sb_show_options,
  .sb_statfs  =  pax_mod_sb_statfs,
  .sb_umount  =  pax_mod_sb_umount,
  .sb_parse_opts_str  =  pax_mod_sb_parse_opts_str,
#ifdef CONFIG_SECURITY_PATH
  .path_unlink  =  pax_mod_path_unlink,
  .path_mkdir  =  pax_mod_path_mkdir,
  .path_rmdir  =  pax_mod_path_rmdir,
  .path_truncate  =  pax_mod_path_truncate,
  .path_chown  =  pax_mod_path_chown,
  .path_chroot  =  pax_mod_path_chroot,
#endif
  .inode_alloc_security  =  pax_mod_inode_alloc_security,
  .inode_free_security  =  pax_mod_inode_free_security,
  .inode_unlink  =  pax_mod_inode_unlink,
  .inode_mkdir  =  pax_mod_inode_mkdir,
  .inode_rmdir  =  pax_mod_inode_rmdir,
  .inode_readlink  =  pax_mod_inode_readlink,
  .inode_follow_link  =  pax_mod_inode_follow_link,
  .inode_permission  =  pax_mod_inode_permission,
  .inode_getattr  =  pax_mod_inode_getattr,
  .inode_getxattr  =  pax_mod_inode_getxattr,
  .inode_listxattr  =  pax_mod_inode_listxattr,
  .inode_removexattr  =  pax_mod_inode_removexattr,
  .inode_need_killpriv  =  pax_mod_inode_need_killpriv,
  .inode_killpriv  =  pax_mod_inode_killpriv,
  .inode_getsecurity  =  pax_mod_inode_getsecurity,
  .inode_setsecurity  =  pax_mod_inode_setsecurity,
  .inode_listsecurity  =  pax_mod_inode_listsecurity,
  .inode_getsecid  =  pax_mod_inode_getsecid,
  .file_permission  =  pax_mod_file_permission,
  .file_alloc_security  =  pax_mod_file_alloc_security,
  .file_free_security  =  pax_mod_file_free_security,
  .file_lock  =  pax_mod_file_lock,
  .file_set_fowner  =  pax_mod_file_set_fowner,
  .file_receive  =  pax_mod_file_receive,
  .dentry_open  =  pax_mod_dentry_open,
  .task_create  =  pax_mod_task_create,
  .cred_alloc_blank  =  pax_mod_cred_alloc_blank,
  .cred_free  =  pax_mod_cred_free,
  .task_setpgid  =  pax_mod_task_setpgid,
  .task_getpgid  =  pax_mod_task_getpgid,
  .task_getsid  =  pax_mod_task_getsid,
  .task_getsecid  =  pax_mod_task_getsecid,
  .task_setnice  =  pax_mod_task_setnice,
  .task_setioprio  =  pax_mod_task_setioprio,
  .task_getioprio  =  pax_mod_task_getioprio,
  .task_setscheduler  =  pax_mod_task_setscheduler,
  .task_getscheduler  =  pax_mod_task_getscheduler,
  .task_movememory  =  pax_mod_task_movememory,
  .task_wait  =  pax_mod_task_wait,
  .task_to_inode  =  pax_mod_task_to_inode,
  .ipc_permission  =  pax_mod_ipc_permission,
  .ipc_getsecid  =  pax_mod_ipc_getsecid,
  .msg_msg_alloc_security  =  pax_mod_msg_msg_alloc_security,
  .msg_msg_free_security  =  pax_mod_msg_msg_free_security,
  .msg_queue_alloc_security  =  pax_mod_msg_queue_alloc_security,
  .msg_queue_free_security  =  pax_mod_msg_queue_free_security,
  .msg_queue_associate  =  pax_mod_msg_queue_associate,
  .msg_queue_msgctl  =  pax_mod_msg_queue_msgctl,
  .shm_alloc_security  =  pax_mod_shm_alloc_security,
  .shm_free_security  =  pax_mod_shm_free_security,
  .shm_associate  =  pax_mod_shm_associate,
  .shm_shmctl  =  pax_mod_shm_shmctl,
  .sem_alloc_security  =  pax_mod_sem_alloc_security,
  .sem_free_security  =  pax_mod_sem_free_security,
  .sem_associate  =  pax_mod_sem_associate,
  .sem_semctl  =  pax_mod_sem_semctl,
  .netlink_send  =  pax_mod_netlink_send,
  .netlink_recv  =  pax_mod_netlink_recv,
  .d_instantiate  =  pax_mod_d_instantiate,
  .getprocattr  =  pax_mod_getprocattr,
  .setprocattr  =  pax_mod_setprocattr,
  .secid_to_secctx  =  pax_mod_secid_to_secctx,
  .secctx_to_secid  =  pax_mod_secctx_to_secid,
  .release_secctx  =  pax_mod_release_secctx,
#ifdef CONFIG_SECURITY_NETWORK
  .unix_stream_connect  =  pax_mod_unix_stream_connect,
  .unix_may_send  =  pax_mod_unix_may_send,
  .socket_create  =  pax_mod_socket_create,
  .socket_listen  =  pax_mod_socket_listen,
  .socket_accept  =  pax_mod_socket_accept,
  .socket_getsockname  =  pax_mod_socket_getsockname,
  .socket_getpeername  =  pax_mod_socket_getpeername,
  .socket_getsockopt  =  pax_mod_socket_getsockopt,
  .socket_setsockopt  =  pax_mod_socket_setsockopt,
  .socket_shutdown  =  pax_mod_socket_shutdown,
  .socket_sock_rcv_skb  =  pax_mod_socket_sock_rcv_skb,
  .socket_getpeersec_stream  =  pax_mod_socket_getpeersec_stream,
  .socket_getpeersec_dgram  =  pax_mod_socket_getpeersec_dgram,
  .sk_alloc_security  =  pax_mod_sk_alloc_security,
  .sk_free_security  =  pax_mod_sk_free_security,
  .sk_clone_security  =  pax_mod_sk_clone_security,
  .sk_getsecid  =  pax_mod_sk_getsecid,
  .sock_graft  =  pax_mod_sock_graft,
  .inet_csk_clone  =  pax_mod_inet_csk_clone,
  .inet_conn_established  =  pax_mod_inet_conn_established,
  .secmark_relabel_packet  =  pax_mod_secmark_relabel_packet,
  .secmark_refcount_inc  =  pax_mod_secmark_refcount_inc,
  .secmark_refcount_dec  =  pax_mod_secmark_refcount_dec,
  .req_classify_flow  =  pax_mod_req_classify_flow,
#endif	/* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
  .xfrm_policy_clone_security  =  pax_mod_xfrm_policy_clone_security,
  .xfrm_policy_free_security  =  pax_mod_xfrm_policy_free_security,
  .xfrm_policy_delete_security  =  pax_mod_xfrm_policy_delete_security,
  .xfrm_state_free_security  =  pax_mod_xfrm_state_free_security,
  .xfrm_state_delete_security  =  pax_mod_xfrm_state_delete_security,
  .xfrm_policy_lookup  =  pax_mod_xfrm_policy_lookup,
  .xfrm_decode_session  =  pax_mod_xfrm_decode_session,
#endif	/* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
  .key_alloc  =  pax_mod_key_alloc,
  .key_free  =  pax_mod_key_free,
#endif	/* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
  .audit_rule_init  =  pax_mod_audit_rule_init,
  .audit_rule_known  =  pax_mod_audit_rule_known,
  .audit_rule_free  =  pax_mod_audit_rule_free,
#endif /* CONFIG_AUDIT */
};

int init_module() { return 0; }

void cleanup_module() { return; }

