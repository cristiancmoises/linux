// SPDX-License-Identifier: GPL-2.0
/*
 * linux/kernel/capability.c
 *
 * Copyright (C) 1997  Andrew Main <zefram@fysh.org>
 *
 * Integrated into 2.1.97+,  Andrew G. Morgan <morgan@kernel.org>
 * 30 May 2002: Cleanup, Robert M. Love <rml@tech9.net>
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/pid_namespace.h>
#include <linux/user_namespace.h>
#include <linux/uaccess.h>

int file_caps_enabled = 1;

/* Function to disable file capabilities via kernel command line */
static int __init file_caps_disable(char *str)
{
	file_caps_enabled = 0;
	return 1;
}
__setup("no_file_caps", file_caps_disable);

#ifdef CONFIG_MULTIUSER

/*
 * Warning messages for legacy capability usage.
 */
static void warn_legacy_capability_use(void)
{
	char name[sizeof(current->comm)];

	pr_info_once("warning: `%s' uses 32-bit capabilities (legacy support in use)\n",
		     get_task_comm(name, current));
}

static void warn_deprecated_v2(void)
{
	char name[sizeof(current->comm)];

	pr_info_once("warning: `%s' uses deprecated v2 capabilities in a way that may be insecure
",
		     get_task_comm(name, current));
}

/*
 * Validate capability version and return size of capability array.
 * Returns the number of u32s in each capability flag array or a negative value on error.
 */
static int cap_validate_magic(cap_user_header_t header, unsigned *tocopy)
{
	__u32 version;

	if (get_user(version, &header->version))
		return -EFAULT;

	switch (version) {
	case _LINUX_CAPABILITY_VERSION_1:
		warn_legacy_capability_use();
		*tocopy = _LINUX_CAPABILITY_U32S_1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
		warn_deprecated_v2();
		/* fallthrough intended */
	case _LINUX_CAPABILITY_VERSION_3:
		*tocopy = _LINUX_CAPABILITY_U32S_3;
		break;
	default:
		if (put_user((u32)_KERNEL_CAPABILITY_VERSION, &header->version))
			return -EFAULT;
		return -EINVAL;
	}

	return 0;
}

/*
 * Retrieve the capabilities of the target process specified by pid.
 * Returns 0 on success and < 0 on error.
 */
static inline int cap_get_target_pid(pid_t pid, kernel_cap_t *pEp,
				     kernel_cap_t *pIp, kernel_cap_t *pPp)
{
	int ret;

	if (pid && (pid != task_pid_vnr(current))) {
		const struct task_struct *target;

		rcu_read_lock();
		target = find_task_by_vpid(pid);

		if (!target) {
			ret = -ESRCH;
		} else {
			ret = security_capget(target, pEp, pIp, pPp);
		}

		rcu_read_unlock();
	} else {
		ret = security_capget(current, pEp, pIp, pPp);
	}

	return ret;
}

/**
 * sys_capget - get the capabilities of a given process.
 * @header: pointer to a struct containing capability version and target pid data
 * @dataptr: pointer to a struct that receives the effective, permitted, and inheritable capabilities
 *
 * Returns 0 on success and < 0 on error.
 */
SYSCALL_DEFINE2(capget, cap_user_header_t, header, cap_user_data_t, dataptr)
{
	int ret = 0;
	pid_t pid;
	unsigned tocopy;
	kernel_cap_t pE, pI, pP;
	struct __user_cap_data_struct kdata[2];

	ret = cap_validate_magic(header, &tocopy);
	if ((dataptr == NULL) || (ret != 0))
		return ((dataptr == NULL) && (ret == -EINVAL)) ? 0 : ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	if (pid < 0)
		return -EINVAL;

	ret = cap_get_target_pid(pid, &pE, &pI, &pP);
	if (ret)
		return ret;

	/* Convert 64-bit capabilities to legacy 32-bit format */
	kdata[0].effective   = pE.val; kdata[1].effective   = pE.val >> 32;
	kdata[0].permitted   = pP.val; kdata[1].permitted   = pP.val >> 32;
	kdata[0].inheritable = pI.val; kdata[1].inheritable = pI.val >> 32;

	/* Handle implicit dropping of upper capability bits for legacy applications */
	if (copy_to_user(dataptr, kdata, tocopy * sizeof(kdata[0])))
		return -EFAULT;

	return 0;
}

static kernel_cap_t mk_kernel_cap(u32 low, u32 high)
{
	return (kernel_cap_t) { (low | ((u64)high << 32)) & CAP_VALID_MASK };
}

/**
 * sys_capset - set capabilities for a process.
 * @header: pointer to a struct containing capability version and target pid data
 * @data: pointer to a struct that contains the effective, permitted, and inheritable capabilities
 *
 * Returns 0 on success and < 0 on error.
 */
SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
{
	struct __user_cap_data_struct kdata[2] = { { 0, }, };
	unsigned tocopy, copybytes;
	kernel_cap_t inheritable, permitted, effective;
	struct cred *new;
	int ret;
	pid_t pid;

	ret = cap_validate_magic(header, &tocopy);
	if (ret != 0)
		return ret;

	if (get_user(pid, &header->pid))
		return -EFAULT;

	/* Only the current process can be affected */
	if (pid != 0 && pid != task_pid_vnr(current))
		return -EPERM;

	copybytes = tocopy * sizeof(struct __user_cap_data_struct);
	if (copybytes > sizeof(kdata))
		return -EFAULT;

	if (copy_from_user(&kdata, data, copybytes))
		return -EFAULT;

	effective   = mk_kernel_cap(kdata[0].effective,   kdata[1].effective);
	permitted   = mk_kernel_cap(kdata[0].permitted,   kdata[1].permitted);
	inheritable = mk_kernel_cap(kdata[0].inheritable, kdata[1].inheritable);

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = security_capset(new, current_cred(), &effective, &inheritable, &permitted);
	if (ret < 0)
		goto error;

	audit_log_capset(new, current_cred());

	return commit_creds(new);

error:
	abort_creds(new);
	return ret;
}

/**
 * has_ns_capability - Check if a task has a capability in a specific user namespace.
 * @t: The task in question
 * @ns: Target user namespace
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability in the specified user namespace.
 */
bool has_ns_capability(struct task_struct *t, struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NONE);
	rcu_read_unlock();

	return (ret == 0);
}

/**
 * has_capability - Check if a task has a capability in init_user_ns.
 * @t: The task in question
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability in init_user_ns.
 */
bool has_capability(struct task_struct *t, int cap)
{
	return has_ns_capability(t, &init_user_ns, cap);
}
EXPORT_SYMBOL(has_capability);

/**
 * has_ns_capability_noaudit - Check if a task has a capability (unaudited) in a specific user namespace.
 * @t: The task in question
 * @ns: Target user namespace
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability in the specified user namespace without auditing.
 */
bool has_ns_capability_noaudit(struct task_struct *t, struct user_namespace *ns, int cap)
{
	int ret;

	rcu_read_lock();
	ret = security_capable(__task_cred(t), ns, cap, CAP_OPT_NOAUDIT);
	rcu_read_unlock();

	return (ret == 0);
}

/**
 * has_capability_noaudit - Check if a task has a capability (unaudited) in init_user_ns.
 * @t: The task in question
 * @cap: The capability to be tested for
 *
 * Return true if the specified task has the given superior capability in init_user_ns without auditing.
 */
bool has_capability_noaudit(struct task_struct *t, int cap)
{
	return has_ns_capability_noaudit(t, &init_user_ns, cap);
}
EXPORT_SYMBOL(has_capability_noaudit);

/**
 * ns_capable - Determine if the current task has a superior capability in effect.
 * @ns: The user namespace to check in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability in the specified user namespace.
 */
bool ns_capable(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NONE);
}
EXPORT_SYMBOL(ns_capable);

/**
 * ns_capable_noaudit - Determine if the current task has a superior capability (unaudited).
 * @ns: The user namespace to check in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability in the specified user namespace without auditing.
 */
bool ns_capable_noaudit(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_NOAUDIT);
}
EXPORT_SYMBOL(ns_capable_noaudit);

/**
 * ns_capable_setid - Check if the current task has a superior capability in effect during setid or setgroups syscall.
 * @ns: The user namespace to check in
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability in the specified user namespace while in a setid context.
 */
bool ns_capable_setid(struct user_namespace *ns, int cap)
{
	return ns_capable_common(ns, cap, CAP_OPT_INSETID);
}
EXPORT_SYMBOL(ns_capable_setid);

/**
 * capable - Determine if the current task has a superior capability in effect.
 * @cap: The capability to be tested for
 *
 * Return true if the current task has the given superior capability available for use.
 */
bool capable(int cap)
{
	return ns_capable(&init_user_ns, cap);
}
EXPORT_SYMBOL(capable);
#endif /* CONFIG_MULTIUSER */

/**
 * file_ns_capable - Check if the file's opener had a capability in effect.
 * @file: The file to check
 * @ns: The user namespace to check in
 * @cap: The capability to be tested for
 *
 * Return true if the task that opened the file had the capability in effect when the file was opened.
 */
bool file_ns_capable(const struct file *file, struct user_namespace *ns, int cap)
{
	if (WARN_ON_ONCE(!cap_valid(cap)))
		return false;

	return (security_capable(file->f_cred, ns, cap, CAP_OPT_NONE) == 0);
}
EXPORT_SYMBOL(file_ns_capable);

/**
 * privileged_wrt_inode_uidgid - Check if capabilities work over the inode's uid and gid.
 * @ns: The user namespace in question
 * @idmap: idmap of the mount from which the inode was found
 * @inode: The inode in question
 *
 * Return true if the inode's uid and gid are within the namespace.
 */
bool privileged_wrt_inode_uidgid(struct user_namespace *ns, struct mnt_idmap *idmap, const struct inode *inode)
{
	return vfsuid_has_mapping(ns, i_uid_into_vfsuid(idmap, inode)) &&
	       vfsgid_has_mapping(ns, i_gid_into_vfsgid(idmap, inode));
}

/**
 * capable_wrt_inode_uidgid - Check if the current task has a capability with respect to the inode's uid and gid.
 * @idmap: idmap of the mount from which the inode was found
 * @inode: The inode in question
 * @cap: The capability in question
 *
 * Return true if the current task has the given capability targeted at its user namespace and the inode's uid and gid are mapped.
 */
bool capable_wrt_inode_uidgid(struct mnt_idmap *idmap, const struct inode *inode, int cap)
{
	struct user_namespace *ns = current_user_ns();

	return ns_capable(ns, cap) && privileged_wrt_inode_uidgid(ns, idmap, inode);
}
EXPORT_SYMBOL(capable_wrt_inode_uidgid);

/**
 * ptracer_capable - Determine if the ptracer holds CAP_SYS_PTRACE in the namespace.
 * @tsk: The task that may be ptraced
 * @ns: The user namespace to search for CAP_SYS_PTRACE in
 *
 * Return true if the task that is ptracing the current task had CAP_SYS_PTRACE in the specified user namespace.
 */
bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
{
	int ret = 0;  /* An absent tracer adds no restrictions */
	const struct cred *cred;

	rcu_read_lock();
	cred = rcu_dereference(tsk->ptracer_cred);
	if (cred)
		ret = security_capable(cred, ns, CAP_SYS_PTRACE, CAP_OPT_NOAUDIT);
	rcu_read_unlock();
	return (ret == 0);
}
