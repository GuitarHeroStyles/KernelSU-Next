// SPDX-License-Identifier: GPL-2.0
//
// Compatibility shim between this kernel's susfs4ksu patch and
// KernelSU-Next (v3.4.0-legacy, CONFIG_KSU_MANUAL_HOOK).
//
// Most of the ksu_handle_* symbols the susfs4ksu patch calls from
// fs/exec.c, fs/stat.c, fs/open.c, fs/read_write.c, kernel/sys.c,
// kernel/reboot.c and drivers/input/input.c are now wired directly to
// KernelSU-Next's own real implementations (feature/sucompat.c,
// hook/setuid_hook.c, runtime/ksud_integration.c, core/init.c,
// supercall/supercall.c), with the kernel's call sites adapted to match
// KSUN's own manual-hook calling convention. Only ksu_handle_vfs_fstat and
// its ksu_is_init_rc_hook_enabled gate are susfs4ksu/ReSukiSU-specific
// concepts with no KSUN equivalent; KSUN does its own init.rc size
// spoofing via ksu_handle_newfstat_ret/ksu_handle_fstat64_ret instead, so
// this hook is kept permanently disabled and stubbed out only so the
// kernel still links.

#include <linux/types.h>
#include <linux/init.h>
#include <linux/cache.h>
#include <linux/jump_label.h>
#include <linux/security.h>
#include <linux/string.h>

#include "../selinux/selinux.h"

#ifdef CONFIG_KSU_SUSFS

#define KERNEL_PRIV_APP_DOMAIN "u:r:priv_app:s0:c512,c768"

DEFINE_STATIC_KEY_TRUE(ksu_is_init_rc_hook_enabled);

u32 susfs_ksu_sid = 0;
u32 susfs_priv_app_sid = 0;

void __init ksu_susfs_compat_init(void)
{
	static_branch_disable(&ksu_is_init_rc_hook_enabled);
}

// Called after SELinux policy is loaded, alongside KSUN's own cache_sid(),
// so susfs' own sid-based checks (security/selinux/avc.c,
// fs/proc_namespace.c, fs/namespace.c, fs/susfs.c, fs/super.c) work the
// same way they do on SukiSU-Ultra/ReSukiSU.
void ksu_susfs_compat_cache_sid(void)
{
	int err;

	err = security_secctx_to_secid(KERNEL_SU_CONTEXT, strlen(KERNEL_SU_CONTEXT), &susfs_ksu_sid);
	if (err)
		susfs_ksu_sid = 0;

	err = security_secctx_to_secid(KERNEL_PRIV_APP_DOMAIN, strlen(KERNEL_PRIV_APP_DOMAIN), &susfs_priv_app_sid);
	if (err)
		susfs_priv_app_sid = 0;
}

bool susfs_is_current_ksu_domain(void)
{
	return is_ksu_domain();
}

void ksu_handle_vfs_fstat(int fd, loff_t *kstat_size_ptr)
{
}

#endif // CONFIG_KSU_SUSFS
