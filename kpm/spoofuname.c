#include <log.h>#include <log.h>
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kputils.h>
#include <syscall.h>
#include <uapi/asm-generic/unistd.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/printk.h> /* 👈 pr_info 사용을 위해 추가 */
#include "../../../common.h"

#ifndef min
#define min(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef MYKPM_VERSION
#define MYKPM_VERSION "v0.0.1-1-unknown"
#endif

/* ===== [수정] 로그가 무조건 출력되도록 변경 ===== */
#define spoof_logd(fmt, ...) pr_info("[SpoofUname] " fmt, ##__VA_ARGS__)

/* ===== [추가] seq_file 관련 선언 ===== */
struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
};
extern int seq_write(struct seq_file *seq, const void *data, size_t len);

/* ===== [수정] @build 문자열을 @localhost 로 변경 ===== */
static void after_version_proc_show(hook_fargs2_t *args, void *udata)
{
    struct seq_file *m = (struct seq_file *)args->arg0;
    if (!m || !m->buf) return;

    // 🎯 [수정] @ 기호를 완전히 제거 (예: android-build)
    const char *clean_ver = "Linux version 6.1.138-android14-11-g0c3d559bcd85-ab14529422 (android-build) (Android (10087095, +pgo, +bolt, +lto, -mlgo, based on r487747c) clang version 17.0.2 (https://android.googlesource.com/toolchain/llvm-project d9f89f4d16663d5012e5c09495f3b30ece3d2362), LLD 17.0.2) #1 SMP PREEMPT Wed Dec  3 02:05:30 UTC 2025\n";
    
    size_t len = strlen(clean_ver);
    if (m->size >= len) { 
        m->count = len;
        memcpy(m->buf, clean_ver, len);
    }
}

static char custom_release[SPOOFUNAME_MAX_LENGTH + 1] = "";
static char custom_version[SPOOFUNAME_MAX_LENGTH + 1] = "";
static int modify_enabled = 0;

KPM_NAME("SpoofUname");
KPM_VERSION(MYKPM_VERSION);
KPM_LICENSE("GPL v2");
KPM_AUTHOR("YangQi0408");
KPM_DESCRIPTION("Spoof Uname Information");

int control(const char *args, char *out_msg, int outlen)
{
    char reply_msg[128] = { 0 };
    int reply_len = 0;

    if (!args || !strncmp(args, "STATUS", 6)) {
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "modify: %s\nrelease: %s\nversion: %s",
                             modify_enabled ? "enabled" : "disabled", custom_release, custom_version);
    } else if (!strncmp(args, "SR ", 3)) {
        const char *new_release = args + 3;
        int len = strlen(new_release);

        if (len > 0 && len <= SPOOFUNAME_MAX_LENGTH) {
            strncpy(custom_release, new_release, SPOOFUNAME_MAX_LENGTH);
            custom_release[SPOOFUNAME_MAX_LENGTH] = '\0';
            modify_enabled = 1;
            reply_len = snprintf(reply_msg, sizeof(reply_msg), "release set to: %s, modify enabled", custom_release);
        } else {
            reply_len = snprintf(reply_msg, sizeof(reply_msg), "error: release abnormal");
        }
    } else if (!strncmp(args, "SV ", 3)) {
        const char *new_version = args + 3;
        int len = strlen(new_version);

        if (len > 0 && len <= SPOOFUNAME_MAX_LENGTH) {
            strncpy(custom_version, new_version, SPOOFUNAME_MAX_LENGTH);
            custom_version[SPOOFUNAME_MAX_LENGTH] = '\0';
            modify_enabled = 1;
            reply_len = snprintf(reply_msg, sizeof(reply_msg), "version set to: %s, modify enabled", custom_version);
        } else {
            reply_len = snprintf(reply_msg, sizeof(reply_msg), "error: version abnormal");
        }
    } else if (!strcmp(args, "EN")) {
        modify_enabled = 1;
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "enabled");
    } else if (!strcmp(args, "DIS")) {
        modify_enabled = 0;
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "disabled");
    } else if (!strcmp(args, "CR")) {
        custom_release[0] = '\0';
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "release cleared");
    } else if (!strcmp(args, "CV")) {
        custom_version[0] = '\0';
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "version cleared");
    } else {
        reply_len = snprintf(reply_msg, sizeof(reply_msg), "Unknown command");
    }

    if (out_msg && outlen > 0 && reply_len > 0) {
        int copy_len = min(reply_len + 1, outlen);
        memcpy(out_msg, reply_msg, copy_len);
    }
    return 0;
}

static void before_reboot(hook_fargs4_t *args, void *udata)
{
    int magic1 = (int)syscall_argn(args, 0);
    int magic2 = (int)syscall_argn(args, 1);
    unsigned int cmd = (unsigned int)syscall_argn(args, 2);
    void __user *arg = (void __user *)syscall_argn(args, 3);

    if (magic1 != SPOOFUNAME_MAGIC_NUMBER1 || magic2 != SPOOFUNAME_MAGIC_NUMBER2) return;

    args->skip_origin = 1;
    args->ret = 0;

    switch (cmd) {
    case SPOOFUNAME_CMD_GET_STATUS:
        if (arg) {
            char status_msg[256] = { 0 };
            snprintf(status_msg, sizeof(status_msg), "modify: %s\nrelease: %s\nversion: %s",
                     modify_enabled ? "enabled" : "disabled", custom_release, custom_version);
            compat_copy_to_user(arg, status_msg, strlen(status_msg) + 1);
        }
        break;
    case SPOOFUNAME_CMD_ENABLE:
        modify_enabled = 1;
        break;
    case SPOOFUNAME_CMD_DISABLE:
        modify_enabled = 0;
        break;
    case SPOOFUNAME_CMD_SET_RELEASE:
        if (arg && compat_strncpy_from_user(custom_release, (const char __user *)arg, SPOOFUNAME_MAX_LENGTH) > 0) {
            custom_release[SPOOFUNAME_MAX_LENGTH] = '\0';
            modify_enabled = 1;
        }
        break;
    case SPOOFUNAME_CMD_SET_VERSION:
        if (arg && compat_strncpy_from_user(custom_version, (const char __user *)arg, SPOOFUNAME_MAX_LENGTH) > 0) {
            custom_version[SPOOFUNAME_MAX_LENGTH] = '\0';
            modify_enabled = 1;
        }
        break;
    case SPOOFUNAME_CMD_CLEAR_RELEASE:
        custom_release[0] = '\0';
        break;
    case SPOOFUNAME_CMD_CLEAR_VERSION:
        custom_version[0] = '\0';
        break;
    }
}

static void after_newuname(hook_fargs1_t *args, void *udata)
{
    if (!modify_enabled) return;

    long ret = args->ret;
    void __user *name = (void __user *)syscall_argn(args, 0);

    if (ret != 0 || !name) return;

    if (custom_release[0] != '\0') {
        compat_copy_to_user((void __user *)(name + UTS_RELEASE_OFFSET), custom_release, strlen(custom_release) + 1);
    }

    if (custom_version[0] != '\0') {
        compat_copy_to_user((void __user *)(name + UTS_VERSION_OFFSET), custom_version, strlen(custom_version) + 1);
    }
}

static long inline_hook_demo_init(const char *args, const char *event, void *__user reserved)
{
    spoof_logd("Spoof Uname init started\n");

    hook_err_t err = inline_hook_syscalln(__NR_uname, 1, NULL, after_newuname, NULL);
    spoof_logd("uname hook result: %d\n", err);
    
    if (err != HOOK_NO_ERR && err != HOOK_DUPLICATED && err != HOOK_BAD_RELO) {
        return err;
    }

    err = inline_hook_syscalln(__NR_reboot, 4, before_reboot, NULL, NULL);
    spoof_logd("reboot hook result: %d\n", err);

    if (err != HOOK_NO_ERR && err != HOOK_DUPLICATED && err != HOOK_BAD_RELO) {
        inline_unhook_syscalln(__NR_uname, NULL, after_newuname);
        return err;
    }

    /* ===== version_proc_show 후킹 ===== */
    void *target = (void *)kallsyms_lookup_name("version_proc_show");
    if (target) {
        hook_wrap(target, 2, NULL, after_version_proc_show, NULL);
        spoof_logd("version_proc_show hooked with hook_wrap successfully\n");
    } else {
        spoof_logd("Failed to find version_proc_show symbol\n");
    }

    return 0;
}

static long inline_hook_control0(const char *args, char *__user out_msg, int outlen)
{
    if (!out_msg || outlen <= 0) {
        return control(args, NULL, 0);
    }

    char buf[256] = { 0 };
    int ret = control(args, buf, sizeof(buf));
    if (ret < 0) return ret;

    int copy_len = min(strlen(buf) + 1, outlen);
    if (compat_copy_to_user(out_msg, buf, copy_len) <= 0) return -1;
    return 0;
}

static long inline_hook_demo_exit(void *__user reserved)
{
    spoof_logd("Spoof Uname exit\n");
    modify_enabled = 0;
    inline_unhook_syscalln(__NR_uname, NULL, after_newuname);
    inline_unhook_syscalln(__NR_reboot, before_reboot, NULL);
    return 0;
}

KPM_INIT(inline_hook_demo_init);
KPM_CTL0(inline_hook_control0);
KPM_EXIT(inline_hook_demo_exit);
