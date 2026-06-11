#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";
pid_t pid_filter = 0;


SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx){
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    char fname[256];
    bpf_probe_read_user_str(&fname,sizeof(fname),(const char*)ctx->args[0]);
    bpf_printk("EXEC pid=%d | file=%s",pid,fname);
    return 0;
}
