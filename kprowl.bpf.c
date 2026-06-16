#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "kprowl.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";
pid_t pid_filter = 0;

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256*1024);
}events SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,8192);
    __type(key,__u32);
    __type(value,__u8);
} tracked SEC(".maps");


SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx){
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if(!bpf_map_lookup_elem(&tracked,&pid)){
        return 0;
    }
    struct event *e = bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) return 0;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm,sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename,sizeof(e->filename),(const char*)ctx->args[0]);
    bpf_ringbuf_submit(e,0);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx){
    char path[64];
    bpf_probe_read_user_str(&path,sizeof(path),(const char*)ctx->args[1]);
    char target[] = "/etc/passwd";
    for(int i = 0;i<sizeof(target);i++){
        if(path[i]!=target[i]){
            return 0;
        }
    }
    
    struct event *e = bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid =  bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm,sizeof(e->comm));
    bpf_probe_read_user_str(&e->filename,sizeof(e->filename),(const char*)ctx->args[1]);
    return 0;
}
