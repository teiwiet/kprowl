#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include "kprowl.h"

#define AF_INET 2

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, __u8);
} tracked SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct file_key);
    __type(value, struct wl_val);
} watchlist SEC(".maps");

static __always_inline int is_tracked(pid_t pid)
{
    return bpf_map_lookup_elem(&tracked, &pid) != NULL;
}

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_EXEC;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_probe_read_user_str(&e->exec.filename, sizeof(e->exec.filename),
                            (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_file_open")
int BPF_KPROBE(handle_file_open, struct file *file)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    struct file_key key = {};
    key.ino = BPF_CORE_READ(file, f_inode, i_ino);

    struct wl_val *hit = bpf_map_lookup_elem(&watchlist, &key);
    if (!hit)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_FILE_OPEN;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    __builtin_memcpy(&e->file.path, hit->path, sizeof(e->file.path));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(handle_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    if (!is_tracked(pid))
        return 0;

    __u16 family = BPF_CORE_READ(address, sa_family);
    if (family != AF_INET)
        return 0;

    struct sockaddr_in *in = (struct sockaddr_in *)address;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_CONNECT;
    e->pid = pid;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->net.family = family;
    e->net.daddr = BPF_CORE_READ(in, sin_addr.s_addr);
    e->net.dport = BPF_CORE_READ(in, sin_port);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
