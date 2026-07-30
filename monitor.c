#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include "kprowl.h"

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static int is_shell(const char *comm)
{
    static const char *shells[] = {
        "sh", "bash", "dash", "zsh", "ksh",
        "nc", "ncat", "netcat", "socat",
        "python", "python3", "perl", "ruby", "php", NULL
    };
    for (int i = 0; shells[i]; i++)
        if (strcmp(comm, shells[i]) == 0)
            return 1;
    return 0;
}

static int on_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;

    switch (e->type) {
    case EVENT_FILE_OPEN:
        printf("[FILE!] pid=%-6u uid=%-5u comm=%-16s SENSITIVE=%s\n",
               e->pid, e->uid, e->comm, e->file.path);
        break;
    case EVENT_CONNECT: {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &e->net.daddr, ip, sizeof(ip));
        int susp = is_shell(e->comm);
        printf("[CONN%s] pid=%-6u uid=%-5u comm=%-16s -> %s:%u%s\n",
               susp ? "!!" : "  ", e->pid, e->uid, e->comm,
               ip, ntohs(e->net.dport),
               susp ? "   <== possible reverse shell" : "");
        break;
    }
    }
    fflush(stdout);
    return 0;
}

static void load_watchlist(struct bpf_map *wl)
{
    const char *home = getenv("HOME");
    if (!home) home = "/root";

    char ssh_rsa[512], ssh_ed[512], aws[512];
    snprintf(ssh_rsa, sizeof(ssh_rsa), "%s/.ssh/id_rsa", home);
    snprintf(ssh_ed, sizeof(ssh_ed), "%s/.ssh/id_ed25519", home);
    snprintf(aws, sizeof(aws), "%s/.aws/credentials", home);

    const char *paths[] = {
        "/etc/shadow", "/etc/sudoers", "/etc/gshadow", "/etc/ld.so.preload",
        ssh_rsa, ssh_ed, aws,
        NULL
    };

    int fd = bpf_map__fd(wl);
    int n = 0;
    for (int i = 0; paths[i]; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0)
            continue;

        struct file_key key = { .ino = st.st_ino };
        struct wl_val val = {0};
        strncpy(val.path, paths[i], sizeof(val.path) - 1);

        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) == 0) {
            n++;
            fprintf(stderr, "watchlist: + %-32s ino=%llu\n",
                    paths[i], (unsigned long long)key.ino);
        }
    }
    fprintf(stderr, "watchlist: %d entries loaded\n", n);
}
int main(void)
{
    struct bpf_object *obj;
    struct ring_buffer *rb;

    obj = bpf_object__open_file("kprowl.bpf.o", NULL);
    if (!obj) { fprintf(stderr, "Failed to open BPF object\n"); return 1; }

    if (bpf_object__load(obj)) { fprintf(stderr, "Failed to load into kernel (try sudo)\n"); return 1; }

    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj)
        if (!bpf_program__attach(prog))
            fprintf(stderr, "warn: could not attach %s: %s\n",
                    bpf_program__name(prog), strerror(errno));

    struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
    struct bpf_map *watchlist = bpf_object__find_map_by_name(obj, "watchlist");
    struct bpf_map *cfg = bpf_object__find_map_by_name(obj, "kprowl_cfg");
    if (!events_map || !watchlist || !cfg) { fprintf(stderr, "Failed to find maps\n"); return 1; }

    __u32 zero = 0;
    __u8 one = 1;
    bpf_map_update_elem(bpf_map__fd(cfg), &zero, &one, BPF_ANY);

    load_watchlist(watchlist);

    rb = ring_buffer__new(bpf_map__fd(events_map), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "Failed to create ring buffer\n"); return 1; }

    signal(SIGINT, handle_sigint);
    printf("[kprowl] system-wide monitor running. Ctrl-C to stop.\n");

    while (running) {
        int err = ring_buffer__poll(rb, 200);
        if (err == -EINTR) continue;
        if (err < 0) { fprintf(stderr, "poll error: %d\n", err); break; }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
