#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include "kprowl.h"

static volatile int running = 1;
void handle_sigint(int sig) { running = 0; }

static int on_event(void *ctx, void *data, size_t len)
{
    const struct event *e = data;

    switch (e->type) {
    case EVENT_EXEC:
        printf("[EXEC]  pid=%-6u uid=%-5u comm=%-16s exec=%s\n",
               e->pid, e->uid, e->comm, e->exec.filename);
        break;
    case EVENT_FILE_OPEN:
        printf("[FILE!] pid=%-6u uid=%-5u comm=%-16s SENSITIVE=%s\n",
               e->pid, e->uid, e->comm, e->file.path);
        break;
    }
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
        "/etc/shadow", "/etc/passwd", "/etc/sudoers",
        ssh_rsa, ssh_ed, aws,
        NULL
    };

    int fd = bpf_map__fd(wl);
    for (int i = 0; paths[i]; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0)
            continue;

        struct file_key key = { .ino = st.st_ino };
        struct wl_val val = {0};
        strncpy(val.path, paths[i], sizeof(val.path) - 1);

        if (bpf_map_update_elem(fd, &key, &val, BPF_ANY) == 0)
            printf("[watchlist] %s (ino=%llu)\n",
                   paths[i], (unsigned long long)st.st_ino);
    }
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: %s <program> [args...]\n", argv[0]);
        return 1;
    }

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
    struct bpf_map *tracked = bpf_object__find_map_by_name(obj, "tracked");
    struct bpf_map *watchlist = bpf_object__find_map_by_name(obj, "watchlist");
    if (!events_map || !tracked || !watchlist) { fprintf(stderr, "Failed to find maps\n"); return 1; }

    load_watchlist(watchlist);

    rb = ring_buffer__new(bpf_map__fd(events_map), on_event, NULL, NULL);
    if (!rb) { fprintf(stderr, "Failed to create ring buffer\n"); return 1; }

    signal(SIGINT, handle_sigint);

    pid_t child = fork();
    if (child < 0) { perror("fork"); goto cleanup; }
    if (child == 0) {
        raise(SIGSTOP);
        execvp(argv[1], &argv[1]);
        perror("execvp");
        _exit(127);
    }

    int sstatus;
    waitpid(child, &sstatus, WUNTRACED);
    __u32 pid = child;
    __u8 one = 1;
    bpf_map_update_elem(bpf_map__fd(tracked), &pid, &one, BPF_ANY);
    kill(child, SIGCONT);

    printf("[kprowl] tracing pid %d (%s)\n", child, argv[1]);

    while (running) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) continue;
        if (err < 0) { fprintf(stderr, "poll error: %d\n", err); break; }
        int wstatus;
        if (waitpid(child, &wstatus, WNOHANG) == child) {
            ring_buffer__poll(rb, 100);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
