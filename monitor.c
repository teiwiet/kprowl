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

int main(){

}
