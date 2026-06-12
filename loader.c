#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include "kprowl.h"

static volatile int running = 1;

void handle_sigint(int sigint){
    running = 0;
}

static int on_event(void *ctx, void *data, size_t len)
{
	const struct event *e = data;
	printf("pid=%-7u uid=%-5u comm=%-16s file=%s\n",
	       e->pid, e->uid, e->comm, e->filename);
	return 0;
}
int main(){
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct bpf_program *prog = NULL;
    int err = 0;

    obj = bpf_object__open_file("kprowl.bpf.o",NULL);
    if(!obj){
        printf("Failed to open file");
        return 1;
    }

    if(bpf_object__load(obj)){
        printf("Failed to load project into kernel try running with sudo\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj,"handle_execve");
    if(!prog){
        printf("Failed to find program name\n");
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if(!link){
        printf("Failed to attach\n");
        goto cleanup;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj,"events");
    if(!map){
        printf("Failed to find map\n");
        goto cleanup;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map),on_event,NULL,NULL);
    if(!rb){
        printf("Failed to create ring buffer\n");
        goto cleanup;
    }
    signal(SIGINT,handle_sigint);

    while(running){
        int err = ring_buffer__poll(rb,100);
        if(err == -EINTR) continue;
        if(err < 0 ){
            printf("Poll err : %d",err);
            break;
        }
    }
cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
