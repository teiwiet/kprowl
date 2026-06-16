#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
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
int main(int argc,char **argv){
    if(argc < 2){
        printf("Usage : %s <program> \n",argv[0]);
        return 1;
    }
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    struct bpf_map *tracked = NULL;
    struct ring_buffer *rb = NULL;
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

    map = bpf_object__find_map_by_name(obj,"events");
    if(!map){
        printf("Failed to find map\n");
        goto cleanup;
    }
    
    tracked = bpf_object__find_map_by_name(obj,"tracked");
    if(!tracked){
        printf("Failed to find map tracked\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(map),on_event,NULL,NULL);
    if(!rb){
        printf("Failed to create ring buffer\n");
        goto cleanup;
    }
    signal(SIGINT,handle_sigint);
    pid_t child = fork();
    
    if(child < 0){
        perror("fork");
        goto cleanup;
    }

    if(child == 0){
        execvp(argv[1],&argv[1]);
        perror("execvp");
        _exit(127);
    }
    __u32 pid = child;
    __u8 one = 1;

    bpf_map__update_elem(tracked,&pid,sizeof(pid),&one,sizeof(one),BPF_ANY);
    printf("[kprowl] tracing pid %d (%s)\n",child,argv[1]);
    while(running){
        int err = ring_buffer__poll(rb,100);
        if(err == -EINTR) continue;
        if(err < 0 ){
            printf("Poll err : %d",err);
            break;
        }
        int wstatus;
        if(waitpid(child,&wstatus,WNOHANG)){
            ring_buffer__poll(rb,100);
            break;
        }
    }
cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    ring_buffer__free(rb);
    return 0;
}
