#include <bpf/libbpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static volatile int running = 1;

void handle_sigint(int sigint){
    running = 0;
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


    signal(SIGINT,handle_sigint);

    while(running){
        sleep(1);
    }
cleanup:
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
