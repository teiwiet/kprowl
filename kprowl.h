#ifndef __KPROWL_H
#define __KPROWL_H
#include <linux/types.h>
#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
struct event{
    __u32 pid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif
