#ifndef __KPROWL_H
#define __KPROWL_H

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 256

enum event_type {
    EVENT_EXEC = 0,
    EVENT_FILE_OPEN,
    EVENT_CONNECT,
};

struct file_key {
    __u64 ino;
};

struct wl_val {
    char path[MAX_FILENAME_LEN];
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    char  comm[TASK_COMM_LEN];
    union {
        struct {
            char filename[MAX_FILENAME_LEN];
        } exec;
        struct {
            char path[MAX_FILENAME_LEN];
        } file;
        struct {
            __u32 daddr;
            __u16 dport;
            __u16 family;
        } net;
    };
};

#endif
