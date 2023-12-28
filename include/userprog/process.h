#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H
#define MAX_ARGS 128

#include "threads/thread.h"

struct load_info {
    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    size_t num_page;
};

tid_t process_create_initd(const char *file_name);
tid_t process_fork(const char *name, struct intr_frame *if_);
int process_exec(void *f_name);
int process_wait(tid_t);
void process_exit(void);
void process_activate(struct thread *next);

static bool setup_stack(struct intr_frame *if_);
bool lazy_load_segment(struct page *page, void *aux);
#endif /* userprog/process.h */
