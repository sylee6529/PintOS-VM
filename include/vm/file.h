#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;
/* project 3 */
/* a structure that includes the information for the loading */
struct lazy_load_arg {
    struct file *file;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    off_t ofs;
    void *open_addr;
    void *close_addr;
};

struct file_page {
    struct file *file;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    off_t ofs;
};

void vm_file_init(void);
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset);
void do_munmap(void *va);
#endif
