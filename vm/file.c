/* file.c: Implementation of memory backed file object (mmaped object). */

#include "userprog/process.h"
#include "vm/vm.h"
#include "threads/mmu.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;

    // todo: page struct의 일부 정보(such as 메모리가 백업되는 파일과 관련된
    // 정보)를 업데이트할 수도 있습니다.
    struct load_info *lazy_load_arg = (struct load_info *)page->uninit.aux;
    file_page->file = lazy_load_arg->file;
    file_page->ofs = lazy_load_arg->ofs;
    file_page->read_bytes = lazy_load_arg->read_bytes;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    if (pml4_is_dirty(thread_current()->pml4, page->va)) {
        file_write_at(page->file.file, page->va, page->file.read_bytes,
                      page->file.ofs);
        pml4_set_dirty(thread_current()->pml4, page->va, 0);
    }
    pml4_clear_page(thread_current()->pml4, page->va);

    // page struct를 해제할 필요가 없습니다. (file_backed_destroy의 호출자가
    // 해야 함)
    struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
/* lazy load하게 파일을 매핑한다. */
void *do_mmap(void *addr, size_t length, int writable, struct file *file,
              off_t offset) {
    struct file *f = file_reopen(file);
    // 매핑 성공 시 파일이 매핑된 가상 주소 반환하는 데 사용
    void *start_addr = addr;
    // 이 매핑을 위해 사용한 총 페이지 수
    int total_page_count =
        length <= PGSIZE
            ? 1
            : (length % PGSIZE ? length / PGSIZE + 1 : length / PGSIZE);

    size_t read_bytes = file_length(f) < length ? file_length(f) : length;
    size_t zero_bytes = PGSIZE - read_bytes % PGSIZE;

    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(addr) == 0);  // upage가 페이지 정렬되어 있는지 확인
    ASSERT(offset % PGSIZE == 0)  // ofs가 페이지 정렬되어 있는지 확인

    while (read_bytes > 0 || zero_bytes > 0) {
        /* 이 페이지를 채우는 방법을 계산합니다.
        파일에서 PAGE_READ_BYTES 바이트를 읽고
        최종 PAGE_ZERO_BYTES 바이트를 0으로 채웁니다. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct load_info *lazy_load_arg =
            (struct load_info *)malloc(sizeof(struct load_info));
        lazy_load_arg->file = f;
        lazy_load_arg->ofs = offset;
        lazy_load_arg->read_bytes = page_read_bytes;
        lazy_load_arg->zero_bytes = page_zero_bytes;

        // vm_alloc_page_with_initializer를 호출하여 대기 중인 객체를
        // 생성합니다.
        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable,
                                            lazy_load_segment, lazy_load_arg))
            return NULL;

        struct page *p = spt_find_page(&thread_current()->spt, start_addr);
        p->mapped_page_count = total_page_count;

        /* Advance. */
        // 읽은 바이트와 0으로 채운 바이트를 추적하고 가상 주소를 증가시킵니다.
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }

    return start_addr;
}

/* Do the munmap */
/*  */
void do_munmap(void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *p = spt_find_page(spt, addr);
    int count = p->mapped_page_count;
    for (int i = 0; i < count; i++) {
        if (p) destroy(p);

        addr += PGSIZE;
        p = spt_find_page(spt, addr);
    }
}