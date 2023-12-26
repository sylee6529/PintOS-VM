/* vm.c: Generic interface for virtual memory objects. */

#include "userprog/process.h"
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "hash.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
    list_init(&frame_table);
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *page = malloc(sizeof(struct page));
        if (page == NULL) {
            PANIC("Fail to allocate memory for page");
        }

        // if aux is not null, set var that has type load_info to aux
        struct load_info *load_info = NULL;
        load_info = aux;

        bool (*page_initializer)(struct page *, enum vm_type, void *);
        page_initializer = NULL;

        switch (VM_TYPE(type)) {
            case VM_ANON:
                page_initializer = anon_initializer;
                break;
            case VM_FILE:
                page_initializer = file_backed_initializer;
                break;
        }

        uninit_new(page, upage, init, type, aux, page_initializer);
        page->writable = writable;

        /* TODO: Insert the page into the spt. */
        if (spt_insert_page(spt, page)) {
            return true;
        }

        free(page);
        return false;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED) {
    struct page *page = (struct page *)malloc(sizeof(struct page));
    /* TODO: Fill this function. */
    page->va = pg_round_down(va);
    struct hash_elem *e = hash_find(&spt->page_map, &page->hash_elem);

    free(page);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED) {
    int succ = false;
    /* TODO: Fill this function. */

    return hash_insert(&spt->page_map, &page->hash_elem) == NULL ? true : false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    hash_delete(&spt->page_map, &page->hash_elem);
    vm_dealloc_page(page);
    return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
    struct frame *victim = NULL;
    /* TODO: The policy for eviction is up to you. */

    return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim UNUSED = vm_get_victim();
    /* TODO: swap out the victim and return the evicted frame. */

    return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    /* TODO: Fill this function. */
    void *kva = palloc_get_page(PAL_USER);

    if (kva == NULL) {
        struct frame *victim = vm_evict_frame();
        victim->page = NULL;
        return victim;
    }

    frame->kva = kva;
    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);

    list_push_back(&frame_table, &frame->frame_elem);
    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
    // handle not writeable page
    return false;
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */

    if (addr == NULL) return false;
    if (is_kernel_vaddr(addr)) return false;
    /* TODO: Your code goes here */

    // 접근한 메모리의 physical page가 존재하지 않은 경우
    if (not_present) {
        page = spt_find_page(spt, addr);
        if (page == NULL) {
            return false;
        }

        // write 불가능한 페이지에 write 요청한 경우
        if (write == 1 && page->writable == 0) {
            return vm_handle_wp(page);
        }

        return vm_do_claim_page(page);
    }

    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va);

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    // 가상 주소와 물리 주소를 매핑
    struct thread *current = thread_current();
    pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

    return swap_in(page, frame->kva);
}

/* Return hash value of page p. */
unsigned page_hash_func(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof(p->va));
}

/* Return true if page a precedes page b. */
unsigned spt_less_func(const struct hash_elem *a_, const struct hash_elem *b_,
                       void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);

    return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt) {
    hash_init(&spt->page_map, page_hash_func, spt_less_func, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    struct hash *parent_pages = &src->page_map;

    hash_first(&i, parent_pages);

    // 부모 spt 해시테이블의 모든 elem 순회
    while (hash_next(&i)) {
        // 부모 프로세스의 현재 페이지 정보 저장
        struct page *parent_page =
            hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type parent_type = parent_page->operations->type;

        // page type이 uninit인 경우
        if (parent_type == VM_UNINIT) {
            vm_initializer *init = parent_page->uninit.init;
            void *aux = parent_page->uninit.aux;

            vm_alloc_page_with_initializer(VM_ANON, parent_page->va,
                                           parent_page->writable, init, aux);
        }
        // page type이 anon 또는 file인 경우 -> 일단 uninit 페이지 생성함.
        // type별 init으로 수정 필요
        else {
            // uninit page 생성 & 초기화
            if (!vm_alloc_page(parent_type, parent_page->va,
                               parent_page->writable)) {
                return false;
            }

            // 해당 페이지에 빈 frame 할당 -> pml4에 연결 정보 저장
            if (!vm_claim_page(parent_page->va)) {
                return false;
            }

            // 생성한 빈 frame에 부모 frame 내용 복제하기
            struct page *child_page = spt_find_page(dst, parent_page->va);
            memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
        }
    }

    return true;
}
void spt_destructor(struct hash_elem *e, void *aux) {
    const struct page *p = hash_entry(e, struct page, hash_elem);
    free(p);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */

    hash_clear(&spt->page_map, spt_destructor);
}
