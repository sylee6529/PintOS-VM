/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/inspect.h"
#include "stdio.h"
#include "threads/mmu.h"

struct list frame_table;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
    // list_init(&frame_table);
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

    /* Check whether the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        struct page *p = (struct page *)malloc(sizeof(struct page));
        bool (*page_initializer)(struct page *, enum vm_type, void *);

        switch (VM_TYPE(type)) {
            case VM_ANON:
                page_initializer = anon_initializer;
                break;
            case VM_FILE:
                page_initializer = file_backed_initializer;
                break;
        }
        uninit_new(p, upage, init, type, aux, page_initializer);
        p->writable =
            writable;  // 순서 중요. 필드 수정을 uninit_new 이후에 해야함.

        return spt_insert_page(&spt->spt_hashmap, p);  // 헐
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED) {
    struct page *page;
    page = (struct page *)malloc(sizeof(struct page));
    // 주소를 페이지 경계로 round down 해서 찾아야함
    // void *upage_va = pg_round_down(va);
    // page->va = upage_va;
    page->va = pg_round_down(va);  // 페이지 시작주소 할당

    struct hash_elem *e;
    e = hash_find(&spt->spt_hashmap, &page->hash_elem);

    free(page);

    return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED) {
    return hash_insert(&spt->spt_hashmap, &page->hash_elem) == NULL ? true
                                                                    : false;
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
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
/* Gets a new physical page from the user pool by calling palloc_get_page.
 * When successfully got a page from the user pool, also allocates a frame,
 * initialize its members, and returns it.
 * 사용자 풀에서 페이지를 성공적으로 가져오면, 프레임을 할당하고 해당
 * 프레임의 멤버를 초기화한 후 반환한다. 페이지 할당을 실패할 경우, PANIC
 * ("todo")로 표시한다. (swap out을 구현한 이후 변경한다.)
 *
 * palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user
 * pool memory is full, this function evicts the frame to get the available
 * memory space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    /* TODO: Fill this function. */
    frame->kva = palloc_get_page(PAL_USER || PAL_ZERO);

    if (frame->kva == NULL) {
        PANIC("todo");
    }
    // 프레임을 할당하고 해당 프레임의 멤버를 초기화한 후 반환한다
    frame->page = NULL;

    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);

    return frame;
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = NULL;

    if (addr == NULL || is_kernel_vaddr(addr)) {
        return false;
    }

    // if the physical page doesn't exit
    if (not_present) {
        page = spt_find_page(spt, addr);
        if (page == NULL) {
            return false;
        }
        if (write == 1 &&
            page->writable ==
                0) {  // if it's asking to write in unwritable page
            return false;
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
    // spt에서 va에 해당하는 page 찾기
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL) {
        return false;
    }
    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    // add the mapping from the virtual address to the physical address in
    // the page table (pml4_set_page())
    struct thread *curr = thread_current();
    pml4_set_page(curr->pml4, page->va, frame->kva, page->writable);

    return swap_in(page, frame->kva);
}

/* project 3 */
/* Computes and returns the hash value for hash element E, */
unsigned page_hash(const struct hash_elem *he, void *aux UNUSED) {
    const struct page *p = hash_entry(he, struct page, hash_elem);
    // hash_bytes: returns a hash of the size(sec arg) bytes in BUF(first
    // arg)
    return hash_bytes(&p->va, sizeof(p->va));
}

/* Returns true if A is less than B, or false if A is greater than or equal
 * to B
 */
bool page_less(const struct hash_elem *a, const struct hash_elem *b,
               void *aux UNUSED) {
    const struct page *pa = hash_entry(a, struct page, hash_elem);
    const struct page *pb = hash_entry(b, struct page, hash_elem);
    return pa->va < pb->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->spt_hashmap, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
// 자식 프로세스 생성할때 spt()
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first(&i, &src->spt_hashmap);
    while (hash_next(&i)) {
        struct page *src_page =
            hash_entry(hash_cur(&i), struct page, hash_elem);
        enum vm_type type = src_page->operations->type;
        void *upage = src_page->va;
        bool writable = src_page->writable;

        // type이 uninit이면
        if (type == VM_UNINIT) {  // uninit page 생성 & 초기화
            vm_initializer *init = src_page->uninit.init;
            void *aux = src_page->uninit.aux;
            vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
            continue;
        }

        // type이 uninit이 아니면
        if (!vm_alloc_page(type, upage, writable))  // uninit page 생성 & 초기화
            return false;

        // vm_claim_page으로 요청해서 매핑 & 페이지 타입에 맞게 초기화
        if (!vm_claim_page(upage)) return false;

        // 매핑된 프레임에 내용 로딩
        struct page *dst_page = spt_find_page(dst, upage);
        memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
    }
    return true;
}

void hash_page_destroy(struct hash_elem *e, void *aux) {
    struct page *page = hash_entry(e, struct page, hash_elem);
    destroy(page);
    free(page);
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * TODO: writeback all the modified contents to the storage. */
    hash_clear(&spt->spt_hashmap,
               hash_page_destroy);  // 해시 테이블의 모든 요소를 제거
}
