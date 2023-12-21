/* vm.c: Generic interface for virtual memory objects. */

#include "vm/vm.h"

#include "threads/malloc.h"
#include "vm/inspect.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
/* 각 sub system의 초기화 코드를 호출하여 가상 메모리 sub system을 초기화합니다.
 */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
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

/* lazy loading으로 보류 중인 page 객체 생성 with initializer.
페이지를 만들고 싶다면 직접 만들지 말고 이 함수나 `vm_alloc_page`를 통해
만들어주세요. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    /* 해당 페이지가 이미 점유되어 있는지 확인 */
    if (spt_find_page(spt, upage) == NULL) {
        /* TODO: Create the page, fetch the initialier according to the VM type,
         * TODO: and then create "uninit" page struct by calling uninit_new. You
         * TODO: should modify the field after calling the uninit_new. */
        struct page *page = NULL;
        page = (struct page *)calloc(sizeof(struct page), 1);

        /* TODO: Insert the page into the spt. */
        spt_insert_page(&spt, &page);
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED) {
    // 탐색을 위한 임시 페이지 구성하기
    struct page *page = NULL;
    page = (struct page *)calloc(sizeof(struct page), 1);
    page->va = pg_round_down(va);  // 페이지 시작주소 할당

    // 해당 va를 넣은 페이지의 hash_elem은 해당 va의 해시값을 지닌다.
    // hash_find()는 이 해시값을 토대로 타겟 페이지의 hash_elem을 탐색한다.
    struct hash_elem *hash_elem = hash_find(&spt->spt_pages, &page->elem);

    // 임시 페이지 해제
    free(page);

    if (hash_elem != NULL) {
        // hash_elem을 지닌 페이지 반환
        return hash_entry(hash_elem, struct page, elem);
    } else {
        return NULL;  // 페이지를 못 찾았을 경우
    }
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
                     struct page *page UNUSED) {
    int succ = false;

    /* TODO: Fill this function. */
    // 페이지 이미 존재하는지 검사
    struct page *p = spt_find_page(spt, page->va);
    if (p != NULL) {
        return succ;
    }

    if (hash_insert(&spt, &page->elem) == NULL) {
        succ = true;
    }

    return succ;
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

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;
    /* TODO: Fill this function. */

    // 1. USER_POOL에서 frame의 kva 받기
    void *allocated_kva = palloc_get_page(PAL_USER);

    // 2. free frame 없는지? (kva 할당 실패) - 그렇다면 evict
    if (allocated_kva == NULL) {
        vm_evict_frame();
    }

    // 3. frame 할당 + frame table에 기록
    frame = calloc(sizeof(struct frame), 1);  // frame 할당
    frame->kva = allocated_kva;               // frame의 kva 초기화

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
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    /* TODO: Validate the fault */
    /* TODO: Your code goes here */

    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
/* VA에 할당된 페이지 요청 */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va);

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* 해당 페이지를 물리 메모리 할당 + frame에 매핑  */
static bool vm_do_claim_page(struct page *page) {
    struct frame *frame = vm_get_frame();

    /* Set links */
    frame->page = page;
    page->frame = frame;

    /* TODO: Insert page table entry to map page's VA to frame's PA. */
    bool writable = is_writable(page->va);
    pml4_set_page(&thread_current()->pml4, page->va, frame->kva, writable);

    return swap_in(page, frame->kva);
}

/* Returns a hash value for page p. */
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, elem);
    return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, elem);
    const struct page *b = hash_entry(b_, struct page, elem);

    return a->va < b->va;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    hash_init(&spt->spt_pages, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    // &src 접근 -> spt_pages 순회하면서 값을 &dst에 넣어주기 (spt insert 활용)
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * writeback all the modified contents to the storage. */
    /* TODO: 스레드가 보유하고 있는 모든 Supplemental_page_table을 삭제하고
     * 수정된 모든 콘텐츠를 스토리지에 다시 씁니다. */

    // hash_destroy 활용 -> 순회돌면서 연결 해제 및 모든 bucket free
    // hash_action_func: 각 hash_elem에 대해서 해당 함수가 지정한 action 수행.
    // hash_destroy(&spt->spt_pages, free_pages);
}
