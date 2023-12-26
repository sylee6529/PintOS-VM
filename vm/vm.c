/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"
#include "hash.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
/* 각 sub system의 초기화 코드를 호출하여 가상 메모리 sub system을 초기화합니다. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    list_init(&frame_table);
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

/*
인자로 받은 해당 페이지 타입에 맞게 새 페이지를 초기화한 뒤
다시 유저 프로그램으로 제어권을 넘긴다.

이니셜라이저와 함께 lazy loading으로 보류 중인 page 객체를 생성한다.
페이지를 만들고 싶다면 직접 만들지 말고 이 함수나 `vm_alloc_page`를 통해 만들기
*/

bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux){

  ASSERT(VM_TYPE(type) != VM_UNINIT)

  bool success = false;
  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL){
    /* TODO: Create the page, fetch the initializer according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    struct page *p = (struct page *)malloc(sizeof(struct page));
    
    if (type & VM_ANON){
      uninit_new(p, pg_round_down(upage), init, type, aux, anon_initializer);
    } else if (type & VM_FILE){
      uninit_new(p, pg_round_down(upage), init, type, aux, file_backed_initializer);
    }

    p->writable = writable;
    /* TODO: Insert the page into the spt. */
    success = spt_insert_page(spt, p);
  }
  return success;
err:
  return success;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED) {
    // 탐색을 위한 임시 페이지 구성하기
    struct page *page = NULL;
    page = (struct page *)malloc(sizeof(struct page));
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

    if (hash_insert(&spt->spt_pages, &page->elem) == NULL) {
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
    if (victim->page){
		swap_out(victim->page);
    }
    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
    /* TODO: Fill this function. */

    void *kva = palloc_get_page(PAL_USER); // user pool에서 새로운 physical page를 가져온다.

	if (kva == NULL) // page 할당 실패
	{
		struct frame *victim = vm_evict_frame();
		victim->page = NULL;
		return victim;
	}
	
    frame->kva = kva;
	frame->page = NULL;

	list_push_back(&frame_table, &frame->frame_elem);	
    ASSERT(frame != NULL);
    ASSERT(frame->page == NULL);
    return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
	// 스택 크기를 증가시키기 위해 anon page를 하나 이상 할당하여 주어진 주소(addr)가 더 이상 예외 주소(faulted address)가 되지 않도록 합니다.
	// 할당할 때 addr을 PGSIZE로 내림하여 처리
	vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED,
                         bool user UNUSED, bool write UNUSED,
                         bool not_present UNUSED) {
    struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    struct page *page = NULL;
    //////////////////
    // 주소가 없거나 커널 영역 주소라면 false
    if (addr == NULL) return false;
    if (is_kernel_vaddr(addr)) return false;

    // 접근한 메모리가 load되지 않은 경우(physical page가 존재하지 않은 경우)
    if (not_present) {
        /* 바로 do_claim하지 말고, fault 적절한지 체크 */		
        // 일단 spt에는 있어야 함
        page = spt_find_page(spt, addr);
		if (page == NULL){
			return false;
        }
		
        // write 불가능한 페이지에 write 요청한 경우는 걸러주기
        if (write == 1 && page->writable == 0) {
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
/* VA에 할당된 페이지 찾기 -> vm_do_claim_page(page) 호출 */
bool vm_claim_page(void *va UNUSED) {
    struct page *page = NULL;
    /* TODO: Fill this function */
    page = spt_find_page(&thread_current()->spt, va); 

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
/* 해당 페이지를 물리 메모리 할당 + pml4와 frame 매핑  */
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
        
	struct hash_iterator i;	
    struct hash *parent_pages = &src->spt_pages;

    hash_first(&i, parent_pages);

    // 부모 spt 해시테이블의 모든 elem 순회
    while (hash_next(&i)){    
        // 부모 프로세스의 현재 페이지 정보 저장            
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, elem);        
        enum vm_type parent_type = parent_page->operations->type;        

        // page type이 uninit인 경우
        if (parent_type == VM_UNINIT){
            vm_initializer *init = parent_page->uninit.init;
            void *aux = parent_page->uninit.aux;

            vm_alloc_page_with_initializer(VM_ANON, parent_page->va, parent_page->writable, init, aux);
        } 
        // page type이 anon 또는 file인 경우 -> 일단 uninit 페이지 생성함. type별 init으로 수정 필요       
        else {
    		// parent type에 해당하는 page 생성
    		if (!vm_alloc_page(parent_type, parent_page->va, parent_page->writable)){
    			return false;
            }

    		// 해당 페이지에 빈 frame 할당 -> pml4에 연결 정보 저장 
    		if (!vm_claim_page(parent_page->va)){
    			return false;
            }

    		// 생성한 빈 frame에 부모 frame 내용 복제하기
    		struct page *child_page = spt_find_page(dst, parent_page->va);
    		memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);		
        }
    }
	
    return true;
}

/* Free the resource hold by the supplemental page table 
    process_exit()에서 호출된다. thx for e-juhee
*/
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* TODO: Destroy all the supplemental_page_table hold by thread and
     * writeback all the modified contents to the storage. */    

    hash_clear(&spt->spt_pages, hash_page_destroy); // 해시 테이블의 모든 요소를 제거
}

void hash_page_destroy(struct hash_elem *e, void *aux){
	struct page *page = hash_entry(e, struct page, elem);
	destroy(page);
	free(page);
}