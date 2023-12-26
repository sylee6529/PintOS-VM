/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in(struct page *page, void *kva);
static bool anon_swap_out(struct page *page);
static void anon_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
    .swap_in = anon_swap_in,
    .swap_out = anon_swap_out,
    .destroy = anon_destroy,
    .type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void vm_anon_init(void) {
    /* TODO: Set up the swap_disk. */
    swap_disk = disk_get(1, 1);
    list_init(&swap_table);

    // swap_disk 크기만큼 slot을 만들어서 swap_table에 넣어둔다.
    /*  
        1 slot에 1 page를 담을 수 있는 slot 개수 구하기
        : 1 sector = 512bytes, 1 page = 4096bytes -> 1 slot = 8 sector
    */
    disk_sector_t swap_size = disk_size(swap_disk) / 8;
    
    for (disk_sector_t i = 0; i < swap_size; i++) {
        struct swap_slot *slot = (struct swap_slot *)malloc(sizeof(struct swap_slot));
        
        slot->page = NULL;
        slot->slot_no = i;

        list_push_back(&swap_table, &slot->swap_elem);
    }
}

/* Initialize the file mapping */
// 이 함수는 익명 페이지의 핸들러를 page->operations에 설정합니다.
// 현재는 빈 구조체인 anon_page에서 일부 정보를 업데이트해야 할 수도 있습니다.
// 이 함수는 익명 페이지(즉, VM_ANON)의 초기화 함수로 사용됩니다.
bool anon_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &anon_ops;

    struct anon_page *anon_page = &page->anon;
    // initializer가 호출되는 시점은 page가 매핑된 상태. 따라서 디스크의 swap 영역에 존재하지 않는다.
    // 즉, swap_slot을 차지하지 않는다.
    anon_page->slot_number = -1;  
                                  
    return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool anon_swap_in(struct page *page, void *kva) {
    struct anon_page *anon_page = &page->anon;
}

/* Swap out the page by writing contents to the swap disk. */
static bool anon_swap_out(struct page *page) {
    struct anon_page *anon_page = &page->anon;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void anon_destroy(struct page *page) {
    struct anon_page *anon_page = &page->anon;
    
	// anonymous page에 의해 유지되던 리소스를 해제합니다.
	// page struct를 명시적으로 해제할 필요는 없으며, 호출자가 이를 수행해야 합니다.
	struct list_elem *e;
	struct swap_slot *swap_slot;

	// 차지하던 slot 반환
	for (e = list_begin(&swap_table); e != list_end(&swap_table); e = list_next(e)){
		swap_slot = list_entry(e, struct swap_slot, swap_elem);
		if (swap_slot->slot_no == anon_page->slot_number){
			swap_slot->page = NULL;
			break;
		}
	}
}
