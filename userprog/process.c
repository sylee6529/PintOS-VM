#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* General process initializer for initd and other process. */
static void process_init(void) { struct thread *current = thread_current(); }

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL) return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr);
    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR) palloc_free_page(fn_copy);

    return tid;
}

/* A thread function that launches first user process. */
static void initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0) {
        PANIC("Fail to launch initd\n");
    }
    NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t process_fork(const char *name, struct intr_frame *if_ UNUSED) {
    /* Clone current thread to new thread.*/
    struct thread *parent = thread_current();
    memcpy(&parent->parent_tf, if_, sizeof(struct intr_frame));
    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, parent);
    if (tid == TID_ERROR) return tid;

    struct thread *child = get_child_thread(tid);

    sema_down(&child->fork_sema);

    if (child->exit_status == TID_ERROR) {
        return TID_ERROR;
    }
    return tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* 1. TODO: If the parent_page is kernel page, then return immediately. */
    if (is_kernel_vaddr(va)) {
        return true;
    }

    /* 2. Resolve VA from the parent's page map level 4. */
    parent_page = pml4_get_page(parent->pml4, va);
    if (parent_page == NULL) {
        return false;
    }

    /* 3. TODO: Allocate new PAL_USER page for the child and set result to
     *    TODO: NEWPAGE. */
    newpage = palloc_get_page(PAL_USER);
    if (newpage == NULL) {
        return false;
    }

    /* 4. TODO: Duplicate parent's page to the new page and
     *    TODO: check whether parent's page is writable or not (set WRITABLE
     *    TODO: according to the result). */
    memcpy(newpage, parent_page, PGSIZE);
    writable = is_writable(pte);

    /* 5. Add new page to child's page table at address VA with WRITABLE
     *    permission. */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        /* 6. TODO: if fail to insert page, do error handling. */
        return false;
    }
    return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();
    /* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
    struct intr_frame *parent_tf = &parent->parent_tf;
    bool succ = true;

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_tf, sizeof(struct intr_frame));
    if_.R.rax = 0;

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL) goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt)) goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) goto error;
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/
    if (parent->fd_idx == FDCOUNT_LIMIT) {
        goto error;
    }

    for (int i = 0; i < FDCOUNT_LIMIT; i++) {
        struct file *file = parent->fd_table[i];
        if (file == NULL) continue;
        if (file > 2) {
            file = file_duplicate(file);
        }
        current->fd_table[i] = file;
    }
    current->fd_idx = parent->fd_idx;
    sema_up(&current->fork_sema);

    // process_init ();

    /* Finally, switch to the newly created process. */
    if (succ) do_iret(&if_);
error:
    sema_up(&current->fork_sema);
    exit(TID_ERROR);
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
    char *file_name = (char *)palloc_get_page(PAL_ZERO);
    strlcpy(file_name, (char *)f_name, strlen(f_name) + 1);
    bool success;

    /* We cannot use the intr_frame in the thread structure.
     * This is because when current thread rescheduled,
     * it stores the execution information to the member. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();
    supplemental_page_table_init(&thread_current()->spt);

    /* project 2: argument passing */
    char *argv[MAX_ARGS];
    int argc = 0;
    tokenizer(file_name, argv, &argc);
    /* project 2: argument passing */

    /* And then load the binary */
    success = load(file_name, &_if);

    /* If load failed, quit. */
    if (!success) {
        palloc_free_page(file_name);
        return -1;
    }

    /* project 2: argument passing */
    stacker(argv, argc, &_if);
    _if.R.rdi = argc;
    _if.R.rsi = _if.rsp + 8;
    // hex_dump(_if.rsp, _if.rsp, USER_STACK-_if.rsp, true);
    /* project 2: argument passing */

    palloc_free_page(file_name);

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
    /* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
     * XXX:       to add infinite loop here before
     * XXX:       implementing the process_wait. */

    struct thread *child;
    if (!(child = get_child_thread(child_tid))) {
        return -1;
    }

    sema_down(&child->wait_sema);
    list_remove(&child->child_elem);
    int exit_status = child->exit_status;
    sema_up(&child->exit_sema);
    return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *curr = thread_current();
    /* TODO: Your code goes here.
     * TODO: Implement process termination message (see
     * TODO: project2/process_termination.html).
     * TODO: We recommend you to implement process resource cleanup here. */
    for (int i = 2; i < FDCOUNT_LIMIT; i++) {
        close(i);
    }
    palloc_free_multiple(curr->fd_table, FDT_PAGES);

    file_close(curr->running);

    process_cleanup();

    sema_up(&curr->wait_sema);
    sema_down(&curr->exit_sema);
}

/* Free the current process's resources. */
static void process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4;
    /* Destroy the current process's page directory and switch back
     * to the kernel-only page directory. */
    pml4 = curr->pml4;
    if (pml4 != NULL) {
        /* Correct ordering here is crucial.  We must set
         * cur->pagedir to NULL before switching page directories,
         * so that a timer interrupt can't switch back to the
         * process page directory.  We must activate the base page
         * directory before destroying the process's page
         * directory, or our active page directory will be one
         * that's been freed (and cleared). */
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
    /* Activate thread's page tables. */
    pml4_activate(next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
extern struct lock file_lock;
static bool load(const char *file_name, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct ELF ehdr;
    struct file *file = NULL;
    off_t file_ofs;
    bool success = false;
    int i;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL) goto done;
    process_activate(thread_current());

    /* Open executable file. */
    lock_acquire(&file_lock);
    file = filesys_open(file_name);
    lock_release(&file_lock);
    if (file == NULL) {
        printf("load: %s: open failed\n", file_name);
        goto done;
    }

    t->running = file;
    file_deny_write(file);

    /* Read and verify executable header. */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
        memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 ||
        ehdr.e_machine != 0x3E  // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) ||
        ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        goto done;
    }

    /* Read program headers. */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                goto done;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes =
                            (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) -
                             read_bytes);
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes =
                            ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *)mem_page,
                                      read_bytes, zero_bytes, writable))
                        goto done;
                } else
                    goto done;
                break;
        }
    }

    /* Set up stack. */
    if (!setup_stack(if_)) goto done;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    /* TODO: Your code goes here.
     * TODO: Implement argument passing (see project2/argument_passing.html). */

    success = true;

done:
    /* We arrive here whether the load is successful or not. */
    return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file)) return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz) return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0) return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr)) return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz))) return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr) return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE) return false;

    /* It's okay. */
    return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL) return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    
    

    
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

struct lazy_load_arg {
    struct file *file;
    off_t ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
};

// 첫번째 접근으로 인한 page fault일 때, 진짜 파일을 불러온다
static bool lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */

    struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)aux;

    // 1) 파일의 position을 ofs으로 지정한다.
    file_seek(lazy_load_arg->file, lazy_load_arg->ofs);

    // 2) 파일을 read_bytes만큼 물리 프레임에 읽어 들인다.
    if (file_read(lazy_load_arg->file, page->frame->kva, lazy_load_arg->read_bytes) != (int)(lazy_load_arg->read_bytes)) {
        palloc_free_page(page->frame->kva);
        return false;
    }

    // 3) 다 읽은 지점부터 zero_bytes만큼 0으로 채운다.
    memset(page->frame->kva + lazy_load_arg->read_bytes, 0, lazy_load_arg->zero_bytes);    
    	
	free(lazy_load_arg);	

    return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
/* 파일의 OFS(오프셋)에서 시작하는 세그먼트를 UPAGE에 로드합니다.
총 READ_BYTES + ZERO_BYTES 바이트의 가상 메모리가 다음과 같이 초기화됩니다:
- UPAGE에서 READ_BYTES 바이트는 파일의 오프셋 OFS에서 시작하여 읽어야 합니다.
- UPAGE + READ_BYTES에서 ZERO_BYTES 바이트는 0으로 초기화되어야 합니다.
이 함수에 의해 초기화된 페이지는 WRITABLE이 참인 경우 사용자 프로세스에 의해
쓰기 가능해야 하며, 그렇지 않은 경우 읽기 전용이어야 합니다.
성공적으로 완료되면 true를 반환하고, 메모리 할당 오류 또는 디스크 읽기 오류가
발생하면 false를 반환합니다. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);  // read_bytes + zero_bytes가 페이지 크기(PGSIZE)의 배수인지 확인
    ASSERT(pg_ofs(upage) == 0);  // upage가 페이지 정렬되어 있는지 확인
    ASSERT(ofs % PGSIZE == 0)  // ofs가 페이지 정렬되어 있는지 확인;

    // read_bytes와 zero_bytes가 0보다 큰 동안 루프를 실행
    while (read_bytes > 0 || zero_bytes > 0)  {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        // 최대 PGSIZE 만큼 읽을 수 있다.
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        ////////////////////

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        // vm_alloc_page_with_initializer에 제공할 aux 인수로 필요한 보조 값들을 설정해야 합니다.
        // loading을 위해 필요한 정보를 포함하는 구조체를 만들어야 합니다.

        // void *aux = NULL;

        struct lazy_load_arg *lazy_load_arg = (struct lazy_load_arg *)malloc(sizeof(struct lazy_load_arg));
        
        // 내용이 담긴 파일 객체
        lazy_load_arg->file = file;

        // 이 페이지에서 읽기 시작할 위치
        lazy_load_arg->ofs = ofs;

        // 이 페이지에서 읽어야 하는 바이트 수
        lazy_load_arg->read_bytes = page_read_bytes;

        // 이 페이지에서 read_bytes만큼 읽고 공간이 남아 0으로 채워야 하는 바이트 수
        lazy_load_arg->zero_bytes = page_zero_bytes;

        ////////////////
        // vm_alloc_page_with_initializer를 호출하여 대기 중인 객체를 생성합니다.
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, lazy_load_arg)){
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
        
        // 아래 추가 //
        ofs += page_read_bytes;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;

    // 스택은 아래로 성장하므로, USER_STACK에서 PGSIZE만큼 아래로 내린 지점에서 페이지를 생성한다.
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: stack_bottom에 스택을 매핑하고 페이지를 즉시 요청하세요.
     * TODO: 성공하면, rsp를 그에 맞게 설정하세요.
     * TODO: 페이지가 스택임을 표시해야 합니다. */
    /* TODO: Your code goes here */

    // 1) stack_bottom에 페이지를 하나 할당받는다.
    if (vm_alloc_page(VM_ANON | VM_MARKER_0, stack_bottom, true)) {
        // 2) 할당 받은 페이지에 바로 물리 프레임을 매핑한다.
        if (vm_claim_page(stack_bottom)) {
            // 3) rsp를 변경한다. (argument_stack에서 이 위치부터 인자를 push한다.)
            if_->rsp = USER_STACK;
            success = true;
        }
    }

    return success;
}
#endif /* VM */

void tokenizer(char *file_name, char **argv, int *argc) {
    char *token, *save_ptr;
    token = strtok_r(file_name, " ", &save_ptr);
    while (token != NULL) {
        argv[*argc] = token;
        token = strtok_r(NULL, " ", &save_ptr);
        (*argc)++;
    }
}

void stacker(char **argv, int argc, struct intr_frame *if_) {
    /* stacking variables */
    char *addrs[MAX_ARGS];
    int i = argc - 1;
    while (i >= 0) {
        // printf("stacking %s at %p\n", argv[i], if_->rsp-strlen(argv[i])-1);
        int arglen = strlen(argv[i]);
        if_->rsp -= arglen + 1;
        strlcpy(if_->rsp, argv[i], arglen + 1);
        addrs[i--] = if_->rsp;
    }

    /* padding aligning */
    while (if_->rsp % 8 != 0) {
        // printf("padding 1 at %p\n", if_->rsp-1);
        if_->rsp--;
        *(uint8_t *)if_->rsp = 0;
    }

    /* null pointer sentiel */
    // printf("border at %p\n", if_->rsp-8);
    if_->rsp -= 8;
    *(uint64_t *)if_->rsp = 0;

    /* stacking addresses */
    i = argc - 1;
    while (i >= 0) {
        // printf("stacking %p at %p\n", addrs[i], if_->rsp-8);
        if_->rsp -= 8;
        *(uint64_t *)if_->rsp = (uint64_t)addrs[i--];
    }

    /* fake return address */
    // printf("fake return address at %p\n", if_->rsp-8);
    if_->rsp -= 8;
    *(uint64_t *)if_->rsp = 0;
}
