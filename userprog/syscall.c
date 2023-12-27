#include <debug.h>
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file *get_file_from_fd_table (int fd);
struct lock file_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&file_lock);
}

void check_address(void *addr) {
	struct thread *t = thread_current();
	/* [기존 코드: 정상적인 lazy loading 에서도 에러 검출되는 구조]

	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4 , addr) == NULL) {
		exit(-1);
	}
	*/

	/* [수정 코드: lazy loading이라 pml4에 없는 상황 고려] */
	if (!is_user_vaddr(addr) || addr == NULL) {
		exit(-1);
	}
	
	if (pml4_get_page(t->pml4 , addr) == NULL){
		// spt에 있으면 정상적인 lazy loading 상황 -> 에러 아님!
		if(!spt_find_page(&t->spt, addr)){
			exit(-1);
		}
	}
}


int add_file_to_fd_table (struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->fd_table;
	int fd = t->fd_idx;
	while (t->fd_table[fd] != NULL) {
		if (fd >= FDCOUNT_LIMIT) {
			t->fd_idx = FDCOUNT_LIMIT;
			return -1;
		}
		fd++;
	}
	t->fd_idx = fd;
	fdt[fd] = file;
	return fd;
}

void halt(void) {
	power_off();
}

void exit (int status) {
	thread_current()->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), thread_current()->exit_status);
	thread_exit();
}

tid_t fork (const char *thread_name, int (*f)(int)) {
	check_address(thread_name);
	return process_fork(thread_name, f);
}

int exec (const char *file) {
	check_address(file);
    if (process_exec((void *) file) < 0) {
		exit(-1);
	}
}

int wait (tid_t tid) {
	return process_wait (tid);
}

bool create (const char *file, unsigned initial_size) {
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int open (const char *file) {
	check_address(file);
	lock_acquire(&file_lock);
	struct file *file_info = filesys_open(file);
	lock_release(&file_lock);
	if (file_info == NULL) {
		return -1;
	}
	int fd = add_file_to_fd_table(file_info);
	if (fd == -1) {
		file_close(file_info);
	}
	return fd;
}

int filesize (int fd) {
	return file_length(get_file_from_fd_table(fd));
}

int read (int fd, void *buffer, unsigned length) {
	/* 
	[write-protected 여부 체크]
	
	1) pt-write-code2 테스트
	- 잘못된 영역(코드 세그먼트)에 read() 시도를 한다. 
	- 메모리 관점에서 보면 read() 시스템콜은 파일의 데이터를 읽어서 메모리의 버퍼에 쓰는 작업을 수행
	- 즉, not writable한 페이지에 write를 시도하고 있다. 
	- 해당 addr 페이지의 writable 여부를 체크해주고, -1 exit code를 반환해야 한다.

	2) pt-grow-stk-sc 테스트
	- 첫 스택접근이 syscall에 의한 것일 때도 스택이 올바르게 확장되는가를 체크한다. 

	*/

	struct page *page = spt_find_page(&thread_current()->spt, buffer);
	if (page) {
		if (!page->writable) {
			exit(-1);
		}
	}

	//

	int bytesRead = 0;
	if (fd == 0) { 
		for (int i = 0; i < length; i++) {
			char c = input_getc();
			((char *)buffer)[i] = c;
			bytesRead++;

			if (c == '\n') break;
		}
	} else if (fd == 1) {
		return -1;
	} else {
		struct file *f = get_file_from_fd_table(fd);
		if (f == NULL) {
			return -1; 
		}
		lock_acquire(&file_lock);
		bytesRead = file_read(f, buffer, length);
		lock_release(&file_lock);
	}
	return bytesRead;
}

struct file *get_file_from_fd_table (int fd) {
	struct thread *t = thread_current();
	if (fd < 0 || fd >= 128) {
		return NULL;
	}
	return t->fd_table[fd];
}

int write (int fd, const void *buffer, unsigned length) {	
	check_address(buffer);
	int bytesRead = 0;

	if (fd == 0) {
		return -1;
	} else if (fd == 1) {
		putbuf(buffer, length);
		return length;
	} else {
		struct file *f = get_file_from_fd_table(fd);
		if (f == NULL) {
			return -1;
		}
		lock_acquire(&file_lock);
		bytesRead = file_write(f, buffer, length);
		lock_release(&file_lock);
	}
	return bytesRead;
}

void seek (int fd, unsigned position) {
	struct file *f = get_file_from_fd_table(fd);
	if (f == NULL) {
		return;
	}
	file_seek(f, position);
}

unsigned tell (int fd) {
	struct file *f = get_file_from_fd_table(fd);
	if (f == NULL) {
		return -1;
	}
	return file_tell(f);
}

void close (int fd) {
	struct thread *t = thread_current();
	struct file **fdt = t->fd_table;
	if (fd < 0 || fd >= 128) {
		return;
	}
	if (fdt[fd] == NULL) {
		return;
	}
	file_close(fdt[fd]);
	fdt[fd] = NULL;
}



/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// syscall 호출되면 커널 모드로 전환 -> thread에 rsp 저장
	thread_current()->rsp = f->rsp;

	// syscall table
	switch (f->R.rax) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) < 0) {
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
			break;
		default:
			exit(-1);
	}
}
