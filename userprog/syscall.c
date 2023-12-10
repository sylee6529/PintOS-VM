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

typedef int pid_t;

void syscall_entry (void);
void syscall_handler (struct intr_frame *);
struct file *get_file_from_fd_table (int fd);

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
	
}

void check_address(void *addr) {
	struct thread *t = thread_current();
	if (!is_user_vaddr(addr) || addr == NULL || pml4_get_page(t->pml4 , addr) == NULL) {
		exit(-1);
	}
}

int add_file_to_fd_table (struct file *file) {
	struct thread *t = thread_current();
	struct file **fdt = t->fd_table;
	int fd = t->fd_idx;

	while (t->fd_table[fd] != NULL) {
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
	if (!list_empty(&thread_current()->child_list)) {
		thread_current()->exit_status = list_entry(list_front(&thread_current()->child_list), struct thread, child_elem)->exit_status;
	} else {
		thread_current()->exit_status = status;
	}
	printf("%s: exit(%d)\n", thread_name(), thread_current()->exit_status);
	thread_exit();
}

pid_t fork (const char *thread_name) {
	return 0;
}

int exec (const char *file) {
	check_address(file);
    if (process_exec((void *) file) < 0) {
		exit(-1);
	}
}

int wait (pid_t pid) {
	return process_wait (pid);
}

bool create (const char *file, unsigned initial_size) {
	check_address(file);
	if (filesys_create(file, initial_size)) {
		return true;
	}
	else {
		return false;
	}
}

bool remove (const char *file) {
	check_address(file);
	if (filesys_remove(file)) {
		return true;
	}
	else {
		return false;
	}
}

int open (const char *file) {
	check_address(file);
	struct file *file_info = filesys_open(file);

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
	// return file_length(thread_current()->fd_table[fd]);
	return 0;
}

int read (int fd, void *buffer, unsigned length) {
	check_address(buffer);

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

		bytesRead = file_read(f, buffer, length);
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

		bytesRead = file_write(f, buffer, length);
	}
	return bytesRead;
}

void seek (int fd, unsigned position) {
	return 0;
}

unsigned tell (int fd) {
	return 0;
}

void close (int fd) {
	return 0;
}



/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_HALT:
			halt();			// pintos를 종료시키는 시스템 콜
			break;
		case SYS_EXIT:
			exit(f->R.rdi);	// 현재 프로세스를 종료시키는 시스템 콜
			break;
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi);
			break;
		case SYS_EXEC:
			if (exec(f->R.rdi) == -1) {
				exit(-1);
			}
			break;
		case SYS_WAIT:
			f->R.rax = process_wait(f->R.rdi);
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
			thread_exit();
	}
}
