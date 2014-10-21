#include "userprog/syscall.h"
#include <lib/stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

// Lock that should be acquired to perform any file operations.
struct lock file_resource_lock;

int process_add_file(struct file *f);
struct file* process_get_file(int fd);

static void syscall_handler(struct intr_frame *);
int get_physicaladdr(const void *virtual_addr);
void retrieve_syscall_param(struct intr_frame *f, int *arg, int number_of_parameters);
void is_virtual_addr_valid(const void *virtual_addr);
void is_memory_mapped(void* buffer, unsigned size);

void syscall_init(void) {
	// Initializing the lock.
	lock_init(&file_resource_lock);
	intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED) {
	is_virtual_addr_valid((const void*) f->esp);

	int system_call_number = *(int *) f->esp;
	switch (system_call_number) {
	case SYS_HALT: {
		halt();
		break;
	}
	case SYS_EXIT: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		// The status for sys_exit
		int status = arg[0];
		exit(status);
		break;
	}
	case SYS_EXEC: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		const char *file = (const char *) get_physicaladdr((const void *) arg[0]);
		f->eax = exec(file);
		break;
	}
	case SYS_WAIT: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int pid = arg[0];
		f->eax = wait(pid);
		break;
	}
	case SYS_CREATE: {
		int arg[2];
		retrieve_syscall_param(f, &arg[0], 2);
		const char *file = (const char *) get_physicaladdr((const void *) arg[0]);
		unsigned initial_size = (unsigned) arg[1];
		f->eax = create(file, initial_size);
		break;
	}
	case SYS_REMOVE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		const char *file = (const char *) get_physicaladdr((const void *) arg[0]);
		f->eax = remove(file);
		break;
	}
	case SYS_OPEN: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		const char *file = (const char *) get_physicaladdr((const void *) arg[0]);
		f->eax = open(file);
		break;
	}
	case SYS_FILESIZE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = arg[0];
		f->eax = filesize(file_descriptor);
		break;
	}
	case SYS_READ: {
		int arg[3];
		retrieve_syscall_param(f, &arg[0], 3);
		void *virtual_buffer = (void *) arg[1];
		unsigned size = (unsigned) arg[2];
		is_memory_mapped(virtual_buffer, size);
		void *physical_buffer = get_physicaladdr(virtual_buffer);
		int file_descriptor = arg[0];
		f->eax = read(file_descriptor, physical_buffer, size);
		break;
	}
	case SYS_WRITE: {
		int arg[3];
		retrieve_syscall_param(f, &arg[0], 3);
		void *virtual_buffer = (void *) arg[1];
		unsigned size = (unsigned) arg[2];
		is_memory_mapped(virtual_buffer, size);
		void *physical_buffer = get_physicaladdr(virtual_buffer);
		int file_descriptor = arg[0];
		f->eax = write(file_descriptor, physical_buffer, size);
		break;
	}
	case SYS_SEEK: {
		int arg[2];
		retrieve_syscall_param(f, &arg[0], 2);
		int file_descriptor = arg[0];
		unsigned position = (unsigned) arg[1];
		seek(file_descriptor, position);
		break;
	}
	case SYS_TELL: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = arg[0];
		f->eax = tell(file_descriptor);
		break;
	}
	case SYS_CLOSE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = arg[0];
		close(file_descriptor);
		break;
	}
	}
}

void halt(void) {
	shutdown_power_off();
}

void exit(int status) {
	struct thread *cur = thread_current();
	if (thread_alive(cur->parent_tid)) {
		cur->my_position_in_parent_children->status_value = status;
	}
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
}

pid_t exec(const char *cmd_line) {
	pid_t pid = process_execute(cmd_line);
	struct spawned_child_thread* cp = retrieve_child(pid);
	ASSERT(cp);
	while (cp->load_status == LOAD_NOT_STARTED) {
		barrier();
	}
	if (cp->load_status == FAILED_LOAD) {
		return SYSCALL_ERROR;
	}
	return pid;
}

int wait(pid_t pid) {
	return process_wait(pid);
}

bool create(const char *file, unsigned initial_size) {
	lock_acquire(&file_resource_lock);
	bool success = filesys_create(file, initial_size);
	lock_release(&file_resource_lock);
	return success;
}

bool remove(const char *file) {
	lock_acquire(&file_resource_lock);
	bool success = filesys_remove(file);
	lock_release(&file_resource_lock);
	return success;
}

int open(const char *file) {
	lock_acquire(&file_resource_lock);
	struct file *f = filesys_open(file);
	if (!f) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int fd = process_add_file(f);
	lock_release(&file_resource_lock);
	return fd;
}

int filesize(int fd) {
	lock_acquire(&file_resource_lock);
	struct file *f = process_get_file(fd);
	if (!f) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int size = file_length(f);
	lock_release(&file_resource_lock);
	return size;
}

int read(int fd, void *buffer, unsigned size) {
	if (fd == STDIN_FILENO) {
		unsigned i;
		uint8_t* local_buffer = (uint8_t *) buffer;
		for (i = 0; i < size; i++) {
			local_buffer[i] = input_getc();
		}
		return size;
	}
	lock_acquire(&file_resource_lock);
	struct file *f = process_get_file(fd);
	if (!f) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int bytes = file_read(f, buffer, size);
	lock_release(&file_resource_lock);
	return bytes;
}

int write(int fd, const void *buffer, unsigned size) {
	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		return size;
	}
	lock_acquire(&file_resource_lock);
	struct file *f = process_get_file(fd);
	if (!f) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int bytes = file_write(f, buffer, size);
	lock_release(&file_resource_lock);
	return bytes;
}

void seek(int fd, unsigned position) {
	lock_acquire(&file_resource_lock);
	struct file *f = process_get_file(fd);
	if (!f) {
		lock_release(&file_resource_lock);
		return;
	}
	file_seek(f, position);
	lock_release(&file_resource_lock);
}

unsigned tell(int fd) {
	lock_acquire(&file_resource_lock);
	struct file *f = process_get_file(fd);
	if (!f) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	off_t offset = file_tell(f);
	lock_release(&file_resource_lock);
	return offset;
}

void close(int fd) {
	lock_acquire(&file_resource_lock);
	close_file(fd);
	lock_release(&file_resource_lock);
}

/**
 * Checks if a given virtual address is valid.
 */
void is_virtual_addr_valid(const void *virtual_addr) {
	if (virtual_addr < ((void *) 0x08048000) || !is_user_vaddr(virtual_addr)) {
		exit(SYSCALL_ERROR);
	}
}

// Returns the physical address corresponding to the give virtual address. If physical addressed is unmapped, this function will call exit().
int get_physicaladdr(const void *virtual_addr) {
	//TODO
	// TO DO: Need to check if all bytes within range are correct
	// for strings + buffers
	//***********
	is_virtual_addr_valid(virtual_addr);
	void *physical_addr = pagedir_get_page(thread_current()->pagedir, virtual_addr);
	if (physical_addr == NULL) {
		exit(SYSCALL_ERROR);
	}
	return (int) physical_addr;
}

int process_add_file(struct file *f) {
	struct file_details *pf = malloc(sizeof(struct file_details));
	pf->file = f;
	pf->file_descriptor = thread_current()->file_descriptor;
	thread_current()->file_descriptor++;
	list_push_back(&thread_current()->currently_used_files, &pf->elem);
	return pf->file_descriptor;
}

struct file* process_get_file(int fd) {
	struct thread *t = thread_current();
	struct list_elem *e;

	for (e = list_begin(&t->currently_used_files);
			e != list_end(&t->currently_used_files); e = list_next(e)) {
		struct file_details *pf = list_entry (e, struct file_details, elem);
		if (fd == pf->file_descriptor) {
			return pf->file;
		}
	}
	return NULL;
}

void close_file(int fd) {
	struct thread *t = thread_current();
	struct list_elem *next, *e = list_begin(&t->currently_used_files);

	while (e != list_end(&t->currently_used_files)) {
		next = list_next(e);
		struct file_details *pf = list_entry (e, struct file_details, elem);
		if (fd == pf->file_descriptor || fd == PROCESS_EXIT) {
			file_close(pf->file);
			list_remove(&pf->elem);
			free(pf);
			if (fd != PROCESS_EXIT) {
				return;
			}
		}
		e = next;
	}
}

// Retrieves the system call parameters
void retrieve_syscall_param(struct intr_frame *f, int *arg, int number_of_parameters) {
	int i;
	int *ptr;

	for (i = 0; i < number_of_parameters; i++) {
		ptr = f->esp + i*sizeof(char *) + sizeof(char *);
		is_virtual_addr_valid((const void *) ptr);
		arg[i] = *ptr;
	}
}
// Checks if the buffer is valid.
void is_memory_mapped(void* buffer, unsigned size) {
	unsigned i;
	char* buffer_ = (char *) buffer;
	for (i = 0; i < size; i++,buffer_++) {
		is_virtual_addr_valid((const void*) buffer_);
	}
}
