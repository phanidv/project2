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

int add_file_to_currently_used_files(struct file *file_);
struct file* get_file_from_currently_used_files(int file_descriptor);

static void syscall_handler(struct intr_frame *);
int get_physicaladdr(const void *virtual_addr);
void retrieve_syscall_param(struct intr_frame *f, int *arg,
		int number_of_parameters);
void is_virtual_addr_valid(const void *virtual_addr);
void is_memory_mapped(void* buffer, unsigned size);

char* get_physcial_file(int file_syscall_parameter);
unsigned int get_size(int size_syscall_parameter);
int get_file_descriptor(int file_descriptor_syscall_parameter);
int read_from_standard_input(void *buffer, unsigned size_to_be_read);
int read_from_file(int file_descriptor, void *buffer, unsigned size_to_be_read);
int write_to_standard_output(void *buffer, unsigned size_to_be_read);
int write_to_file(int file_descriptor, void *buffer, unsigned size_to_be_read);
int perform_actions_after_file_open(struct file *file_);
void close_single_file(struct file_details* file_detials);
struct file_details* find_file_details(struct thread *t, int file_descriptor);


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
		const char *file = get_physcial_file(arg[0]);
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
		const char *file = get_physcial_file(arg[0]);
		unsigned initial_size = get_size(arg[1]);
		f->eax = create(file, initial_size);
		break;
	}
	case SYS_REMOVE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		const char *file = get_physcial_file(arg[0]);
		f->eax = remove(file);
		break;
	}
	case SYS_OPEN: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		const char *file = get_physcial_file(arg[0]);
		f->eax = open(file);
		break;
	}
	case SYS_FILESIZE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = get_file_descriptor(arg[0]);
		f->eax = filesize(file_descriptor);
		break;
	}
	case SYS_READ: {
		int arg[3];
		retrieve_syscall_param(f, &arg[0], 3);
		void *virtual_buffer = (void *) arg[1];
		unsigned size = get_size(arg[2]);
		is_memory_mapped(virtual_buffer, size);
		void *physical_buffer = get_physicaladdr(virtual_buffer);
		int file_descriptor = get_file_descriptor(arg[0]);
		f->eax = read(file_descriptor, physical_buffer, size);
		break;
	}
	case SYS_WRITE: {
		int arg[3];
		retrieve_syscall_param(f, &arg[0], 3);
		void *virtual_buffer = (void *) arg[1];
		unsigned size = get_size(arg[2]);
		is_memory_mapped(virtual_buffer, size);
		void *physical_buffer = get_physicaladdr(virtual_buffer);
		int file_descriptor = get_file_descriptor(arg[0]);
		f->eax = write(file_descriptor, physical_buffer, size);
		break;
	}
	case SYS_SEEK: {
		int arg[2];
		retrieve_syscall_param(f, &arg[0], 2);
		int file_descriptor = get_file_descriptor(arg[0]);
		unsigned position = (unsigned) arg[1];
		seek(file_descriptor, position);
		break;
	}
	case SYS_TELL: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = get_file_descriptor(arg[0]);
		f->eax = tell(file_descriptor);
		break;
	}
	case SYS_CLOSE: {
		int arg[1];
		retrieve_syscall_param(f, &arg[0], 1);
		int file_descriptor = get_file_descriptor(arg[0]);
		close(file_descriptor);
		break;
	}
	}
}

void halt(void) {
	shutdown_power_off();
}

void exit(int status) {
	struct thread *current_thread = thread_current();
	if (is_thread_alive(current_thread->parent_tid)) {
		current_thread->my_position_in_parent_children->status_value = status;
	}
	printf("%s: exit(%d)\n", current_thread->name, status);
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
	int file_descriptor = perform_actions_after_file_open(f);
	lock_release(&file_resource_lock);
	return file_descriptor;
}

int filesize(int file_descriptor) {
	lock_acquire(&file_resource_lock);
	struct file *f = get_file_from_currently_used_files(file_descriptor);
	if (f == NULL) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int size = file_length(f);
	lock_release(&file_resource_lock);
	return size;
}

int read(int file_descriptor, void *buffer, unsigned size) {
	if (file_descriptor == STDIN_FILENO) {
		int size_ = read_from_standard_input(buffer, size);
		return size_;
	}
	int bytes = read_from_file(file_descriptor, buffer, size);
	return bytes;
}

int write(int file_descriptor, const void *buffer, unsigned size) {
	if (file_descriptor == STDOUT_FILENO) {
		int size_ = write_to_standard_output(buffer, size);
		return size_;
	}
	int bytes = write_to_file(file_descriptor, buffer, size);
	return bytes;
}

void seek(int fd, unsigned position) {
	lock_acquire(&file_resource_lock);
	struct file *f = get_file_from_currently_used_files(fd);
	if (f == NULL) {
		lock_release(&file_resource_lock);
		return;
	}
	file_seek(f, position);
	lock_release(&file_resource_lock);
}

unsigned tell(int fd) {
	lock_acquire(&file_resource_lock);
	struct file *f = get_file_from_currently_used_files(fd);
	if (f == NULL) {
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
	void *physical_addr = pagedir_get_page(thread_current()->pagedir,
			virtual_addr);
	if (physical_addr == NULL) {
		exit(SYSCALL_ERROR);
	}
	return (int) physical_addr;
}

int add_file_to_currently_used_files(struct file *file_) {
	struct file_details *f_details = malloc(sizeof(struct file_details));
	f_details->file = file_;
	f_details->file_descriptor = thread_current()->current_fd_to_be_assigned;
	thread_current()->current_fd_to_be_assigned++;
	list_push_back(&thread_current()->currently_used_files, &f_details->elem);
	return f_details->file_descriptor;
}

struct file* get_file_from_currently_used_files(int file_descriptor) {
	struct thread *t = thread_current();
	struct list_elem *e;

	e = list_begin(&t->currently_used_files);
	while (e != list_end(&t->currently_used_files)) {
		struct file_details *file_details_ =
				list_entry (e, struct file_details, elem);
		if (file_descriptor == file_details_->file_descriptor) {
			return file_details_->file;
		}
		e = list_next(e);
	}

	return NULL;
}

void close_file(int fd) {
	struct thread *t = thread_current();
	struct list_elem *next, *e;

	if (fd != PROCESS_EXIT) {
		struct file_details *pf = find_file_details(t, fd);
		if (pf != NULL) {
			close_single_file(pf);
		}
	} else {
		for (e = list_begin(&t->currently_used_files);
				e != list_end(&t->currently_used_files); e = next) {
			next = list_next(e);
			struct file_details *pf = list_entry (e, struct file_details, elem);
			if (pf != NULL) {
				close_single_file(pf);
			}
		}
	}
}

// Closes single file
void close_single_file(struct file_details* file_detials) {
	if (file_detials != NULL) {
		file_close(file_detials->file);
		list_remove(&file_detials->elem);
		free(file_detials);
	}
}

// Finds the file details in the list of currently used files of thread using the file descriptor.
struct file_details* find_file_details(struct thread *t, int file_descriptor) {
	struct list_elem *e;

	for (e = list_begin(&t->currently_used_files);
			e != list_end(&t->currently_used_files); e = list_next(e)) {
		struct file_details *pf = list_entry (e, struct file_details, elem);
		if (file_descriptor == pf->file_descriptor) {
			return pf;
		}
	}
	return NULL;
}

// Returns the file pointer
char* get_physcial_file(int file_syscall_parameter) {
	return (const char *) get_physicaladdr(
			(const void *) file_syscall_parameter);
}

// returns the size as unsidned value.
unsigned int get_size(int size_syscall_parameter) {
	return (unsigned) size_syscall_parameter;
}

// Returns the file descriptor.
int get_file_descriptor(int file_descriptor_syscall_parameter) {
	return file_descriptor_syscall_parameter;
}

// Reads for standard input.
int read_from_standard_input(void *buffer, unsigned size_to_be_read) {
	unsigned i;
	uint8_t* buffer_ = (uint8_t *) buffer;
	for (i = 0; i < size_to_be_read; i++) {
		buffer_[i] = input_getc();
	}
	return size_to_be_read;
}

// Reads from file
int read_from_file(int file_descriptor, void *buffer, unsigned size_to_be_read) {
	lock_acquire(&file_resource_lock);
	struct file *f = get_file_from_currently_used_files(file_descriptor);
	if (f == NULL) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int bytes = file_read(f, buffer, size_to_be_read);
	lock_release(&file_resource_lock);
	return bytes;
}

// Write to standard output
int write_to_standard_output(void *buffer, unsigned size_to_be_read) {
	putbuf(buffer, size_to_be_read);
	return size_to_be_read;
}

// Writes to file
int write_to_file(int file_descriptor, void *buffer, unsigned size_to_be_read) {
	lock_acquire(&file_resource_lock);
	struct file *f = get_file_from_currently_used_files(file_descriptor);
	if (f == NULL) {
		lock_release(&file_resource_lock);
		return SYSCALL_ERROR;
	}
	int bytes = file_write(f, buffer, size_to_be_read);
	lock_release(&file_resource_lock);
	return bytes;
}

// Performs actions after file is opened
int perform_actions_after_file_open(struct file *file_) {
	if (file_ == NULL) {
		return SYSCALL_ERROR;
	}
	int file_descriptor = add_file_to_currently_used_files(file_);
	return file_descriptor;
}

// Retrieves the system call parameters
void retrieve_syscall_param(struct intr_frame *f, int *arg,
		int number_of_parameters) {
	int i;
	int *ptr;

	for (i = 0; i < number_of_parameters; i++) {
		ptr = f->esp + i * sizeof(char *) + sizeof(char *);
		is_virtual_addr_valid((const void *) ptr);
		arg[i] = *ptr;
	}
}
// Checks if the buffer is valid.
void is_memory_mapped(void* buffer, unsigned size) {
	unsigned i;
	char* buffer_ = (char *) buffer;
	for (i = 0; i < size; i++, buffer_++) {
		is_virtual_addr_valid((const void*) buffer_);
	}
}
