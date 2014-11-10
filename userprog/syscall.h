#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"
#include "lib/kernel/list.h"

/*
 * Lock that should be acquired to perform any file operations.
 */
struct lock file_resource_lock;

// The default error code to be returned when some error occurs while executing system calls.
typedef enum {
	SYSCALL_ERROR = -1
} error_code;

// The struct that holds the details of a file.
struct file_details {
	// The file descriptor
	int file_descriptor;
	// An open file.
	struct file *file;

	// list_elem that will be present in thread's list of currently used files.
	struct list_elem elem;
};


void syscall_init(void);
int add_file_to_currently_used_files(struct file *file_);
struct file* get_file_from_currently_used_files(int file_descriptor);

#endif /* userprog/syscall.h */
