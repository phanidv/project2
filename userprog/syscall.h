#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

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

#endif /* userprog/syscall.h */
