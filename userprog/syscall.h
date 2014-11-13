#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define STACK_HEURISTIC 32

/*
 * Lock that should be acquired to perform any file operations.
 */
struct lock file_resource_lock;

// The default error code to be returned when some error occurs while executing system calls.
typedef enum {
	SYSCALL_ERROR = -1
} error_code;

// The struct that holds the details of a map entry.
struct mem_map_entry {

	// A unique identifier for the entry
	int map_id;

	// supplemental page table entry
	struct supplemental_pte *spte;

	// list_elem that will be present in thread's list of currently used mem maps.
	struct list_elem elem;
};

// The struct that holds the details of a file.
struct file_details {
	// The file descriptor
	int file_descriptor;
	// An open file.
	struct file *file;

	// list_elem that will be present in thread's list of currently used files.
	struct list_elem elem;
};

void syscall_init (void);

// Closes the file
void close_file(int fd);

#endif /* userprog/syscall.h */
