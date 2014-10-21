#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

typedef enum {SYSCALL_ERROR = -1} error_code;

void syscall_init (void);

#endif /* userprog/syscall.h */
