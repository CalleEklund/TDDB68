#include <stdbool.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define ARG_ERROR -1

void syscall_init (void);
typedef int pid_t;

#endif /* userprog/syscall.h */
