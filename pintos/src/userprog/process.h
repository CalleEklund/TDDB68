#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

struct new_proc_args {
  struct semaphore load_sema;
  struct parent_child* parent;
  char* file_name;
  //char* argv[32];
  //int argc;
  char* cmd_line;
};

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
