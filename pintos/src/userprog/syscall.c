#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"


void halt(void);

bool create (const char *file, unsigned initial_size);

int open (const char *file); 

void close(int fd);

int write(int fd, const void *buffer, unsigned size);

int get_new_fd (struct file* openfile, struct thread* current_thread);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  printf("try to create file \n");
  char filename[5] = {'a','.','t','x','t'};
  /*bool success = create(filename, 100);
  if(success) printf("Succesfully created file a.txt\n");*/

  int fd = open(filename);
  printf("Fd: %d\n", fd);
  
  halt();
  thread_exit ();
}

void halt(void)
{
  power_off();  // Works! (i think)
}


bool create (const char *file, unsigned initial_size)
{
  off_t init_size = (off_t) initial_size;
  return filesys_create(file, init_size);
}


int open (const char *file)
{
  struct thread* current_thread = thread_current();
  struct file* openfile = filesys_open(file);
  if(openfile == NULL) {
    return -1;
  }
  int fd = get_new_fd(openfile, current_thread);
  struct file* first_file = current_thread->fd_table[0];
  if(first_file == NULL) printf("First file is null\n");
  printf("File pointer %p\n", first_file);
  return fd;
} 

/*
void close(int fd)
{
}

int write(int fd, const void *buffer, unsigned size)
{
}*/


int get_new_fd (struct file* openfile, struct thread* current_thread)
{
  current_thread->fd_table[0] = openfile;
  current_thread->nr_open_files++;

  return 2;
}

