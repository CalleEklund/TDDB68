#include "userprog/syscall.h"
#include <stdio.h>
#include <stdbool.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"


void halt(void);

bool create (const char *file, unsigned initial_size);

int open (const char *file); 

void close(int fd);

int write(int fd, const void *buffer, unsigned size);

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
  bool success = create(filename, 100);
  if(success) printf("Succesfully created file a.txt\n");

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

/*
int open (const char *file)
{
} 

void close(int fd)
{
}

int write(int fd, const void *buffer, unsigned size)
{
}*/

