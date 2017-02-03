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

int add_file_to_fd_table(struct file* openfile, struct thread* current_thread);

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

  int fd = open(filename);
  printf("Fd: %d\n", fd);
  int nr_bytes_w = write(2,filename,5);
  printf("%d number of bytes written.\n", nr_bytes_w);
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
  int index = add_file_to_fd_table(openfile, current_thread);
  int fd = index + current_thread->fd_table_offset;              //offset is 2 in our case
  printf("Fd table offset %d\n", current_thread->fd_table_offset);
  printf("MAx nr files %d\n", current_thread->max_nr_open_files);
  struct file* first_file = current_thread->fd_table[index];     // debugging
  if(first_file == NULL) printf("First file is null\n");
  printf("File pointer %p\n", first_file);
  return fd;
} 


void close(int fd)
{
  struct thread* current_thread = thread_current();
  int i = fd - current_thread->fd_table_offset;
  struct file* closing_file = current_thread->fd_table[i];
  file_close(closing_file);
}

int write(int fd, const void *buffer, unsigned size)
{
  int nr_bytes_written;
  struct thread* current_thread = thread_current();
  int i = fd - current_thread->fd_table_offset;
  struct file* file = current_thread->fd_table[i];

  off_t size_var = (off_t)size;
  if (file == NULL) {
    nr_bytes_written = -1;
    printf("File is null in write");
  }
  else{ 
    nr_bytes_written = (int)file_write(file, buffer, size_var);
    printf("Returned nr bytes written from file_write %d\n", nr_bytes_written);
    if (nr_bytes_written == 0){    
      printf("0 bytes were written in write");
      nr_bytes_written = -1;
  }
 }
  return nr_bytes_written;
}

/* 
Puts the file at the first found avaiable spot in the file descriptor table,
and returns the index or -1 if the file descriptor table is full.
 */
int add_file_to_fd_table(struct file* openfile, struct thread* current_thread)
{
  if(current_thread->nr_open_files <= current_thread->max_nr_open_files) {
      int i;
      for(i=0; i < current_thread->max_nr_open_files; i++) {
        if(current_thread->fd_table[i]==NULL){
          current_thread->fd_table[i] = openfile;
	  current_thread->nr_open_files++;
	  break;
        }
      }
      return i;
  }
  return -1;
}
