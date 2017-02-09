#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "userprog/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"
#include "lib/kernel/console.h"
#include "devices/input.h"


void halt(void);

void exit(int status);

bool create (const char *file, unsigned initial_size);

int open (const char *file); 

void close(int fd);

int write(int fd, const void *buffer, unsigned size);

int read (int fd, void *buffer, unsigned size);

int add_file_to_fd_table(struct file* openfile, struct thread* current_thread);

void get_args(int nr_args, int* args, void* esp);

bool validate_fd(int fd, struct thread* current_thread);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf("Entering syscall handler...\n");
  uint32_t return_value = NULL;
  int syscall_nr =  *((int*)f->esp);
  //printf("Syscall nr is %d\n", syscall_nr);
  int* arg1;

  int args[3];         // Used to store syscall args, max nr args 3

  switch(syscall_nr) {

  case SYS_HALT :                   /* Halt the operating system.*/
    halt();
    break;
    
  case SYS_EXIT :                   /* Terminate this process. */
    get_args(1, args, f->esp);
    exit((int) args[0]);
    break; 

  case SYS_CREATE :                 /* Create a file. */
    get_args(2, args, f->esp);
    return_value = (uint32_t) create((const char*)args[0], (unsigned)args[1]);
    break;

  case SYS_OPEN :                   /* Open a file. */
    get_args(1, args, f->esp);
    return_value = (uint32_t) open((const char*) args[0]);
    break;

  case SYS_READ :                   /* Read from a file. */
    get_args(3, args, f->esp);
    return_value = (uint32_t) read((int)args[0], (void*)args[1], (unsigned)args[2]);
    break;

  case SYS_WRITE :                  /* Write to a file. */
    get_args(3, args, f->esp);
    return_value = (uint32_t) write((int)args[0], (const void*)args[1], (unsigned)args[2]);
    break;

  case SYS_CLOSE :                  /* Close a file. */
    get_args(1, args, f->esp);
    close((int) args[0]);
    break;
  }

  f->eax = return_value;
}

void halt(void)
{
  printf("Syscall halt\n");
  power_off();  // Works! (i think)
}

void exit(int status UNUSED)
{
  printf("Syscall exit thread\n");
  struct thread* t = thread_current();
  if (t->nr_open_files > 0) { 
    int i;
    for(i=0; i<t->max_nr_open_files; i++) {
      if(t->fd_table[i] != NULL) {
        int fd = i + t->fd_table_offset;
        close(fd);
      }
    } 
 }
  thread_exit();
}

bool create (const char *file, unsigned initial_size)
{
  off_t init_size = (off_t) initial_size;
  printf("Init size %d in create",initial_size);
  return filesys_create(file, init_size);
}

int open (const char *file)
{
  printf("First letter of file name %c \n", *file);
  struct thread* current_thread = thread_current();
  struct file* openfile = filesys_open(file);
  if(openfile == NULL) {
    printf("Openfile is nuuullllll in open\n");
    return -1;
  }
  printf("Openfile is not null in open\n");
  int index = add_file_to_fd_table(openfile, current_thread);
  int fd = index + current_thread->fd_table_offset;              //offset is 2 in our case
  struct file* file_fd = current_thread->fd_table[index];     // debugging
  if(file_fd == NULL) printf("First file is null\n");
  printf("File pointer %p in open\n", file_fd);
  return fd;
} 

void close(int fd)
{ 
  struct thread* current_thread = thread_current();
  if (!(validate_fd(fd, current_thread))) return;
  int i = fd - current_thread->fd_table_offset;
  struct file* closing_file = current_thread->fd_table[i];
  if (closing_file != NULL)
    { file_close(closing_file);
      current_thread->fd_table[i] = NULL;
      printf("Setting fd table index %d to null \n", i);
      (current_thread->nr_open_files)-- ;  
    }
}

int write(int fd, const void *buffer, unsigned size)
{
  int nr_bytes_written = -1;
  
  if(fd == 1) {
    // File descriptor 1 writes to console
    const unsigned  max_size = 500;  // bytes
    const void *curr_buffer = buffer;
    unsigned curr_size = size;
    while(curr_size > max_size) {
      putbuf(curr_buffer, (size_t) max_size);
      curr_size -= max_size;
      curr_buffer += max_size;
      printf("Wrote max size\n");
    }
    putbuf(curr_buffer, (size_t) curr_size);
    return (int) size;   
  }

  // Deal with all file descriptors stored in current thread's 
  // file descriptor table.
  
  struct thread* current_thread = thread_current();
  if ( !(validate_fd(fd, current_thread))) return nr_bytes_written;
  int i = fd - current_thread->fd_table_offset;
  struct file* file = current_thread->fd_table[i];

  off_t size_var = (off_t)size;
  if (file == NULL || buffer == NULL) {
    nr_bytes_written = -1;
    printf("File or buffer is null in write");
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

int read (int fd, void *buffer, unsigned size) 
{
  int nr_bytes_read = -1;
  
  if (fd == 0) 
  {
    uint8_t* curr_buffer = (uint8_t*)buffer; 
    unsigned i;
    for(i=0 ; i<size; i++){ // read from the keyboard
      uint8_t key; 
      key = input_getc();
      curr_buffer[i]=key;
      }
    return size;
  }
  struct thread* current_thread = thread_current();
  if ( !(validate_fd(fd, current_thread))) return nr_bytes_read;
  int i = fd - current_thread->fd_table_offset;
  struct file* file = current_thread->fd_table[i];
  printf("File pointer %p in read\n", file);
  if ( file != NULL && buffer != NULL)
    {
      nr_bytes_read = (int)file_read(file, buffer, (off_t)size);
    }
  return nr_bytes_read;
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
        printf("Index %d in fd table passed\n",i);
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

void get_args(int nr_args, int* args, void* esp)
{
  int i;
  int* p;
  for(i=0; i < nr_args; i++) {
    p = (int*) esp + 1 + i;
    args[i] = *p;
    //args[i] = *((int*) esp +1 +1);        // TOFDO: Why this don't work??!!!!
  }
}

bool validate_fd(int fd, struct thread* current_thread)
{
  return ((fd < current_thread->max_nr_open_files) & (fd > 0)); 
}
