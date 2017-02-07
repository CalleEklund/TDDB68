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

bool create (const char *file, unsigned initial_size);

int open (const char *file); 

void close(int fd);

int write(int fd, const void *buffer, unsigned size);

int read (int fd, void *buffer, unsigned size);

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
  char filename_a[5] = {'a','.','t','x','t'};
  char filename_c[5] = {'c','.','t','x','t'};
  char nonsense[11] = {'a','.','t','x','t','h','e','j','r','y','f'};
  char buffer[10];
  //bool success = create(filename, 50);
  //if(success) printf("Succesfully created file a.txt\n");

  int fd_c = open(filename_c);
  close(fd_c);
  //int fd_a = open(filename_a);

  printf("Fdc: %d\n", fd_c);
  //printf("Fda: %d\n", fd_a);
  

  //close(fd_c);
  //int nr_bytes_w1 = write(fd,filename,5);
  //int nr_bytes_w3 = write(fd,nonsense,11);
  //int nr_bytes_r = read(fd, buffer,10);
  //int nr_bytes_w2 = write(1,buffer,10);
  //printf("%d number of bytes read.\n", nr_bytes_r);
  //printf("%d number of bytes written to file try1.\n", nr_bytes_w1);
  //printf("%d number of bytes written to file try2.\n", nr_bytes_w3);
  //printf("%d number of bytes written to console.\n", nr_bytes_w2);
  //halt();
  // thread_exit ();
}

void halt(void)
{
  power_off();  // Works! (i think)
}

void exit(int status)
{
 thread_exit ();
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
  int i = fd - current_thread->fd_table_offset;
  struct file* closing_file = current_thread->fd_table[i];
  file_close(closing_file);
  current_thread->fd_table[i] = NULL;
  printf("Setting fd table index %d to null \n", i);
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
    //uint8_t key; 
    nr_bytes_read = input_getc();
  }
  struct thread* current_thread = thread_current();
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
