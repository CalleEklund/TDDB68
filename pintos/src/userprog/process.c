#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program with given arguments loaded from
   CMD_LINE.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line) 
{
  char *cmd_copy;
  tid_t tid;

  /* Make a copy of CMD_LINE.
     Otherwise there's a race between the caller and load(). */
  cmd_copy = palloc_get_page (0);
  if (cmd_copy == NULL)
    return TID_ERROR;
  strlcpy (cmd_copy, cmd_line, PGSIZE);

  /* Create a new thread to execute FILE_NAME. */

  // Create new_proc_args to hold filename, arguments, argc,
  // load_sema and pointer to parent's parent_child struct.
  struct new_proc_args* pr_args = (struct new_proc_args*) malloc(sizeof(struct new_proc_args));
  pr_args->cmd_line = cmd_copy;
  sema_init(&(pr_args->load_sema),0);

  struct parent_child* child = (struct parent_child*) malloc(sizeof(struct parent_child));
  //printf("Before child push back\n");
  list_push_back(&thread_current()->children, &(child->elem));
  //printf("After child push back\n");
  
  // initialise alive_count protected by its lock
  lock_init(&(child->alive_lock));
  lock_acquire(&(child->alive_lock));
  child->alive_count = 2;
  lock_release(&(child->alive_lock));
  child->exit_status = -1;
  
  //initialisation of the wait_lock of the child
  sema_init(&(child->wait_sema),0);

  pr_args->parent = child;

  char* file_name = palloc_get_page (0);
  if (file_name == NULL)
    return TID_ERROR;
  strlcpy (file_name, cmd_line, PGSIZE);

  char* save_ptr;
  char* file_name_extr = strtok_r (file_name, " ", &save_ptr);
  pr_args->file_name = file_name_extr;

  tid = thread_create (file_name_extr, PRI_DEFAULT, start_process, pr_args);
  // Wait for program to load
  printf("Before waiting in load_sema\n");
  //printf("Value of load_sema in pr_execute: %d\n", (int) pr_args->load_sema.value);
  sema_down(&(pr_args->load_sema));
  if(!pr_args->load_success) tid = TID_ERROR;
  printf("Awoke from load_sema\n");

  child->child = tid;
  printf("Set new child id to %d\n", (int) child->child);
  free(pr_args);

  if (tid == TID_ERROR)
    palloc_free_page (cmd_copy); 

  printf("End of process execute\n");

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  char* file_name = ((struct new_proc_args*) aux)->file_name;
  struct intr_frame if_;
  bool success;

  // Transfer info from aux to the new thread
  struct new_proc_args* pr_args = ((struct new_proc_args*) aux);
  // Store parent pnt separetely since pr_args will be freed in process_execute()
  thread_current()->parent = pr_args->parent;
  thread_current()->pr_args = pr_args;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);
  // Release load_lock so parent process can continue executing
  pr_args->load_success = success;
  printf("Before load sema up\n");
  sema_up(&(pr_args->load_sema));

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) {
    printf("Unsuccesfully loaded file_name\n");
    thread_exit ();
  }

  printf("Before last line in start_process()\n");
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{
  printf("In process_wait()\n");
  struct thread* t = thread_current();
  struct list_elem* e; 
  int exit_status = -1;
  for (e = list_begin (&(t->children)); e != list_end (&(t->children)); e = list_next (e))
      {
          struct parent_child *child = list_entry (e, struct parent_child, elem);
	  printf("Cmp children ids: %d and given %d\n", child->child, child_tid);
          if (child->child == child_tid) 
	    {
	      printf("Child found in wait\n");
	      // Child has terminated
	      if (child->alive_count == 1) 
		{
		  exit_status = child->exit_status;
		  printf("Child with exit status %d has already exited\n", exit_status);
		}
	      // Wait for child to terminate
	      else 
		{
		  printf("Waiting for child to terminate...\n");
		  sema_down(&(child->wait_sema));
		  exit_status = child->exit_status;
		  printf("Child with exit status %d has now exited\n", exit_status);
		}
	      child->exit_status = -1;
	      break;
	    }
      }
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  printf("Start of process_exit()\n");
  struct thread *cur = thread_current ();
  uint32_t *pd;
  struct parent_child* par = cur->parent;
  int debug_status = par->exit_status;
  

  // Do if the current thread is not the initial thread
  if(par != NULL) { 

    // alive count is decremented
    lock_acquire(&(par->alive_lock));
    //printf("Reached in process_exit()\n");
    par->alive_count--;
            
    //   Alive count goes from 1 to 0 (terminate after parent)  (decr parent struct)
    // free our parent struct
    // (parent did not call wait)
    if (par->alive_count == 0)
      {
	lock_release(&(par->alive_lock));
	free(par);
      }
    // Alive count goes from 2 to 1 (terminate before parent) (decr parent struct)
    // do sema up on wait_sema
    else
      {
	// release the sema holding process_wait()
	printf("%s: exit(%d)\n", cur->name, debug_status);
	sema_up(&(cur->parent->wait_sema));
	printf("After sema up in process_exit() Exiting with status %d\n", par->exit_status);
      }
  }
  
  // Go through all children and decrement alive count
  // Alive count goes from 2 to 1 (terminate before its child) (decr child struct)
  // Alive count goes from 1 to 0 (terminate after its child) (decr child struct)
  //   free the child's struct and remove it from the list
  struct list_elem* e; 
  for (e = list_begin (&(cur->children)); e != list_end (&(cur->children)); e = list_next (e))
      {
          struct parent_child *child = list_entry (e, struct parent_child, elem);
	  lock_acquire(&child->alive_lock);
	  child->alive_count--;
          if (child->alive_count == 0) 
	    {
	      lock_release(&(child->alive_lock));
	      list_remove(e);
	      printf("Removed child from children list\n");
	      free(child);
	    }
      }

  //printf("Before the page dir destruction in process_exit()\n");
  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  printf("At end of process_exit()\n");
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Set up stack. */
  if (!setup_stack (esp)){
    goto done;
  }

   /* Uncomment the following line to print some debug
     information. This will be useful when you debug the program
     stack.*/
  //#define STACK_DEBUG

#ifdef STACK_DEBUG
  printf("*esp is %p\nstack contents:\n", *esp);
  hex_dump((int)*esp , *esp, PHYS_BASE-*esp+16, true);
  /* The same information, only more verbose: */
  /* It prints every byte as if it was a char and every 32-bit aligned
     data as if it was a pointer. */
  void * ptr_save = PHYS_BASE;
  i=-15;
  while(ptr_save - i >= *esp) {
    char *whats_there = (char *)(ptr_save - i);
    // show the address ...
    printf("%x\t", (uint32_t)whats_there);
    // ... printable byte content ...
    if(*whats_there >= 32 && *whats_there < 127)
      printf("%c\t", *whats_there);
    else
      printf(" \t");
    // ... and 32-bit aligned content 
    if(i % 4 == 0) {
      uint32_t *wt_uint32 = (uint32_t *)(ptr_save - i);
      printf("%x\t", *wt_uint32);
      printf("\n-------");
      if(i != 0)
        printf("------------------------------------------------");
      else
        printf(" the border between KERNEL SPACE and USER SPACE ");
      printf("-------");
    }
    printf("\n");
    i++;
  }
#endif

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. Also sets up the arguments passed to the user program. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
	{
	  *esp = PHYS_BASE;  

	  // Setup the user's arguments to the stack
	  // Actual strings
	  struct new_proc_args* pr_args = thread_current()->pr_args;
	  void* p = *esp;
	  /*int i;
	  for(i=0; i<t->argc; i++) {
	    p -= strlen(t->argv[i]) +1;
	    printf("Writing %s to stack\n", t->argv[i]);
	    memcpy(p, &(t->argv[i]), strlen(t->argv[i]) +1);
	    }*/

	  char* argv[32];
	  int argc;
	  char *token, *save_ptr;
	  ASSERT(pr_args->cmd_line != NULL);
	  for (token = strtok_r (pr_args->cmd_line, " ", &save_ptr); token != NULL;
	       token = strtok_r (NULL, " ", &save_ptr))
	    {
	      p -= strlen(token) +1;
	      //printf("Writing %s to stack\n", token);
	      memcpy(p, token, strlen(token) +1);
	      argv[argc] = p;
	      argc++;
	      if(argc == 31) break;
	    }

	  argv[argc] = NULL;

	  // Word allign (to make stack pointer divisable by 4)
	  while((int)p % 4 != 0) {
	    p--;
	  }
	  // Add extra last element in array, set to NULL
	  /*if(t->argc != 0) {
	    char* nl_sent = NULL;
	    memcpy(p, &nl_sent, sizeof(char*));
	    p -= sizeof(char*);
	    }*/

	  // Argv (pointers to the strings)
	  char** argvpnt;
	  int i;
	  for(i=argc; i>=0; i--) {
	    p -= sizeof(char*);
	    memcpy(p, &(argv[i]), sizeof(char*));
	    argvpnt = p;
	  }
	  p -= sizeof(char**);
	  memcpy(p, &argvpnt, sizeof(char**));
	  //printf("Put argv at addr %p\n", p);

	  p -= sizeof(int);
	  memcpy(p, &argc, sizeof(int));
	  //printf("Put argc at addr %p\n", p);

	  // Fake return addr
	  void* dummy;
	  p -= sizeof(dummy);
          memcpy(p, &dummy, sizeof(dummy));

	  *esp = (void*) p;
	}
      else
        palloc_free_page (kpage);
    }
  printf("End of setup_stack()\n");
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
