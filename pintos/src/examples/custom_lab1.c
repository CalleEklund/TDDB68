#include <syscall.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

int
main (void)
{
  printf("Start of customlab1\n");
  char filename[6] = {'t','1','.','t','x','t'};
  char filename_a[5] = {'a','.','t','x','t'};
  int fd =  open(filename_a);
  //bool success = create(filename,20);
  //if(success) printf("Sucessfully created file");
  printf("End of customlab1 \n");
}
