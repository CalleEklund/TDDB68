#include <syscall.h>

int
main (void)
{
  char filename[6] = {'t','1','.','t','x','t'};
  create(filename,20);
  
}
