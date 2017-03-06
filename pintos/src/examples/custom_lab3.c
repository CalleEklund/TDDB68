#include <syscall.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

int
main (int argc, char* argv[])
{
  printf("Start of customlab3\n");
	int pid = (int) exec("exit");
	if(pid == -1) {
		printf("Got pid -1 back in cuslab3\n");
		return -1;
	}
	printf("Started process nr %d in cuslab3\n", pid);
	wait(pid);
  printf("End of customlab3 \n");
	return 0;
}
