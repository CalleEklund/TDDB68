#include <stdio.h>

int main(int argc, char ** argv)
{
  char str[] = "sihtgubed";
  char *stri = &str[8];
  char *buf[9];
  char **bufi, **bufend;
  bufi = buf;
  bufend = &buf[9];

  while (bufi != bufend){
    *bufi = stri;
    bufi++;
    stri--;
  }

	// compensate for extra ++ in above loop - caused the segmentation fault!
	bufi--;

  while (bufi != buf-1){          // added -1 so to cover first letter
    **bufi -= 32;
	  bufi--;
  }

	// compensate for extra -- in above loop
	bufi++;

  while (bufi != bufend){
    printf("%c", **bufi);
    bufi++;
  }
}
