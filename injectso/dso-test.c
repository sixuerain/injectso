/* gcc -fPIC -shared -nostartfiles dso-test.c -o /tmp/i.so */
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

void _init()
{
	fprintf(stderr, "Yo from init()\n");
	close(open("/tmp/injectso.works", O_RDWR|O_CREAT, 0600));
}


