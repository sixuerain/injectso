CC=gcc
LD=ld
CFLAGS=-c -Wall -O2

all:
	$(CC) $(CFLAGS) inject.c
	$(CC) inject.o -o inject -ldl

	$(CC) $(CFLAGS) -fPIC event.c dlwrap.c
	$(CC) $(CFLAGS) -fPIC dso-test.c
	$(LD) -Bshareable -o event.so event.o dlwrap.o -lpthread
	$(LD) -Bshareable -o dso-test.so dso-test.o

clean:
	rm -rf *.o




