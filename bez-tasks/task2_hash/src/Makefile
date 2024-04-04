CC = gcc
CFLAGS = -g
LDFLAGS = -lcrypto

all: hash
run:
	#run your tests here...
hash: hash.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)
