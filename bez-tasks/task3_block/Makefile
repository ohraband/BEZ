CC = g++ -Wall -pedantic
CFLAGS = -g
LDFLAGS = -lcrypto

all: encrypt decrypt
run:
	#run your tests here...
encrypt: encrypt.o
	$(CC) -o $@ $< $(LDFLAGS)
decrypt: decrypt.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)