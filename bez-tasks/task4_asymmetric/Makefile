CC = g++ -Wall -pedantic
CFLAGS = -g
LDFLAGS = -lcrypto

all: main
run:
	#run your tests here...
main: main.o
	$(CC) -o $@ $< $(LDFLAGS)
%.o: %.cpp
	$(CC) -c -o $@ $< $(CFLAGS)