CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c11

all: firewall

firewall: main.o firewall.o
	$(CC) $(CFLAGS) -o firewall main.o firewall.o

main.o: src/main.c src/firewall.h
	$(CC) $(CFLAGS) -c src/main.c

firewall.o: src/firewall.c src/firewall.h
	$(CC) $(CFLAGS) -c src/firewall.c

clean:
	rm -f *.o firewall
