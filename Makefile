phony:
	gcc main.c scanner.c udp.c tcp.c -lpcap -std=gnu99 -o main
