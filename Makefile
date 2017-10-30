all : netfilter_block

netfilter_block: main.o
	gcc -o netfilter_block main.o -lnetfilter_queue

main.o: netfilter_block.c my_netfilter_block.h
	gcc -c -o main.o netfilter_block.c

clean:
	rm -f netfilter_block
	rm -f *.o

