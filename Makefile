all: netfilter_block

netfilter_block: main.o
	g++ -o netfilter_block main.o -lnetfilter_queue

main.o : main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm *.o netfilter_block
