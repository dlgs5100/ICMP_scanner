all: ipscanner

ipscanner: main.o pcap.o fill_packet.o
	gcc -o ipscanner main.o pcap.o fill_packet.o -lpcap

main.o: main.c
	gcc -Wall -c main.c

pcap.o: pcap.c
	gcc -Wall -c pcap.c

fill_packet.o: fill_packet.c
	gcc -Wall -c fill_packet.c

clean:
	rm -rf ipscanner *.[ois]
