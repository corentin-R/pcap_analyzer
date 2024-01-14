CC = gcc
CFLAGS = -Wall -Wextra -pedantic

all: analyse_pcap

analyse_pcap: pcap_analyzer.c
	$(CC) $(CFLAGS) -o pcap_analyzer pcap_analyzer.c -lpcap

clean:
	rm -f pcap_analyzer