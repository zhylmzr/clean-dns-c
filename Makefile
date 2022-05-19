INC=/usr/include
CC=clang

all:
	$(CC) -O2 -Wall -target bpf -c -I $(INC) -o xdp-clean-dns.elf main.c 

openwrt:
	$(CC) -O2 -Wall -target bpf -c -I $(INC) -o xdp-clean-dns.elf main.c -D NOPRINTK

clean:
	rm -f xdp-clean-dns.elf