
ifeq ($(DPDK),)
DPDK=/home/simon/src_packages/odp_inst
endif

GCC=gcc
CFLAGS=-L$(DPDK)/lib -I$(DPDK)/include

stack += src/stack/eth.o
stack += src/stack/arp.o
stack += src/stack/ipv4.o
stack += src/stack/ipv6.o
stack += src/stack/icmp.o
stack += src/stack/icmp6.o

test:
	echo $(CFLAGS)

src/stack/%.o: src/stack/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

build: $(stack)
	rm $(stack)



