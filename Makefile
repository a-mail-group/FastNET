
ifeq ($(ODP),)
ODP=/home/simon/src_pak2/odp_inst
endif

GCC=gcc
CFLAGS=-L$(ODP)/lib -I$(ODP)/include
CFLAGS += -Iinclude
#stack += src/stack/eth.o
#stack += src/stack/arp.o
#stack += src/stack/ipv4.o
#stack += src/stack/ipv6.o
#stack += src/stack/icmp.o
#stack += src/stack/icmp6.o
#src/stack/%.o: src/stack/%.c
#	$(GCC) -c $(CFLAGS) $< -o $@
#build: $(stack)
#	rm $(stack)

net += src/net/basis_input.o
net += src/net/net_init.o

runnable: $(net) src/main/main.o
	$(GCC) $(CFLAGS) $(net) src/main/main.o -lodp-linux -o runnable

test:
	echo $(CFLAGS)

src/net/%.o: src/net/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

src/main/%.o: src/main/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

build: $(net)
	rm $(net)
