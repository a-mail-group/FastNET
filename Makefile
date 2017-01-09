
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
net += src/net/fastnet_tcp_input.o

net += src/net/in_tlp.o
net += src/net/ipv4check.o
net += src/net/ipv4_reass.o
net += src/net/net_init.o
net += src/net/packet_input.o
net += src/net/tlp_init.o

net += src/net_linux/start_threads.o

runnable: $(net) src/main/main.o runscript
	$(GCC) $(CFLAGS) $(net) src/main/main.o -lodp-linux -lodphelper-linux -o runnable

runscript:
	echo "#!/bin/sh" > runscript
	echo LD_LIBRARY_PATH=$(ODP)/lib ./runnable >> runscript
	chmod +x runscript

clean:
	rm $(net) src/main/main.o

test:
	echo $(CFLAGS)

src/net/%.o: src/net/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

src/net_linux/%.o: src/net_linux/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

src/main/%.o: src/main/%.c
	$(GCC) -c $(CFLAGS) $< -o $@

build: $(net)
	rm $(net)
