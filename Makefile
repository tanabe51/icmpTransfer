PROGRAM=icmpTrance
OBJS=main.o ether.o checksum.o ip.o icmp.o packetAnalyze.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
LDFLAGS=
$(PROGRAM):$(OBJS)
	 $(CC) $(CFLAGS) $(LDFLAGS) -o $(PROGRAM) $(OBJS) $(LDLIBS)
