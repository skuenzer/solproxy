RM = rm -f
CC = gcc
CFLAGS += -O3 -Wall -g
LDFLAGS +=
LDLIBS += -lipmiconsole

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%: %.o
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

solproxy: solproxy.o solsession.o

all: solproxy

clean:
	$(RM) *.o *~ core solproxy
