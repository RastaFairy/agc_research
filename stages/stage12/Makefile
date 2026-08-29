CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
all: test_layout

test_layout: packet_layout.h test_layout.c
	$(CC) $(CFLAGS) test_layout.c -o $@
clean:
	rm -f test_layout
