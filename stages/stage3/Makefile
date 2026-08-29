CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_dcb

test_dcb: agc_ps5_dcb.c agc_ps5_dcb.h test_dcb.c
	$(CC) $(CFLAGS) agc_ps5_dcb.c test_dcb.c -o $@

clean:
	rm -f test_dcb
