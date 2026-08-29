CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

all: test_submit

test_submit: agc_ps5_dcb.c agc_ps5_dcb.h agc_ps5_submit.c agc_ps5_submit.h test_submit.c
	$(CC) $(CFLAGS) agc_ps5_dcb.c agc_ps5_submit.c test_submit.c -o $@

clean:
	rm -f test_submit

.PHONY: all clean
