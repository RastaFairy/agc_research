CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_submit

test_submit: agc_ps5_submit.c test_submit.c agc_ps5_submit.h
	$(CC) $(CFLAGS) agc_ps5_submit.c test_submit.c -o $@

clean:
	rm -f test_submit
