CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_stage35

test_stage35: agc_ps5_submit_boundary.c test_stage35.c agc_ps5_submit_boundary.h
	$(CC) $(CFLAGS) agc_ps5_submit_boundary.c test_stage35.c -o $@

clean:
	rm -f test_stage35
