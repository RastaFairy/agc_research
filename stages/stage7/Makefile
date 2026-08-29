CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_bootstrap

test_bootstrap: agc_ps5_bootstrap.c test_bootstrap.c agc_ps5_bootstrap.h
	$(CC) $(CFLAGS) agc_ps5_bootstrap.c test_bootstrap.c -o $@

clean:
	rm -f test_bootstrap
