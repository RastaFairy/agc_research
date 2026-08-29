CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_host

test_host: agc_p0_decoder.c agc_p0_host.c test_host.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f test_host stage26_reference.ppm
