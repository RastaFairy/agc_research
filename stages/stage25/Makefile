CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_decoder

test_decoder: agc_p0_decoder.c agc_p0_decoder.h test_decoder.c
	$(CC) $(CFLAGS) agc_p0_decoder.c test_decoder.c -o $@

clean:
	rm -f test_decoder
