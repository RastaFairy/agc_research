CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_native_backend

test_native_backend: agc_ps5_native_backend.c test_native_backend.c agc_ps5_native_backend.h
	$(CC) $(CFLAGS) agc_ps5_native_backend.c test_native_backend.c -o $@

clean:
	rm -f test_native_backend
