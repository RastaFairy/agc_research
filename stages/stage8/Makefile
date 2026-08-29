CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: test_manifest

test_manifest: agc_ps5_abi_manifest.c test_manifest.c agc_ps5_abi_manifest.h
	$(CC) $(CFLAGS) agc_ps5_abi_manifest.c test_manifest.c -o $@

clean:
	rm -f test_manifest
