CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Wpedantic -O2

all: test_driver

test_driver: agc_ps5_dcb.c agc_ps5_dcb.h agc_ps5_driver.c agc_ps5_driver.h test_driver.c
	$(CC) $(CFLAGS) agc_ps5_dcb.c agc_ps5_driver.c test_driver.c -o $@

clean:
	rm -f test_driver

.PHONY: all clean
