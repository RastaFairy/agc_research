CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
LDFLAGS ?= -ldl

all: test_vulkan

test_vulkan: agc_p0_vulkan.c test_vulkan.c agc_p0_vulkan.h
	$(CC) $(CFLAGS) agc_p0_vulkan.c test_vulkan.c $(LDFLAGS) -o $@

clean:
	rm -f test_vulkan
