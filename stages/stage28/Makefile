CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
all: test_device
test_device: agc_vk_device.c test_device.c agc_vk_device.h
	$(CC) $(CFLAGS) agc_vk_device.c test_device.c -ldl -o $@
clean:
	rm -f test_device
