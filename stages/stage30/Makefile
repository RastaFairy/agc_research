CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2
all: test_requirements test_device

test_requirements: agc_vk_requirements.c test_requirements.c agc_vk_requirements.h
	$(CC) $(CFLAGS) agc_vk_requirements.c test_requirements.c -ldl -o $@

test_device: agc_vk_device.c test_device.c agc_vk_device.h
	$(CC) $(CFLAGS) agc_vk_device.c test_device.c -ldl -o $@

clean:
	rm -f test_requirements test_device
