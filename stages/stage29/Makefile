CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -Werror -O2

all: agc_vk_probe test_probe

agc_vk_probe: agc_vk_probe.c
	$(CC) $(CFLAGS) agc_vk_probe.c -ldl -o $@

test_probe: test_probe.c
	$(CC) $(CFLAGS) test_probe.c -o $@

clean:
	rm -f agc_vk_probe test_probe
