PS5_PAYLOAD_SDK := /opt/ps5-payload-sdk
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS := -O0 -g -Wall -Werror -ffreestanding -fno-builtin -fPIC -fno-stack-protector
ELF := stage40_probe.elf
OBJS := stage40_probe.o libSceAgcDriver.o

all: $(ELF)

$(ELF): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

stage40_probe.o: stage40_probe.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f stage40_probe.o stage40_probe.elf