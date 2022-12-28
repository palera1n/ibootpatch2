CC		= cc
CC_FOR_BUILD = cc
AS_FOR_TARGET ?= as
ASFLAGS_FOR_TARGET ?= -arch arm64 -nostdlib -static -ffreestanding
SOURCE	= patch.c offsetfinder.c payload.c

UNAME  := $(shell uname)
ifeq ($(UNAME), Darwin)
ARCH	= -arch x86_64 -arch arm64
else
ARCH	=
endif

CFLAGS	= -fcommon
BIN		= iBootpatch2

VERSION = $(shell git rev-parse HEAD | tr -d '\n')-$(shell git rev-list --count HEAD | tr -d '\n')

.PHONY: all clean

all: payload.c
	$(CC) $(SOURCE) $(ARCH) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o $(BIN)
	
vmacho:
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o vmacho vmacho.c

clean:
	-$(RM) $(BIN) *.bin *.o vmacho payload.c

%.o:
	$(AS_FOR_TARGET) $(ASFLAGS_FOR_TARGET) $*.S -o $*.o

%.bin: %.o vmacho
	./vmacho -f $*.o $*.bin

payload.c: a10_a11rxw.bin go_cmd_hook.bin tram.bin
	xxd -iC a10_a11rxw.bin >> payload.c
	xxd -iC go_cmd_hook.bin >> payload.c
	xxd -iC tram.bin >> payload.c

.PHONY: all clean
