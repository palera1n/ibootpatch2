CC		= cc
CC_FOR_BUILD = cc
TARGET_AS = as
TARGET_ASFLAGS = -arch arm64
SOURCE	= patch.c offsetfinder.c

UNAME  := $(shell uname)
ifeq ($(UNAME), Darwin)
ARCH	= -arch x86_64 -arch arm64
else
ARCH	=
endif

CFLAGS	=
BIN		= iBootpatch2

VERSION = $(shell git rev-parse HEAD | tr -d '\n')-$(shell git rev-list --count HEAD | tr -d '\n')

.PHONY: all clean

all: payload.h
	$(CC) $(SOURCE) $(ARCH) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o $(BIN)
	
vmacho:
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o vmacho vmacho.c

clean:
	-$(RM) $(BIN) *.bin *.o vmacho payload.h

%.o:
	$(TARGET_AS) $(TARGET_ASFLAGS) $*.S -o $*.o

%.bin: %.o vmacho
	./vmacho -f $*.o $*.bin

payload.h: a10_a11rxw.bin go_cmd_hook.bin tram.bin
	xxd -iC a10_a11rxw.bin > payload.h
	xxd -iC go_cmd_hook.bin >> payload.h
	xxd -iC tram.bin >> payload.h

.PHONY: all clean
