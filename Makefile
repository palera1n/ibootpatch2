CC		=	gcc
SOURCE	=  	\
			patch.c \
			offsetfinder.c

CFLAGS	=

ARCH	=	-arch x86_64 -arch arm64
	
BIN		=	iBootpatch2

.PHONY: all clean

all:
	$(CC) $(SOURCE) $(ARCH) $(CFLAGS) -o $(BIN)
	
clean:
	-$(RM) $(BIN)
