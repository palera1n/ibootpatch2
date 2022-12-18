CC		=	gcc
SOURCE	=  	\
			patch.c \
			offsetfinder.c

ARCH	=	-arch x86_64 -arch arm64
	
BIN		=	iBootpatch2

.PHONY: all clean

all:
	$(CC) $(SOURCE) $(ARCH) -o $(BIN)
	
clean:
	-$(RM) $(BIN)
