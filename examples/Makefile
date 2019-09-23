SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGETS := aes-example

COMMON   := -O2 -Wall
CFLAGS   := $(CFLAGS) $(COMMON)
CC       := gcc
LDADD    := -lcrypto -lssl
LD       := $(CC)

all : $(TARGETS)
.PHONY : all

# {{{ for debugging
debug : CFLAGS += -g -DDEBUG=1
debug : $(TARGETS)
.PHONY : debug
# }}}

$(OBJECTS) : %.o : %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGETS) : % : %.o
	$(LD) -o $@ $^ $(LDADD)

.PHONY : clean
clean :
	rm -f $(OBJECTS) $(TARGETS)
