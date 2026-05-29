CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = myapp
SRCS = main.c utils.c parser.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test:
	./run_tests.sh

install:
	cp $(TARGET) /usr/local/bin/

clean:
	rm -f $(OBJS) $(TARGET)
